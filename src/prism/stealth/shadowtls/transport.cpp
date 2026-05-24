/**
 * @file transport.cpp
 * @brief ShadowTLS v3 传输层包装器实现
 */

#include <prism/stealth/shadowtls/transport.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <cstdint>
#include <cstring>
#include <algorithm>

constexpr std::string_view tag = "[ShadowTLS.Transport]";

namespace psm::stealth::shadowtls
{
    namespace
    {
        // 计算 XOR 密钥：SHA256(password + serverRandom)
        [[nodiscard]] auto compute_write_key(std::string_view password, std::span<const std::byte> server_random)
            -> memory::vector<std::uint8_t>
        {
            SHA256_CTX sha_ctx;
            SHA256_Init(&sha_ctx);
            SHA256_Update(&sha_ctx, password.data(), password.size());
            // safe: SSL API requires uint8_t*, byte span data is read-only for SHA256
            SHA256_Update(&sha_ctx, reinterpret_cast<const std::uint8_t *>(server_random.data()),
                         server_random.size());
            memory::vector<std::uint8_t> key(32);
            SHA256_Final(key.data(), &sha_ctx);
            return key;
        }
    } // namespace

    shadowtls_transport::shadowtls_transport(net::ip::tcp::socket socket,
                                             std::string_view password,
                                             std::span<const std::byte> server_random,
                                             std::span<const std::byte> initial_data,
                                             std::shared_ptr<HMAC_CTX> hmac_write_ctx,
                                             std::shared_ptr<HMAC_CTX> hmac_read_ctx)
        : socket_(std::move(socket))
        , write_key_(compute_write_key(password, server_random))
        , initial_buffer_(initial_data.begin(), initial_data.end())
        , hmac_write_ctx_(hmac_write_ctx)
        , hmac_read_ctx_(hmac_read_ctx)
    {
        // 存储 server_random
        std::memcpy(server_random_.data(), server_random.data(), server_random.size());

        trace::debug("{} created, initial_data_size={}, hmac_write_ctx={}, hmac_read_ctx={}",
                    tag, initial_data.size(),
                    hmac_write_ctx ? "yes" : "no",
                    hmac_read_ctx ? "yes" : "no");
    }

    shadowtls_transport::~shadowtls_transport()
{
    // HMAC 上下文由 shared_ptr 自动管理，不需要手动释放
}

    auto shadowtls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        trace::debug("{} async_read_some: buf={}, init_off={}, init_sz={}, pend_off={}, pend_sz={}",
                    tag, buffer.size(), initial_offset_, initial_buffer_.size(), pending_offset_, pending_buffer_.size());

        // 优先返回初始数据
        if (initial_offset_ < initial_buffer_.size())
        {
            const auto available = initial_buffer_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_buffer_.data() + initial_offset_, n);
            initial_offset_ += n;
            trace::debug("{} returned {} from initial, off={}", tag, n, initial_offset_);
            co_return n;
        }

        // 返回 pending buffer 中的剩余数据
        if (pending_offset_ < pending_buffer_.size())
        {
            const auto available = pending_buffer_.size() - pending_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), pending_buffer_.data() + pending_offset_, n);
            pending_offset_ += n;

            if (pending_offset_ == pending_buffer_.size())
            {
                pending_buffer_.clear();
                pending_offset_ = 0;
            }

            trace::debug("{} returned {} from pending, rem={}", tag, n, pending_buffer_.size());
            co_return n;
        }

        // 读取新的 TLS frame
        trace::debug("{} buffers empty, reading TLS frame", tag);
        auto frame_opt = co_await read_tls_frame(ec);
        if (ec || !frame_opt)
        {
            trace::warn("{} read_tls_frame failed: {}", tag, ec.message());
            co_return 0;
        }

        auto &frame = *frame_opt;
        trace::debug("{} TLS frame payload: {} bytes", tag, frame.size());

        const auto n = std::min(frame.size(), buffer.size());
        std::memcpy(buffer.data(), frame.data(), n);

        // 存储剩余数据到 pending buffer
        if (frame.size() > n)
        {
            pending_buffer_.assign(frame.begin() + n, frame.end());
            pending_offset_ = 0;
            trace::debug("{} stored {} pending", tag, pending_buffer_.size());
        }

        trace::debug("{} returned {} to user", tag, n);
        co_return n;
    }

    auto shadowtls_transport::read_tls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        trace::debug("{} read_tls_frame: starting to read TLS header", tag);

        // 使用 boost::system::error_code 用于 redirect_error
        boost::system::error_code boost_ec;

        // 读取 TLS header(5)
        std::array<std::byte, tls_header_size> header{};
        auto header_n = co_await net::async_read(
            socket_, net::buffer(header.data(), tls_header_size),
            net::redirect_error(net::use_awaitable, boost_ec));

        trace::debug("{} read_tls_frame: header_n={}, boost_ec={}", tag, header_n, boost_ec.message());

        if (boost_ec || header_n < tls_header_size)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn("{} read TLS header failed: {} (header_n={})", tag, boost_ec.message(), header_n);
            co_return std::nullopt;
        }

        // safe: casting byte buffer to uint8_t to parse TLS record header fields
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const std::uint16_t record_length = (static_cast<std::uint16_t>(raw[3]) << 8) | raw[4];

        trace::debug("{} read_tls_frame: TLS record type=0x{:02x}, length={}", tag, raw[0], record_length);

        // 读取 TLS payload
        memory::vector<std::byte> payload(record_length);
        auto payload_n = co_await net::async_read(
            socket_, net::buffer(payload.data(), record_length),
            net::redirect_error(net::use_awaitable, boost_ec));

        if (boost_ec || payload_n < record_length)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn("{} read TLS payload failed: {}", tag, boost_ec.message());
            co_return std::nullopt;
        }

        // 检查是否为 Application Data
        if (raw[0] != content_type_application_data)
        {
            trace::warn("{} unexpected TLS record type: 0x{:02x}", tag, raw[0]);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // payload 格式：HMAC(4) + actual_data(N)
        if (payload.size() < hmac_size)
        {
            trace::warn("{} payload too small for HMAC: {}", tag, payload.size());
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // 提取客户端 HMAC
        std::array<std::uint8_t, hmac_size> client_hmac{};
        std::memcpy(client_hmac.data(), payload.data(), hmac_size);

        // actual_data = HMAC 之后的数据
        auto actual_data = std::span<const std::byte>(
            payload.data() + hmac_size, payload.size() - hmac_size);

        // 参照 sing-shadowtls verifyApplicationData:
        // 1. 将 actual_data 写入累积 HMAC
        // 2. 计算当前 HMAC[:4]
        // 3. 验证匹配
        // 4. 验证成功后，将 HMAC[:4] 也加入累积状态
        if (!hmac_read_ctx_)
        {
            trace::warn("{} hmac_read_ctx is null, cannot verify HMAC", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // 累积 HMAC：写入 actual_data
        // safe: SSL HMAC API requires uint8_t*, byte span data is read-only
        HMAC_Update(hmac_read_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(actual_data.data()),
                   actual_data.size());

        // 计算当前 HMAC[:4]（使用 copy 避免改变状态）
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        {
            HMAC_CTX *hmac_copy = HMAC_CTX_new();
            HMAC_CTX_copy(hmac_copy, hmac_read_ctx_.get());
            HMAC_Final(hmac_copy, md.data(), &md_len);
            HMAC_CTX_free(hmac_copy);
        }

        std::array<std::uint8_t, hmac_size> expected_hmac{};
        std::memcpy(expected_hmac.data(), md.data(), hmac_size);

        // 验证 HMAC
        if (CRYPTO_memcmp(client_hmac.data(), expected_hmac.data(), hmac_size) != 0)
        {
            trace::warn("{} HMAC mismatch in transport read_tls_frame", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // 验证成功，将 HMAC[:4] 也加入累积状态（参照 sing-shadowtls verifyApplicationData update=true）
        HMAC_Update(hmac_read_ctx_.get(), client_hmac.data(), hmac_size);

        trace::debug("{} TLS frame verified (cumulative HMAC), payload_size={}, added HMAC to cumulative state",
                    tag, actual_data.size());

        // 返回 actual_data（剥离 HMAC）
        memory::vector<std::byte> result(actual_data.begin(), actual_data.end());
        co_return result;
    }

    auto shadowtls_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        trace::debug("{} async_write_some: buffer_size={}, calling write_tls_frame", tag, buffer.size());
        return write_tls_frame(buffer, ec);
    }

    auto shadowtls_transport::async_write(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        trace::debug("{} async_write: data_size={}, calling write_tls_frame directly", tag, data.size());
        // 完整写入：直接调用 write_tls_frame
        return write_tls_frame(data, ec);
    }

    auto shadowtls_transport::write_tls_frame(std::span<const std::byte> payload, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        trace::debug("{} write_tls_frame: payload_size={}", tag, payload.size());

        // 参照 sing-shadowtls verifiedConn.write:
        // 1. 累积 HMAC 写入 plain payload（不 XOR）
        // 2. 计算 HMAC[:4]
        // 3. 将 HMAC[:4] 也加入累积状态
        // 4. 发送 plain payload + HMAC[:4]
        // 注意：XOR 加密只在握手阶段使用，传输阶段发送 plain payload

        // 累积 HMAC：写入 plain payload
        // safe: SSL HMAC API requires uint8_t*, byte span data is read-only
        HMAC_Update(hmac_write_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(payload.data()),
                   payload.size());

        // 计算当前 HMAC（使用 copy 避免改变累积状态）
        // 参照 sing-shadowtls verifiedConn.write: hmacHash := c.hmacAdd.Sum(nil)[:hmacSize]
        // Sum 不改变状态，用 HMAC_CTX_copy 实现
        HMAC_CTX *hmac_copy = HMAC_CTX_new();
        HMAC_CTX_copy(hmac_copy, hmac_write_ctx_.get());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(hmac_copy, md.data(), &md_len);
        HMAC_CTX_free(hmac_copy);

        std::array<std::uint8_t, hmac_size> hmac_tag{};
        std::memcpy(hmac_tag.data(), md.data(), hmac_size);

        // 参照 sing-shadowtls verifiedConn.write: c.hmacAdd.Write(hmacHash)
        // 将 HMAC[:4] 也加入累积状态！
        HMAC_Update(hmac_write_ctx_.get(), hmac_tag.data(), hmac_size);

        trace::debug("{} write_tls_frame: HMAC computed for frame", tag);

        // 构建 TLS frame：header(5) + HMAC(4) + plain payload
        // 参照 sing-shadowtls verifiedConn.write: 发送 plain payload，不 XOR
        const std::uint16_t tls_payload_len = static_cast<std::uint16_t>(hmac_size + payload.size());
        memory::vector<std::byte> frame(tls_header_size + tls_payload_len);
        // safe: casting mutable byte vector to uint8_t for in-place TLS frame header construction
        auto *raw = reinterpret_cast<std::uint8_t *>(frame.data());

        // TLS header
        raw[0] = content_type_application_data;
        raw[1] = 3; // TLS 1.2 legacy version
        raw[2] = 3;
        raw[3] = static_cast<std::uint8_t>(tls_payload_len >> 8);
        raw[4] = static_cast<std::uint8_t>(tls_payload_len & 0xFF);

        // HMAC 标签
        std::memcpy(raw + tls_header_size, hmac_tag.data(), hmac_size);

        // Plain payload（不 XOR 加密！传输阶段用 plain payload）
        // 参照 sing-shadowtls verifiedConn.write 发送 plain payload
        std::memcpy(raw + tls_header_size + hmac_size, payload.data(), payload.size());

        // 使用 boost::system::error_code 用于 redirect_error
        boost::system::error_code boost_ec;
        auto written = co_await net::async_write(
            socket_, net::buffer(frame.data(), frame.size()),
            net::redirect_error(net::use_awaitable, boost_ec));

        if (boost_ec)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn("{} write TLS frame failed: {}", tag, boost_ec.message());
            co_return 0;
        }

        trace::debug("{} wrote {} bytes (TLS frame size={})", tag, payload.size(), frame.size());
        co_return payload.size();
    }

    void shadowtls_transport::close()
    {
        boost::system::error_code ec;
        socket_.close(ec);
    }

    void shadowtls_transport::cancel()
    {
        socket_.cancel();
    }
} // namespace psm::stealth::shadowtls