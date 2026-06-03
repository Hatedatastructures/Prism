#include <prism/stealth/facade/shadowtls/transport.hpp>

#include <prism/protocol/tls/record.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace psm::stealth::shadowtls
{

    namespace
    {
        constexpr std::string_view tag = "[ShadowTLS.Transport]";

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
                                             shadowtls_handover handover)
        : socket_(std::move(socket))
        , write_key_(compute_write_key(handover.password, handover.server_random))
        , initial_buffer_(handover.initial_data.begin(), handover.initial_data.end())
        , hmac_write_ctx_(std::move(handover.hmac_write_ctx))
        , hmac_read_ctx_(std::move(handover.hmac_read_ctx))
    {
        // 存储 server_random — WHY: HMAC 上下文在后续 read/write 中持续使用
        std::memcpy(server_random_.data(), handover.server_random.data(), handover.server_random.size());

        const auto *hw_str = "no";
        if (hmac_write_ctx_)
        {
            hw_str = "yes";
        }
        const auto *hr_str = "no";
        if (hmac_read_ctx_)
        {
            hr_str = "yes";
        }
        trace::debug("{} created, initial_data_size={}, hmac_write_ctx={}, hmac_read_ctx={}",
                    tag, handover.initial_data.size(),
                    hw_str, hr_str);

    }

    shadowtls_transport::~shadowtls_transport() noexcept
{
}


    auto shadowtls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        trace::debug("{} async_read_some: buf={}, init_off={}, init_sz={}, pend_off={}, pend_sz={}",
                    tag, buffer.size(), initial_offset_, initial_buffer_.size(), pending_offset_, pending_buffer_.size());

        if (initial_offset_ < initial_buffer_.size())
        {
            const auto available = initial_buffer_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_buffer_.data() + initial_offset_, n);
            initial_offset_ += n;
            trace::debug("{} returned {} from initial, off={}", tag, n, initial_offset_);
            co_return n;
        }

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

        auto [read_ec, rec] = co_await ::psm::tls::record::read(socket_);
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn("{} read TLS record failed", tag);
            co_return std::nullopt;
        }

        if (rec.header().content_type != content_appdata)
        {
            trace::warn("{} unexpected TLS record type: 0x{:02x}", tag, rec.header().content_type);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        auto payload = rec.payload();

        if (payload.size() < hmac_size)
        {
            trace::warn("{} payload too small for HMAC: {}", tag, payload.size());
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        std::array<std::uint8_t, hmac_size> client_hmac{};
        std::memcpy(client_hmac.data(), payload.data(), hmac_size);

        auto actual_data = std::span<const std::byte>(
            payload.data() + hmac_size, payload.size() - hmac_size);

        // 参照 sing-shadowtls verifyApplicationData:
        // 写入 actual_data -> 计算 HMAC[:4] -> 验证 -> 将 HMAC[:4] 加入累积状态
        if (!hmac_read_ctx_)
        {
            trace::warn("{} hmac_read_ctx is null, cannot verify HMAC", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // safe: SSL HMAC API requires uint8_t*, byte span data is read-only
        HMAC_Update(hmac_read_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(actual_data.data()),
                   actual_data.size());

        // 使用 copy 避免改变累积状态
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

        if (CRYPTO_memcmp(client_hmac.data(), expected_hmac.data(), hmac_size) != 0)
        {
            trace::warn("{} HMAC mismatch in transport read_tls_frame", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // 参照 sing-shadowtls verifyApplicationData update=true
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

        // safe: SSL HMAC API requires uint8_t*, byte span data is read-only
        HMAC_Update(hmac_write_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(payload.data()),
                   payload.size());

        // 使用 copy 避免改变累积状态（参照 sing-shadowtls verifiedConn.write: hmacHash := c.hmacAdd.Sum(nil)[:hmacSize]）
        HMAC_CTX *hmac_copy = HMAC_CTX_new();
        HMAC_CTX_copy(hmac_copy, hmac_write_ctx_.get());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(hmac_copy, md.data(), &md_len);
        HMAC_CTX_free(hmac_copy);

        std::array<std::uint8_t, hmac_size> hmac_tag{};
        std::memcpy(hmac_tag.data(), md.data(), hmac_size);

        // 参照 sing-shadowtls verifiedConn.write: c.hmacAdd.Write(hmacHash)
        HMAC_Update(hmac_write_ctx_.get(), hmac_tag.data(), hmac_size);

        trace::debug("{} write_tls_frame: HMAC computed for frame", tag);

        // 参照 sing-shadowtls verifiedConn.write: plain payload，不 XOR
        memory::vector<std::byte> tls_payload(hmac_size + payload.size());
        std::memcpy(tls_payload.data(), hmac_tag.data(), hmac_size);
        std::memcpy(tls_payload.data() + hmac_size, payload.data(), payload.size());

        auto frame_rec = ::psm::tls::record::builder()
                             .type(content_appdata)
                             .version(0x0303)
                             .payload(tls_payload)
                             .build();
        auto frame_bytes = frame_rec.serialize();

        boost::system::error_code boost_ec;
        auto written = co_await net::async_write(
            socket_, net::buffer(frame_bytes.data(), frame_bytes.size()),
            net::redirect_error(trace::use_prefix_awaitable, boost_ec));

        if (boost_ec)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn("{} write TLS frame failed: {}", tag, boost_ec.message());
            co_return 0;
        }

        trace::debug("{} wrote {} bytes (TLS frame size={})", tag, payload.size(), frame_bytes.size());
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