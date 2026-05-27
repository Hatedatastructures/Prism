#include <prism/protocol/shadowsocks/conn.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/shadowsocks/framing.hpp>
#include <prism/protocol/shadowsocks/util/cast.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/transport/transmission.hpp>

#include <openssl/rand.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>

constexpr std::string_view tag = "[SS2022.Relay]";

namespace psm::protocol::shadowsocks
{

    namespace
    {
        using util::as_u8;

        // byte vector -> uint8_t 可写 span，用于 AEAD 解密输出
        [[nodiscard]] auto as_u8_mut(std::vector<std::byte> &v) noexcept
            -> std::span<std::uint8_t>
        {
            // safe: casting byte vector to uint8_t span, same memory representation
            return {reinterpret_cast<std::uint8_t *>(v.data()), v.size()};
        }

        // PMR byte vector → uint8_t 可写 span，用于 AEAD 解密输出
        [[nodiscard]] auto as_u8_mut(memory::vector<std::byte> &v) noexcept
            -> std::span<std::uint8_t>
        {
            // safe: casting PMR byte vector to uint8_t span, same memory representation
            return {reinterpret_cast<std::uint8_t *>(v.data()), v.size()};
        }

        // 任意连续容器 -> const byte span，用于 scatter-gather 写入
        [[nodiscard]] auto to_bytes(const auto &c) noexcept
            -> std::span<const std::byte>
        {
            return std::as_bytes(std::span{c});
        }

    } // namespace

    conn::conn(transport::shared_transmission next_layer, const config &cfg,
                 std::shared_ptr<salt_pool> salts)
        : next_layer_(std::move(next_layer)), config_(cfg), salt_pool_(std::move(salts)), psk_(memory::current_resource())
    {
        const auto [ec, psk_bytes] = format::decode_psk(config_.psk);
        if (ec != fault::code::success)
        {
            trace::error("{} invalid PSK configuration: {}", tag, fault::describe(ec));
            return;
        }
        psk_.assign(psk_bytes.begin(), psk_bytes.end());

        method_ = format::resolve_method(config_.method, psk_.size());
        key_salt_len_ = format::keysalt_len(method_);
    }


    auto conn::executor() const
        -> executor_type
    {
        return next_layer_->executor();
    }


    void conn::close()
    {
        if (next_layer_)
        {
            next_layer_->close();
        }
    }


    void conn::cancel()
    {
        if (next_layer_)
        {
            next_layer_->cancel();
        }
    }


    auto conn::derive_aead_context(const std::span<const std::uint8_t> salt) const
        -> std::unique_ptr<crypto::aead_context>
    {
        // 拼接 PSK + salt 作为密钥材料（栈缓冲，PSK+salt 最大 32+32=64 字节）
        std::array<std::uint8_t, 64> material_buf{};
        const auto material_len = psk_.size() + salt.size();
        std::memcpy(material_buf.data(), psk_.data(), psk_.size());
        std::memcpy(material_buf.data() + psk_.size(), salt.data(), salt.size());

        constexpr auto ctx = kdf_context; // SIP022: "shadowsocks 2022 session subkey"
        const auto key = crypto::derive_key(
            ctx, std::span<const std::uint8_t>(material_buf.data(), material_len), key_salt_len_);

        crypto::aead_cipher cipher;
        switch (method_)
        {
        case cipher_method::aes_128_gcm:
            cipher = crypto::aead_cipher::aes_128_gcm;
            break;
        case cipher_method::aes_256_gcm:
            cipher = crypto::aead_cipher::aes_256_gcm;
            break;
        case cipher_method::chacha20_poly1305:
            cipher = crypto::aead_cipher::chacha20_poly1305;
            break;
        }

        return std::make_unique<crypto::aead_context>(cipher, std::span(key));
    }


    auto conn::read_fixed_hdr() const
        -> net::awaitable<std::tuple<fault::code, std::uint16_t, std::int64_t>>
    {
        constexpr auto fail = [](const fault::code ec)
            -> std::tuple<fault::code, std::uint16_t, std::int64_t>
        { return {ec, 0, 0}; };

        std::error_code ec;

        // 读取加密固定头（27 字节）
        std::array<std::byte, fixed_hdr_size> header_enc{};
        co_await transport::async_read(*next_layer_, header_enc, ec);
        if (ec)
        {
            trace::warn("{} read fixed header failed: {}", tag, ec.message());
            co_return fail(fault::code::connection_reset);
        }

        // AEAD 解密
        std::array<std::uint8_t, fixed_hdr_plain> header_plain{};
        if (const auto r = decrypt_ctx_->open(header_plain, as_u8(header_enc));
            r != fault::code::success)
        {
            trace::warn("{} decrypt fixed header failed: {} (expected {} plain bytes, got {} enc bytes)",
                        tag, fault::describe(r), fixed_hdr_plain, fixed_hdr_size);
            co_return fail(fault::code::auth_failed);
        }
        // 验证请求类型
        if (header_plain[0] != request_type)
        {
            trace::warn("{} invalid request type: 0x{:02x}", tag, header_plain[0]);
            co_return fail(fault::code::bad_message);
        }

        // 提取时间戳（8 字节大端序）
        std::uint64_t client_ts = 0;
        for (std::size_t i = 0; i < 8; ++i)
        {
            client_ts = (client_ts << 8) | header_plain[1 + i];
        }

        // 时间戳窗口验证
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        std::int64_t diff = now - static_cast<std::int64_t>(client_ts);
        if (static_cast<std::int64_t>(client_ts) > now)
        {
            diff = static_cast<std::int64_t>(client_ts) - now;
        }
        if (diff > config_.timestamp_window)
        {
            trace::warn("{} timestamp expired: client_ts={}, server_ts={}, diff={}s",
                        tag, client_ts, now, diff);
            co_return fail(fault::code::timestamp_expired);
        }

        // 提取 varHeaderLen（2 字节大端序）
        const auto var_header_len = static_cast<std::uint16_t>(header_plain[9] << 8 | header_plain[10]);

        co_return std::tuple{fault::code::success, var_header_len, now};
    }


    auto conn::read_var_hdr(const std::uint16_t var_header_len, request &req)
        -> net::awaitable<fault::code>
    {
        std::error_code ec;

        // 读取加密变长头
        memory::vector<std::byte> var_header_enc(var_header_len + aead_tag_len);
        co_await transport::async_read(*next_layer_, var_header_enc, ec);
        if (ec)
        {
            trace::warn("{} read variable header failed: {}", tag, ec.message());
            co_return fault::code::connection_reset;
        }

        // AEAD 解密
        memory::vector<std::uint8_t> var_header_plain(var_header_len);
        if (const auto r = decrypt_ctx_->open(var_header_plain, as_u8(var_header_enc));
            r != fault::code::success)
        {
            trace::warn("{} decrypt variable header failed: {}", tag, fault::describe(r));
            co_return fault::code::auth_failed;
        }

        // 解析地址和端口
        const auto [addr_ec, addr_result] = format::parse_addr_port(
            std::span<const std::uint8_t>(var_header_plain));
        if (addr_ec != fault::code::success)
        {
            trace::warn("{} address parse failed: {}", tag, fault::describe(addr_ec));
            co_return addr_ec;
        }

        req.destination_address = addr_result.addr;
        req.port = addr_result.port;

        target_ = protocol::target();
        target_.host = protocol::common::addr_to_str(req.destination_address);
        char port_buf[8];
        const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), req.port);
        target_.port.assign(port_buf, std::distance(port_buf, pe));
        target_.positive = true;

        // 跳过 padding，提取初始 payload
        std::size_t offset = addr_result.offset;
        if (offset + 2 <= var_header_plain.size())
        {
            const auto padding_len = static_cast<std::uint16_t>(var_header_plain[offset] << 8 | var_header_plain[offset + 1]);
            offset += 2 + padding_len;

            if (offset < var_header_plain.size())
            {
                const auto payload_size = var_header_plain.size() - offset;
                init_payload_.resize(payload_size);
                std::memcpy(init_payload_.data(), var_header_plain.data() + offset, payload_size);
            }
        }

        co_return fault::code::success;
    }


    auto conn::send_response(const std::span<const std::uint8_t> client_salt, const std::int64_t server_ts)
        -> net::awaitable<fault::code>
    {
        std::error_code ec;

        // 生成随机 server salt（使用密码学安全随机数生成器）
        memory::vector<std::uint8_t> server_salt(key_salt_len_);
        // safe: RAND_bytes writes to a uint8_t vector's data buffer, same memory layout as unsigned char
        if (RAND_bytes(reinterpret_cast<std::uint8_t *>(server_salt.data()),
                       static_cast<int>(server_salt.size())) != 1)
        {
            co_return fault::code::crypto_error;
        }

        encrypt_ctx_ = derive_aead_context(server_salt);

        // 构建响应固定头明文：type(1) + timestamp(8) + requestSalt + paddingLen(2)
        const std::size_t resp_fixed_plain_len = 1 + 8 + key_salt_len_ + 2;
        memory::vector<std::uint8_t> resp_fixed_plain(resp_fixed_plain_len);
        resp_fixed_plain[0] = response_type;

        // 服务端时间戳（大端序）
        const auto ts = static_cast<std::uint64_t>(server_ts);
        for (std::size_t i = 0; i < 8; ++i)
        {
            resp_fixed_plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        }

        // requestSalt + paddingLen = 0
        std::memcpy(resp_fixed_plain.data() + 9, client_salt.data(), key_salt_len_);
        resp_fixed_plain[9 + key_salt_len_] = 0;
        resp_fixed_plain[9 + key_salt_len_ + 1] = 0;

        // AEAD 加密响应固定头
        memory::vector<std::uint8_t> resp_fixed_enc(
            crypto::aead_context::seal_size(resp_fixed_plain_len));
        if (const auto r = encrypt_ctx_->seal(resp_fixed_enc, resp_fixed_plain);
            r != fault::code::success)
        {
            trace::error("{} encrypt response fixed header failed", tag);
            co_return fault::code::crypto_error;
        }

        // 加密空初始 payload（SIP022 要求固定头后必须跟一个 AEAD 块）
        static_assert(aead_tag_len == 16);
        std::array<std::uint8_t, aead_tag_len> empty_payload_enc{};
        if (const auto r = encrypt_ctx_->seal(empty_payload_enc, {});
            r != fault::code::success)
        {
            trace::error("{} encrypt empty payload chunk failed", tag);
            co_return fault::code::crypto_error;
        }

        // 合并写入：server_salt + 加密固定头 + 加密空初始 payload
        const std::size_t resp_total = server_salt.size() + resp_fixed_enc.size() + empty_payload_enc.size();
        memory::vector<std::byte> resp_combined(resp_total, memory::current_resource());
        std::size_t resp_off = 0;
        const auto salt_bytes = to_bytes(server_salt);
        std::memcpy(resp_combined.data() + resp_off, salt_bytes.data(), salt_bytes.size());
        resp_off += salt_bytes.size();
        const auto fixed_bytes = to_bytes(resp_fixed_enc);
        std::memcpy(resp_combined.data() + resp_off, fixed_bytes.data(), fixed_bytes.size());
        resp_off += fixed_bytes.size();
        const auto empty_bytes = to_bytes(empty_payload_enc);
        std::memcpy(resp_combined.data() + resp_off, empty_bytes.data(), empty_bytes.size());
        co_await transport::async_write(*next_layer_, resp_combined, ec);
        if (ec)
        {
            trace::warn("{} write response failed: {}", tag, ec.message());
            co_return fault::code::connection_reset;
        }

        co_return fault::code::success;
    }


    auto conn::handshake()
        -> net::awaitable<std::pair<fault::code, request>>
    {
        request req;
        req.method = method_;

        if (psk_.empty())
        {
            trace::error("{} PSK not configured", tag);
            co_return std::pair{fault::code::invalid_psk, req};
        }

        // 握手超时保护：30 秒内必须完成
        net::steady_timer deadline(next_layer_->executor(), std::chrono::seconds(30));
        auto on_deadline = [this](const boost::system::error_code &ec)
        {
            if (!ec) next_layer_->cancel();
        };
        deadline.async_wait(std::move(on_deadline));

        std::error_code ec;

        trace::debug("{} handshake start: method={}, key_salt_len={}, psk_size={}",
                    tag, static_cast<int>(method_), key_salt_len_, psk_.size());

        // 1. 读取 client salt
        memory::vector<std::uint8_t> client_salt(key_salt_len_);
        co_await transport::async_read(*next_layer_, std::as_writable_bytes(std::span(client_salt)), ec);
        if (ec)
        {
            deadline.cancel();
            trace::warn("{} read client salt failed: {}", tag, ec.message());
            if (ec == std::make_error_code(std::errc::operation_canceled))
            {
                co_return std::pair{fault::code::timeout, req};
            }
            co_return std::pair{fault::code::connection_reset, req};
        }

        // 2. Salt 重放检查
        if (salt_pool_ && !salt_pool_->check_and_insert(client_salt))
        {
            deadline.cancel();
            trace::warn("{} salt replay detected", tag);
            co_return std::pair{fault::code::replay_detected, req};
        }

        // 保存 client_salt 供 acknowledge() 使用
        client_salt_ = client_salt;

        // 3. 派生解密上下文
        decrypt_ctx_ = derive_aead_context(client_salt);
        trace::debug("{} derived decrypt context from salt", tag);

        // 4. 读取并验证固定头
        auto [header_ec, var_header_len, now] = co_await read_fixed_hdr();
        if (header_ec != fault::code::success)
        {
            deadline.cancel();
            if (header_ec == fault::code::canceled)
            {
                co_return std::pair{fault::code::timeout, req};
            }
            co_return std::pair{header_ec, req};
        }

        // 保存服务端时间戳供 acknowledge() 使用
        handshake_ts_ = now;

        // 5. 读取并解析变长头
        auto var_ec = co_await read_var_hdr(var_header_len, req);
        if (var_ec != fault::code::success)
        {
            deadline.cancel();
            if (var_ec == fault::code::canceled)
            {
                co_return std::pair{fault::code::timeout, req};
            }
            co_return std::pair{var_ec, req};
        }

        // 握手解析完成，响应延迟到 acknowledge() 中发送
        deadline.cancel();
        co_return std::pair{fault::code::success, req};
    }


    auto conn::acknowledge()
        -> net::awaitable<fault::code>
    {
        co_return co_await send_response(
            std::span<const std::uint8_t>(client_salt_.data(), client_salt_.size()),
            handshake_ts_);
    }


    auto conn::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 优先返回初始 payload
        if (init_off_ < init_payload_.size())
        {
            const auto available = init_payload_.size() - init_off_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), init_payload_.data() + init_off_, n);
            init_off_ += n;
            co_return n;
        }

        // 从已解密缓冲区返回
        if (decrypted_off_ < decrypted_.size())
        {
            const auto available = decrypted_.size() - decrypted_off_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), decrypted_.data() + decrypted_off_, n);
            decrypted_off_ += n;

            if (decrypted_off_ == decrypted_.size())
            {
                decrypted_off_ = 0;
                decrypted_.clear();
            }
            co_return n;
        }

        // 读取并解密下一个 chunk
        co_await fetch_chunk(ec);
        if (ec)
        {
            if (ec == fault::code::eof || ec == fault::code::canceled)
                trace::debug("{} async_read_some: client disconnected", tag);
            else
                trace::warn("{} async_read_some: fetch_chunk failed: {}", tag, ec.message());
            co_return 0;
        }

        if (decrypted_.empty())
        {
            co_return 0;
        }

        const auto n = std::min(decrypted_.size(), buffer.size());
        std::memcpy(buffer.data(), decrypted_.data(), n);
        decrypted_off_ = n;

        if (decrypted_off_ == decrypted_.size())
        {
            decrypted_off_ = 0;
            decrypted_.clear();
        }

        co_return n;
    }


    auto conn::fetch_chunk(std::error_code &ec)
        -> net::awaitable<void>
    {
        // 读取加密长度块（18 字节）
        co_await transport::async_read(*next_layer_, length_buf_, ec);
        if (ec)
        {
            co_return;
        }

        // 解密长度
        std::array<std::uint8_t, 2> len_plain{};
        if (const auto r = decrypt_ctx_->open(len_plain, as_u8(length_buf_));
            r != fault::code::success)
        {
            ec = std::make_error_code(std::errc::protocol_error);
            co_return;
        }

        cur_payload_len_ = static_cast<std::uint16_t>((len_plain[0] << 8) | len_plain[1]);

        if (cur_payload_len_ == 0)
        {
            co_return;
        }

        // 读取加密 payload 块
        chunk_buf_.resize(cur_payload_len_ + aead_tag_len);
        co_await transport::async_read(*next_layer_, std::span(chunk_buf_.data(), chunk_buf_.size()), ec);
        if (ec)
        {
            co_return;
        }

        // 解密 payload
        decrypted_.resize(cur_payload_len_);
        decrypted_off_ = 0;
        if (const auto r = decrypt_ctx_->open(as_u8_mut(decrypted_), as_u8(chunk_buf_));
            r != fault::code::success)
        {
            trace::warn("{} decrypt payload block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            decrypted_.clear();
            co_return;
        }
    }


    auto conn::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await send_chunk(buffer, ec);
    }


    auto conn::send_chunk(const std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        const auto chunk_len = std::min(data.size(), static_cast<std::size_t>(max_chunk_size));

        trace::debug("{} send_chunk: chunk_len={}, data_size={}", tag, chunk_len, data.size());

        // 加密长度块
        std::array len_plain{
            static_cast<std::uint8_t>(chunk_len >> 8 & 0xFF),
            static_cast<std::uint8_t>(chunk_len & 0xFF)};

        std::array<std::uint8_t, len_block_size> len_enc{};
        if (const auto r = encrypt_ctx_->seal(len_enc, len_plain);
            r != fault::code::success)
        {
            trace::warn("{} encrypt length block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 加密 payload（复用成员缓冲区，避免每次堆分配）
        payload_enc_buf_.resize(crypto::aead_context::seal_size(chunk_len));
        if (const auto r = encrypt_ctx_->seal(payload_enc_buf_, as_u8(data.first(chunk_len)));
            r != fault::code::success)
        {
            trace::warn("{} encrypt payload block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        trace::debug("{} send_chunk: len_enc_size={}, payload_enc_size={}, calling transport::async_write",
                    tag, len_enc.size(), payload_enc_buf_.size());

        // 合并写入：加密长度块 + 加密 payload
        const std::size_t chunk_total = len_enc.size() + payload_enc_buf_.size();
        memory::vector<std::byte> chunk_combined(chunk_total, memory::current_resource());
        std::memcpy(chunk_combined.data(), len_enc.data(), len_enc.size());
        std::memcpy(chunk_combined.data() + len_enc.size(), payload_enc_buf_.data(), payload_enc_buf_.size());
        co_await transport::async_write(*next_layer_, chunk_combined, ec);

        auto ec_msg = ec.message();
        if (!ec_msg.empty() && (ec_msg.back() == '\n' || ec_msg.back() == '\r'))
            ec_msg = ec_msg.substr(0, ec_msg.find_first_of("\r\n"));
        std::size_t logged_len;
        if (ec)
        {
            logged_len = 0;
        }
        else
        {
            logged_len = chunk_len;
        }
        trace::debug("{} send_chunk: transport::async_write completed, ec={}, returned {}",
                    tag, ec_msg, logged_len);

        std::size_t sent;
        if (ec)
        {
            sent = 0;
        }
        else
        {
            sent = chunk_len;
        }

        co_return sent;
    }

} // namespace psm::protocol::shadowsocks
