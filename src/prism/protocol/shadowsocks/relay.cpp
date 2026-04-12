/**
 * @file relay.cpp
 * @brief SS2022 (SIP022) AEAD 流加密中继器实现
 * @details 实现 SS2022 协议的完整握手流程和 AEAD 分帧加解密。
 * 这是 SS2022 实现中最核心的组件——relay 在整个会话生命周期内
 * 保持活跃，处理所有数据的 AEAD 加解密。
 */

#include <prism/protocol/shadowsocks/relay.hpp>
#include <prism/trace/spdlog.hpp>
#include <cstring>
#include <chrono>

constexpr std::string_view tag = "[SS2022.Relay]";

namespace psm::protocol::shadowsocks
{
    namespace
    {
        /// byte span → uint8_t 只读 span，用于 AEAD 密文输入
        [[nodiscard]] auto as_u8(const std::span<const std::byte> s) noexcept
            -> std::span<const std::uint8_t>
        {
            return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
        }

        /// byte vector → uint8_t 可写 span，用于 AEAD 解密输出
        [[nodiscard]] auto as_u8_mut(std::vector<std::byte> &v) noexcept
            -> std::span<std::uint8_t>
        {
            return {reinterpret_cast<std::uint8_t *>(v.data()), v.size()};
        }

        /// 任意连续容器 → const byte span，用于 scatter-gather 写入
        [[nodiscard]] auto to_bytes(const auto &c) noexcept -> std::span<const std::byte>
        {
            return std::as_bytes(std::span{c});
        }
    } // namespace

    // === 构造 / 控制 ===

    relay::relay(channel::transport::shared_transmission next_layer, const config &cfg,
                 std::shared_ptr<salt_pool> salts)
        : next_layer_(std::move(next_layer)), config_(cfg), salt_pool_(std::move(salts))
    {
        const auto [ec, psk_bytes] = format::decode_psk(config_.psk);
        if (ec != fault::code::success)
        {
            trace::error("{} invalid PSK configuration: {}", tag, fault::describe(ec));
            return;
        }
        psk_ = std::move(psk_bytes);

        if (psk_.size() == 16)
        {
            method_ = cipher_method::aes_128_gcm;
            key_salt_length_ = 16;
        }
        else
        {
            method_ = cipher_method::aes_256_gcm;
            key_salt_length_ = 32;
        }
    }

    auto relay::executor() const -> executor_type
    {
        return next_layer_->executor();
    }

    void relay::close()
    {
        if (next_layer_)
        {
            next_layer_->close();
        }
    }

    void relay::cancel()
    {
        if (next_layer_)
        {
            next_layer_->cancel();
        }
    }

    // === 密钥派生 ===

    auto relay::derive_aead_context(const std::vector<std::uint8_t> &salt) const
        -> std::unique_ptr<crypto::aead_context>
    {
        // 拼接 PSK + salt 作为密钥材料
        std::vector<std::uint8_t> material(psk_.size() + salt.size());
        std::memcpy(material.data(), psk_.data(), psk_.size());
        std::memcpy(material.data() + psk_.size(), salt.data(), salt.size());

        const auto key = crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material), key_salt_length_);

        const auto cipher = method_ == cipher_method::aes_128_gcm
                                ? crypto::aead_cipher::aes_128_gcm
                                : crypto::aead_cipher::aes_256_gcm;

        return std::make_unique<crypto::aead_context>(cipher, std::span(key));
    }

    // === 握手子步骤 ===

    auto relay::read_fixed_header() const
        -> net::awaitable<std::tuple<fault::code, std::uint16_t, std::int64_t>>
    {
        constexpr auto fail = [](const fault::code ec)
            -> std::tuple<fault::code, std::uint16_t, std::int64_t>
        { return {ec, 0, 0}; };

        std::error_code ec;

        // 读取加密固定头（27 字节）
        std::array<std::byte, fixed_header_size> header_enc{};
        co_await next_layer_->async_read(header_enc, ec);
        if (ec)
        {
            trace::warn("{} read fixed header failed: {}", tag, ec.message());
            co_return fail(fault::code::connection_reset);
        }

        // AEAD 解密
        std::array<std::uint8_t, fixed_header_plain> header_plain{};
        if (const auto r = decrypt_ctx_->open(header_plain, as_u8(header_enc));
            r != fault::code::success)
        {
            trace::warn("{} decrypt fixed header failed: {}", tag, fault::describe(r));
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
        for (int i = 0; i < 8; ++i)
        {
            client_ts = (client_ts << 8) | header_plain[1 + i];
        }

        // 时间戳窗口验证
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto diff = static_cast<std::int64_t>(client_ts) > now
                              ? static_cast<std::int64_t>(client_ts) - now
                              : now - static_cast<std::int64_t>(client_ts);
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

    auto relay::read_variable_header(const std::uint16_t var_header_len, request &req)
        -> net::awaitable<fault::code>
    {
        std::error_code ec;

        // 读取加密变长头
        std::vector<std::byte> var_header_enc(var_header_len + aead_tag_len);
        co_await next_layer_->async_read(var_header_enc, ec);
        if (ec)
        {
            trace::warn("{} read variable header failed: {}", tag, ec.message());
            co_return fault::code::connection_reset;
        }

        // AEAD 解密
        std::vector<std::uint8_t> var_header_plain(var_header_len);
        if (const auto r = decrypt_ctx_->open(var_header_plain, as_u8(var_header_enc));
            r != fault::code::success)
        {
            trace::warn("{} decrypt variable header failed: {}", tag, fault::describe(r));
            co_return fault::code::auth_failed;
        }

        // 解析地址和端口
        const auto [addr_ec, addr_result] = format::parse_address_port(
            std::span<const std::uint8_t>(var_header_plain));
        if (addr_ec != fault::code::success)
        {
            trace::warn("{} address parse failed: {}", tag, fault::describe(addr_ec));
            co_return addr_ec;
        }

        req.destination_address = addr_result.addr;
        req.port = addr_result.port;

        target_ = analysis::target();
        target_.host = to_string(req.destination_address);
        target_.port = std::to_string(req.port);
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
                initial_payload_.resize(payload_size);
                std::memcpy(initial_payload_.data(), var_header_plain.data() + offset,payload_size);
            }
        }

        co_return fault::code::success;
    }

    auto relay::send_response(const std::vector<std::uint8_t> &client_salt, const std::int64_t server_ts)
        -> net::awaitable<fault::code>
    {
        std::error_code ec;

        // 生成随机 server salt
        std::vector<std::uint8_t> server_salt(key_salt_length_);
        std::uniform_int_distribution<std::uint32_t> dist(0, 255);
        for (auto &b : server_salt)
        {
            b = static_cast<std::uint8_t>(dist(rng_));
        }

        encrypt_ctx_ = derive_aead_context(server_salt);

        // 构建响应固定头明文：type(1) + timestamp(8) + requestSalt + paddingLen(2)
        const std::size_t resp_fixed_plain_len = 1 + 8 + key_salt_length_ + 2;
        std::vector<std::uint8_t> resp_fixed_plain(resp_fixed_plain_len);
        resp_fixed_plain[0] = response_type;

        // 服务端时间戳（大端序）
        const auto ts = static_cast<std::uint64_t>(server_ts);
        for (int i = 0; i < 8; ++i)
        {
            resp_fixed_plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        }

        // requestSalt + paddingLen = 0
        std::memcpy(resp_fixed_plain.data() + 9, client_salt.data(), key_salt_length_);
        resp_fixed_plain[9 + key_salt_length_] = 0;
        resp_fixed_plain[9 + key_salt_length_ + 1] = 0;

        // AEAD 加密响应固定头
        std::vector<std::uint8_t> resp_fixed_enc(
            crypto::aead_context::seal_output_size(resp_fixed_plain_len));
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

        // scatter-gather 写入：server_salt + 加密固定头 + 加密空初始 payload
        const std::span<const std::byte> resp_parts[] = {to_bytes(server_salt), to_bytes(resp_fixed_enc), to_bytes(empty_payload_enc)};
        co_await next_layer_->async_write_scatter(resp_parts, 3, ec);
        if (ec)
        {
            trace::warn("{} write response failed: {}", tag, ec.message());
            co_return fault::code::connection_reset;
        }

        co_return fault::code::success;
    }

    // === 握手 ===

    auto relay::handshake() -> net::awaitable<std::pair<fault::code, request>>
    {
        request req;
        req.method = method_;

        if (psk_.empty())
        {
            trace::error("{} PSK not configured", tag);
            co_return std::pair{fault::code::invalid_psk, req};
        }

        std::error_code ec;

        // 1. 读取 client salt
        std::vector<std::uint8_t> client_salt(key_salt_length_);
        co_await next_layer_->async_read(std::as_writable_bytes(std::span(client_salt)), ec);
        if (ec)
        {
            trace::warn("{} read client salt failed: {}", tag, ec.message());
            co_return std::pair{fault::code::connection_reset, req};
        }

        // 2. Salt 重放检查
        if (salt_pool_ && !salt_pool_->check_and_insert(client_salt))
        {
            trace::warn("{} salt replay detected", tag);
            co_return std::pair{fault::code::replay_detected, req};
        }

        // 3. 派生解密上下文
        decrypt_ctx_ = derive_aead_context(client_salt);

        // 4. 读取并验证固定头
        auto [header_ec, var_header_len, now] = co_await read_fixed_header();
        if (header_ec != fault::code::success)
        {
            co_return std::pair{header_ec, req};
        }

        // 5. 读取并解析变长头
        auto var_ec = co_await read_variable_header(var_header_len, req);
        if (var_ec != fault::code::success)
        {
            co_return std::pair{var_ec, req};
        }

        // 6. 发送响应
        auto resp_ec = co_await send_response(client_salt, now);
        if (resp_ec != fault::code::success)
        {
            co_return std::pair{resp_ec, req};
        }

        co_return std::pair{fault::code::success, req};
    }

    // === 读取 ===

    auto relay::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 优先返回初始 payload
        if (initial_offset_ < initial_payload_.size())
        {
            const auto available = initial_payload_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_payload_.data() + initial_offset_, n);
            initial_offset_ += n;
            co_return n;
        }

        // 从已解密缓冲区返回
        if (decrypted_offset_ < decrypted_.size())
        {
            const auto available = decrypted_.size() - decrypted_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), decrypted_.data() + decrypted_offset_, n);
            decrypted_offset_ += n;

            if (decrypted_offset_ == decrypted_.size())
            {
                decrypted_.clear();
                decrypted_offset_ = 0;
            }
            co_return n;
        }

        // 读取并解密下一个 chunk
        co_await fetch_chunk(ec);
        if (ec)
        {
            trace::warn("{} async_read_some: fetch_chunk failed: {}", tag, ec.message());
            co_return 0;
        }

        if (decrypted_.empty())
        {
            co_return 0;
        }

        const auto n = std::min(decrypted_.size(), buffer.size());
        std::memcpy(buffer.data(), decrypted_.data(), n);
        decrypted_offset_ = n;

        if (decrypted_offset_ == decrypted_.size())
        {
            decrypted_.clear();
            decrypted_offset_ = 0;
        }

        co_return n;
    }

    auto relay::fetch_chunk(std::error_code &ec) -> net::awaitable<void>
    {
        // 读取加密长度块（18 字节）
        co_await next_layer_->async_read(length_buf_, ec);
        if (ec)
        {
            co_return;
        }

        // 解密长度
        std::array<std::uint8_t, 2> len_plain{};
        if (const auto r = decrypt_ctx_->open(len_plain, as_u8(length_buf_));
            r != fault::code::success)
        {
            trace::warn("{} decrypt length block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return;
        }

        current_payload_len_ = static_cast<std::uint16_t>((len_plain[0] << 8) | len_plain[1]);

        if (current_payload_len_ == 0)
        {
            co_return;
        }

        // 读取加密 payload 块
        chunk_buf_.resize(current_payload_len_ + aead_tag_len);
        co_await next_layer_->async_read(std::span(chunk_buf_.data(), chunk_buf_.size()), ec);
        if (ec)
        {
            co_return;
        }

        // 解密 payload
        decrypted_.resize(current_payload_len_);
        decrypted_offset_ = 0;
        if (const auto r = decrypt_ctx_->open(as_u8_mut(decrypted_), as_u8(chunk_buf_));
            r != fault::code::success)
        {
            trace::warn("{} decrypt payload block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            decrypted_.clear();
            co_return;
        }
    }

    // === 写入 ===

    auto relay::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await send_chunk(buffer, ec);
    }

    auto relay::send_chunk(const std::span<const std::byte> data, std::error_code &ec) const
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        const auto chunk_len = std::min(data.size(), static_cast<std::size_t>(max_chunk_size));

        // 加密长度块
        std::array len_plain{
            static_cast<std::uint8_t>(chunk_len >> 8 & 0xFF),
            static_cast<std::uint8_t>(chunk_len & 0xFF)};

        std::array<std::uint8_t, length_block_size> len_enc{};
        if (const auto r = encrypt_ctx_->seal(len_enc, len_plain);
            r != fault::code::success)
        {
            trace::warn("{} encrypt length block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 加密 payload
        std::vector<std::uint8_t> payload_enc(crypto::aead_context::seal_output_size(chunk_len));
        if (const auto r = encrypt_ctx_->seal(payload_enc, as_u8(data.first(chunk_len)));
            r != fault::code::success)
        {
            trace::warn("{} encrypt payload block failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // scatter-gather 写入
        const std::span<const std::byte> parts[] = {to_bytes(len_enc), to_bytes(payload_enc)};
        co_await next_layer_->async_write_scatter(parts, 2, ec);

        co_return ec ? 0 : chunk_len;
    }
} // namespace psm::protocol::shadowsocks
