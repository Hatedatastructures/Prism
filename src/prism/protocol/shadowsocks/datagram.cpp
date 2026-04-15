#include <prism/protocol/shadowsocks/datagram.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/crypto/block.hpp>
#include <cstring>
#include <cstdlib>
#include <chrono>

constexpr std::string_view tag = "[SS2022.UDP]";

namespace psm::protocol::shadowsocks
{
    namespace
    {
        /// byte span → uint8_t 只读 span
        [[nodiscard]] auto as_u8(const std::span<const std::byte> s) noexcept
            -> std::span<const std::uint8_t>
        {
            return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
        }

        /// 解析 MainHeader 公共部分后的数据（地址 + padding + payload）
        /// @param body_plain 解密后的明文缓冲区，result.payload span 将指向其子区间
        auto parse_body_after_timestamp(const memory::vector<std::uint8_t> &body_plain, udp_decrypted_packet &result)
            -> fault::code
        {
            // Type(1) + Timestamp(8) + 至少 1 字节 ATYP
            if (body_plain.size() < 10)
            {
                return fault::code::bad_message;
            }

            // 验证请求类型
            if (body_plain[0] != request_type)
            {
                trace::warn("{} invalid request type: 0x{:02x}", tag, body_plain[0]);
                return fault::code::bad_message;
            }

            // 验证时间戳
            std::uint64_t client_ts = 0;
            for (int i = 0; i < 8; ++i)
            {
                client_ts = (client_ts << 8) | body_plain[1 + i];
            }

            auto now_timestamp = std::chrono::system_clock::now().time_since_epoch();
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(now_timestamp).count();
            const auto diff = std::abs(static_cast<std::int64_t>(client_ts) - now);
            if (diff > timestamp_window)
            {
                trace::warn("{} timestamp expired: client_ts={}, now={}, diff={}s",
                            tag, client_ts, now, diff);
                return fault::code::timestamp_expired;
            }

            // 解析地址
            std::size_t offset = 9;
            const auto [addr_ec, addr_result] = format::parse_address_port(
                std::span<const std::uint8_t>(body_plain.data() + offset, body_plain.size() - offset));
            if (addr_ec != fault::code::success)
            {
                return addr_ec;
            }

            offset += addr_result.offset;

            // 跳过 padding
            if (offset + 2 <= body_plain.size())
            {
                const auto padding_len = static_cast<std::uint16_t>(body_plain[offset] << 8 | body_plain[offset + 1]);
                offset += 2 + padding_len;
            }

            // 提取 payload（零拷贝：span 指向 body_plain 子区间）
            result.destination_address = addr_result.addr;
            result.destination_port = addr_result.port;
            if (offset < body_plain.size())
            {
                result.payload = std::span<const std::uint8_t>(
                    body_plain.data() + offset, body_plain.size() - offset);
            }

            return fault::code::success;
        }
    } // namespace

    auto udp_relay::decrypt_inbound(std::span<const std::byte> packet, const net::ip::udp::endpoint &sender)
        -> std::pair<fault::code, udp_decrypted_packet>
    {
        if (method_ == cipher_method::chacha20_poly1305)
        {
            return decrypt_chacha20(packet, sender);
        }
        return decrypt_aes_gcm(packet, sender);
    }

    auto udp_relay::encrypt_outbound(std::span<const std::byte> payload, const std::array<std::uint8_t, session_id_len> &session_id,
                                     std::shared_ptr<udp_session_entry> entry)
        -> std::pair<fault::code, std::vector<std::byte>>
    {
        if (method_ == cipher_method::chacha20_poly1305)
        {
            return encrypt_chacha20(payload, session_id, std::move(entry));
        }
        return encrypt_aes_gcm(payload, session_id, std::move(entry));
    }

    auto udp_relay::decrypt_aes_gcm(std::span<const std::byte> packet, const net::ip::udp::endpoint &sender)
        -> std::pair<fault::code, udp_decrypted_packet>
    {
        udp_decrypted_packet result;
        result.sender_endpoint = sender;

        // 最小长度：SeparateHeader(16) + AEAD tag(16)
        if (packet.size() < separate_header_len + aead_tag_len)
        {
            trace::warn("{} packet too short: {} bytes", tag, packet.size());
            return {fault::code::bad_message, result};
        }

        // AES-ECB 解密 SeparateHeader → SessionID + PacketID
        std::array<std::uint8_t, separate_header_len> separate_header{};
        std::memcpy(separate_header.data(), packet.data(), separate_header_len);

        const auto key_span = std::span<const std::uint8_t>(psk_.data(), psk_.size());
        const auto header_plain = crypto::aes_ecb_decrypt(
            std::span<const std::uint8_t, 16>{separate_header.data(), 16}, key_span);

        std::array<std::uint8_t, session_id_len> session_id{};
        std::memcpy(session_id.data(), header_plain.data(), session_id_len);

        std::array<std::uint8_t, packet_id_len> packet_id{};
        std::memcpy(packet_id.data(), header_plain.data() + session_id_len, packet_id_len);

        const auto packet_id_val = read_u64_be(packet_id.data());

        // 查找或创建会话 → 获取缓存的 AEAD 上下文
        auto entry = session_tracker_->get_or_create(session_id, sender, psk_, method_);
        if (!entry || !entry->aead_ctx)
        {
            trace::warn("{} failed to get/create session", tag);
            return {fault::code::crypto_error, result};
        }

        // 构造 nonce：sessionID[4..8] + packetID[0..8] = 12 字节
        const auto nonce = construct_nonce_aes(session_id, packet_id);
        const auto nonce_span = std::span<const std::uint8_t>(nonce.data(), nonce.size());

        // AEAD 解密 body（PMR vector，零拷贝 payload 指向此缓冲区）
        const auto body_enc = packet.subspan(separate_header_len);
        memory::vector<std::uint8_t> body_plain(body_enc.size() - aead_tag_len,
                                                  memory::current_resource());

        if (const auto r = entry->aead_ctx->open(body_plain, as_u8(body_enc), nonce_span);
            r != fault::code::success)
        {
            trace::warn("{} AES-GCM decrypt body failed", tag);
            return {fault::code::crypto_error, result};
        }

        // 验证 PacketID 滑动窗口（解密成功后再验证，确保只跟踪认证过的包）
        if (!entry->packet_ids.check_and_update(packet_id_val))
        {
            trace::warn("{} packet replay detected: packet_id={}", tag, packet_id_val);
            return {fault::code::replay_detected, result};
        }

        // 解析 MainHeader + payload（payload span 指向 body_plain 子区间）
        const auto parse_ec = parse_body_after_timestamp(body_plain, result);
        if (parse_ec != fault::code::success)
        {
            return {parse_ec, result};
        }

        // 转移缓冲区所有权到 result，保持 payload span 有效
        result.buffer = std::move(body_plain);
        result.session_id = session_id;
        return {fault::code::success, result};
    }

    auto udp_relay::encrypt_aes_gcm(std::span<const std::byte> payload, const std::array<std::uint8_t, session_id_len> &session_id,
                                    std::shared_ptr<udp_session_entry> entry)
        -> std::pair<fault::code, std::vector<std::byte>>
    {
        if (!entry || !entry->aead_ctx)
        {
            return {fault::code::crypto_error, {}};
        }

        // 递增服务端 PacketID
        const auto server_packet_id = ++entry->server_packet_id;
        std::array<std::uint8_t, packet_id_len> packet_id{};
        write_u64_be(packet_id.data(), server_packet_id);

        // 构造明文：Type(1) + Timestamp(8) + PaddingLen(2) + Payload（PMR vector）
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        const auto plain_len = 1 + 8 + 2 + payload.size();
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = response_type;
        for (int i = 0; i < 8; ++i)
        {
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        }
        // PaddingLen = 0
        plain[9] = 0;
        plain[10] = 0;
        if (!payload.empty())
        {
            std::memcpy(plain.data() + 11, payload.data(), payload.size());
        }

        // 构造 nonce
        const auto nonce = construct_nonce_aes(session_id, packet_id);
        const auto nonce_span = std::span<const std::uint8_t>(nonce.data(), nonce.size());

        // AEAD 加密 body，直接写入输出缓冲区的 body 区间
        const auto body_enc_len = crypto::aead_context::seal_output_size(plain_len);

        // AES-ECB 加密 SeparateHeader：SessionID + PacketID
        std::array<std::uint8_t, separate_header_len> separate_plain{};
        std::memcpy(separate_plain.data(), session_id.data(), session_id_len);
        std::memcpy(separate_plain.data() + session_id_len, packet_id.data(), packet_id_len);

        const auto key_span = std::span<const std::uint8_t>(psk_.data(), psk_.size());
        const auto header_enc = crypto::aes_ecb_encrypt(
            std::span<const std::uint8_t, 16>{separate_plain.data(), 16}, key_span);

        // 直接在输出缓冲区中构造，消除中间 body_enc vector
        std::vector<std::byte> result(separate_header_len + body_enc_len);
        std::memcpy(result.data(), header_enc.data(), separate_header_len);

        // 将 body 密文直接写入 result 的 body 区间
        const auto body_out = std::span<std::uint8_t>(
            reinterpret_cast<std::uint8_t *>(result.data() + separate_header_len), body_enc_len);
        if (const auto r = entry->aead_ctx->seal(body_out, plain, nonce_span);
            r != fault::code::success)
        {
            trace::warn("{} AES-GCM encrypt body failed", tag);
            return {fault::code::crypto_error, {}};
        }

        return {fault::code::success, result};
    }

    auto udp_relay::decrypt_chacha20(std::span<const std::byte> packet, const net::ip::udp::endpoint &sender)
        -> std::pair<fault::code, udp_decrypted_packet>
    {
        udp_decrypted_packet result;
        result.sender_endpoint = sender;

        // 最小长度：SessionID(8) + PacketID(8) + AEAD tag(16)
        if (packet.size() < session_id_len + packet_id_len + aead_tag_len)
        {
            trace::warn("{} chacha20 packet too short: {} bytes", tag, packet.size());
            return {fault::code::bad_message, result};
        }

        // 提取明文 header：SessionID(8) + PacketID(8)
        std::array<std::uint8_t, session_id_len> session_id{};
        std::memcpy(session_id.data(), packet.data(), session_id_len);

        std::array<std::uint8_t, packet_id_len> packet_id{};
        std::memcpy(packet_id.data(), packet.data() + session_id_len, packet_id_len);

        const auto packet_id_val = read_u64_be(packet_id.data());

        // 构造 24 字节 nonce：SessionID(8) + PacketID(8) + zeros(8)
        std::array<std::uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), session_id.data(), session_id_len);
        std::memcpy(nonce.data() + session_id_len, packet_id.data(), packet_id_len);
        // 剩余 8 字节已由 zero-initialization 填充

        // 使用 PSK 直接构造 XChaCha20 上下文
        crypto::aead_context ctx(crypto::aead_cipher::xchacha20_poly1305,
                                 std::span<const std::uint8_t>(psk_.data(), psk_.size()));

        // 解密 body（跳过 16 字节明文 header，PMR vector）
        const auto body_enc = packet.subspan(session_id_len + packet_id_len);
        memory::vector<std::uint8_t> body_plain(body_enc.size() - aead_tag_len,
                                                  memory::current_resource());
        const auto nonce_span = std::span<const std::uint8_t>(nonce.data(), nonce.size());

        if (const auto r = ctx.open(body_plain, as_u8(body_enc), nonce_span);
            r != fault::code::success)
        {
            trace::warn("{} chacha20 decrypt body failed", tag);
            return {fault::code::crypto_error, result};
        }

        // 验证 PacketID 滑动窗口
        auto entry = session_tracker_->get_or_create(session_id, sender, psk_, method_);
        if (!entry->packet_ids.check_and_update(packet_id_val))
        {
            trace::warn("{} chacha20 packet replay detected: packet_id={}", tag, packet_id_val);
            return {fault::code::replay_detected, result};
        }

        // 解析 MainHeader + payload（payload span 指向 body_plain 子区间）
        const auto parse_ec = parse_body_after_timestamp(body_plain, result);
        if (parse_ec != fault::code::success)
        {
            return {parse_ec, result};
        }

        // 转移缓冲区所有权到 result，保持 payload span 有效
        result.buffer = std::move(body_plain);
        result.session_id = session_id;
        return {fault::code::success, result};
    }

    auto udp_relay::encrypt_chacha20(std::span<const std::byte> payload,
                                     const std::array<std::uint8_t, session_id_len> &session_id,
                                     std::shared_ptr<udp_session_entry> entry)
        -> std::pair<fault::code, std::vector<std::byte>>
    {
        if (!entry)
        {
            return {fault::code::crypto_error, {}};
        }

        // 递增服务端 PacketID
        const auto server_packet_id = ++entry->server_packet_id;
        std::array<std::uint8_t, packet_id_len> packet_id{};
        write_u64_be(packet_id.data(), server_packet_id);

        // 构造 24 字节 nonce：SessionID(8) + PacketID(8) + zeros(8)
        std::array<std::uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), session_id.data(), session_id_len);
        std::memcpy(nonce.data() + session_id_len, packet_id.data(), packet_id_len);

        // 构造明文：Type(1) + Timestamp(8) + PaddingLen(2) + Payload（PMR vector）
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        const auto plain_len = 1 + 8 + 2 + payload.size();
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = response_type;
        for (int i = 0; i < 8; ++i)
        {
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        }
        plain[9] = 0;
        plain[10] = 0;
        if (!payload.empty())
        {
            std::memcpy(plain.data() + 11, payload.data(), payload.size());
        }

        // XChaCha20-Poly1305 加密
        crypto::aead_context ctx(crypto::aead_cipher::xchacha20_poly1305,
                                 std::span<const std::uint8_t>(psk_.data(), psk_.size()));

        const auto body_enc_len = crypto::aead_context::seal_output_size(plain_len);
        const auto nonce_span = std::span<const std::uint8_t>(nonce.data(), nonce.size());

        // 直接在输出缓冲区中构造，消除中间 body_enc vector
        std::vector<std::byte> result(session_id_len + packet_id_len + body_enc_len);
        std::memcpy(result.data(), session_id.data(), session_id_len);
        std::memcpy(result.data() + session_id_len, packet_id.data(), packet_id_len);

        // 将加密 body 直接写入 result 的 body 区间
        const auto body_out = std::span<std::uint8_t>(
            reinterpret_cast<std::uint8_t *>(result.data() + session_id_len + packet_id_len),
            body_enc_len);
        if (const auto r = ctx.seal(body_out, plain, nonce_span);
            r != fault::code::success)
        {
            trace::warn("{} chacha20 encrypt body failed", tag);
            return {fault::code::crypto_error, {}};
        }

        return {fault::code::success, result};
    }

    auto udp_relay::construct_nonce_aes(
        const std::array<std::uint8_t, session_id_len> &session_id,
        const std::array<std::uint8_t, packet_id_len> &packet_id)
        -> std::array<std::uint8_t, 12>
    {
        std::array<std::uint8_t, 12> nonce{};
        // sessionID[4..8]：最后 4 字节
        std::memcpy(nonce.data(), session_id.data() + 4, 4);
        // packetID[0..8]：完整 8 字节
        std::memcpy(nonce.data() + 4, packet_id.data(), 8);
        return nonce;
    }

    auto udp_relay::read_u64_be(const std::uint8_t *data) -> std::uint64_t
    {
        std::uint64_t val = 0;
        for (int i = 0; i < 8; ++i)
        {
            val = (val << 8) | data[i];
        }
        return val;
    }

    void udp_relay::write_u64_be(std::uint8_t *data, std::uint64_t value)
    {
        for (int i = 0; i < 8; ++i)
        {
            data[7 - i] = static_cast<std::uint8_t>(value & 0xFF);
            value >>= 8;
        }
    }
} // namespace psm::protocol::shadowsocks
