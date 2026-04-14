#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/constants.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <cstring>

namespace psm::protocol::reality
{
    constexpr std::string_view ChTag = "[Reality.ClientHello]";

    /**
     * @brief 从字节流中读取大端序 uint16
     */
    [[nodiscard]] static auto read_u16(std::span<const std::uint8_t> data, std::size_t offset) -> std::uint16_t
    {
        return (static_cast<std::uint16_t>(data[offset]) << 8) |
               static_cast<std::uint16_t>(data[offset + 1]);
    }

    /**
     * @brief 从字节流中读取大端序 uint24（3 字节）
     */
    [[nodiscard]] static auto read_u24(std::span<const std::uint8_t> data, std::size_t offset) -> std::size_t
    {
        return (static_cast<std::size_t>(data[offset]) << 16) |
               (static_cast<std::size_t>(data[offset + 1]) << 8) |
               static_cast<std::size_t>(data[offset + 2]);
    }

    auto read_tls_record(channel::transport::transmission &transport,
                         const std::span<const std::byte> initial_data)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        // 初始数据至少需要 5 字节 record header
        if (initial_data.size() < tls::RECORD_HEADER_LEN)
        {
            trace::error("{} initial data too short: {}", ChTag, initial_data.size());
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        // 解析 record header
        const auto *raw = reinterpret_cast<const std::uint8_t *>(initial_data.data());
        const auto content_type = raw[0];
        const auto record_length = read_u16({raw, initial_data.size()}, 3);

        if (content_type != tls::CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("{} unexpected content type: 0x{:02x}", ChTag, content_type);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        if (record_length > tls::MAX_RECORD_PAYLOAD)
        {
            trace::error("{} record too large: {}", ChTag, record_length);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        // 完整记录 = 5 字节 header + record_length 字节
        const std::size_t total = tls::RECORD_HEADER_LEN + record_length;
        memory::vector<std::uint8_t> record(total);

        // 复制已有数据
        const auto copy_len = std::min(initial_data.size(), total);
        std::memcpy(record.data(), raw, copy_len);

        // 读取剩余数据
        if (copy_len < total)
        {
            std::size_t read_offset = copy_len;
            while (read_offset < total)
            {
                std::error_code ec;
                auto buf_span = std::span<std::byte>(
                    reinterpret_cast<std::byte *>(record.data() + read_offset),
                    total - read_offset);
                const auto n = co_await transport.async_read_some(buf_span, ec);
                if (ec || n == 0)
                {
                    trace::error("{} read failed at offset {}: {}", ChTag, read_offset, ec.message());
                    co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
                }
                read_offset += n;
            }
        }

        co_return std::pair{fault::code::success, std::move(record)};
    }

    /**
     * @brief 解析 SNI 扩展
     * @details SNI 扩展格式：ServerNameListLen(2) + ServerNameType(1) + NameLen(2) + Name(N)
     */
    static auto parse_sni(std::span<const std::uint8_t> ext_data, client_hello_info &info) -> void
    {
        if (ext_data.size() < 2)
        {
            return;
        }

        std::size_t offset = 0;
        const auto list_len = read_u16(ext_data, offset);
        offset += 2;

        // 遍历 ServerNameList
        while (offset + 3 <= ext_data.size())
        {
            const auto name_type = ext_data[offset];
            ++offset;

            if (name_type != tls::SERVER_NAME_TYPE_HOSTNAME)
            {
                // 跳过非 hostname 类型
                if (offset + 2 > ext_data.size())
                {
                    break;
                }
                const auto name_len = read_u16(ext_data, offset);
                offset += 2 + name_len;
                continue;
            }

            if (offset + 2 > ext_data.size())
            {
                break;
            }
            const auto name_len = read_u16(ext_data, offset);
            offset += 2;

            if (offset + name_len > ext_data.size())
            {
                break;
            }
            info.server_name.assign(
                reinterpret_cast<const char *>(ext_data.data() + offset),
                name_len);
            // 只取第一个 hostname
            return;
        }
    }

    /**
     * @brief 解析 key_share 扩展
     * @details key_share 扩展格式（ClientHello）：
     * KeyShareListLen(2) + [NamedGroup(2) + KeyExchangeLen(2) + KeyExchange(N)]*
     * 兼容两种 Reality 客户端 key_share：
     * - 纯 X25519：KeyExchange 为 32 字节公钥
     * - X25519MLKEM768 hybrid：KeyExchange 很长，末尾 32 字节是 X25519 公钥
     */
    static auto parse_key_share(std::span<const std::uint8_t> ext_data, client_hello_info &info) -> void
    {
        if (ext_data.size() < 2)
        {
            return;
        }

        std::size_t offset = 0;
        const auto list_len = read_u16(ext_data, offset);
        offset += 2;

        const std::size_t end = std::min(offset + list_len, ext_data.size());
        while (offset + 4 <= end)
        {
            const auto named_group = read_u16(ext_data, offset);
            offset += 2;
            const auto key_len = read_u16(ext_data, offset);
            offset += 2;

            if (offset + key_len > end)
            {
                break;
            }

            if (named_group == tls::NAMED_GROUP_X25519 && key_len == tls::REALITY_KEY_LEN)
            {
                std::memcpy(info.client_public_key.data(), ext_data.data() + offset, tls::REALITY_KEY_LEN);
                info.has_client_public_key = true;
                trace::debug("{} using pure X25519 key_share", ChTag);
                return;
            }

            if (named_group == tls::NAMED_GROUP_X25519_MLKEM768 && key_len >= tls::REALITY_KEY_LEN)
            {
                const auto x25519_offset = offset + key_len - tls::REALITY_KEY_LEN;
                std::memcpy(info.client_public_key.data(), ext_data.data() + x25519_offset, tls::REALITY_KEY_LEN);
                info.has_client_public_key = true;
                trace::debug("{} using X25519MLKEM768 hybrid key_share, extracted trailing X25519 pubkey", ChTag);
                return;
            }

            offset += key_len;
        }
    }

    /**
     * @brief 解析 supported_versions 扩展
     * @details 格式：ListLen(1) + [Version(2)]*
     */
    static auto parse_supported_versions(std::span<const std::uint8_t> ext_data, client_hello_info &info) -> void
    {
        if (ext_data.empty())
        {
            return;
        }

        std::size_t offset = 0;
        const auto list_len = ext_data[offset];
        ++offset;

        while (offset + 2 <= ext_data.size() && offset + 2 <= static_cast<std::size_t>(list_len) + 1)
        {
            info.supported_versions.push_back(read_u16(ext_data, offset));
            offset += 2;
        }
    }

    /**
     * @brief 遍历并解析所有扩展
     */
    static auto parse_extensions(std::span<const std::uint8_t> ext_data, client_hello_info &info) -> void
    {
        if (ext_data.size() < 2)
        {
            trace::debug("{} extensions data too short: {}", ChTag, ext_data.size());
            return;
        }

        std::size_t offset = 0;
        const auto ext_total_len = read_u16(ext_data, offset);
        offset += 2;
        const std::size_t ext_end = offset + ext_total_len;
        while (offset + 4 <= ext_end && offset + 4 <= ext_data.size())
        {
            const auto ext_type = read_u16(ext_data, offset);
            offset += 2;
            const auto ext_len = read_u16(ext_data, offset);
            offset += 2;

            if (offset + ext_len > ext_data.size())
            {
                break;
            }

            const auto ext_payload = ext_data.subspan(offset, ext_len);

            switch (ext_type)
            {
            case tls::EXT_SERVER_NAME:
                parse_sni(ext_payload, info);
                break;
            case tls::EXT_KEY_SHARE:
                parse_key_share(ext_payload, info);
                break;
            case tls::EXT_SUPPORTED_VERSIONS:
                parse_supported_versions(ext_payload, info);
                break;
            default:
                break;
            }

            offset += ext_len;
        }
    }

    auto parse_client_hello(const std::span<const std::uint8_t> raw_tls_record)
        -> std::pair<fault::code, client_hello_info>
    {
        client_hello_info info;

        // 最低长度：RecordHeader(5) + HandshakeType(1) + HandshakeLength(3) +
        //            ClientVersion(2) + Random(32) + SessionIDLen(1) = 44
        if (raw_tls_record.size() < 44)
        {
            trace::error("{} record too short: {}", ChTag, raw_tls_record.size());
            return {fault::code::reality_tls_record_error, std::move(info)};
        }

        // 验证 record header
        if (raw_tls_record[0] != tls::CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("{} not a handshake record: 0x{:02x}", ChTag, raw_tls_record[0]);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }

        const auto record_body_len = read_u16(raw_tls_record, 3);
        if (tls::RECORD_HEADER_LEN + record_body_len > raw_tls_record.size())
        {
            trace::error("{} record body truncated", ChTag);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }

        // Handshake 消息从 offset 5 开始
        std::size_t offset = tls::RECORD_HEADER_LEN;

        // HandshakeType
        const auto handshake_type = raw_tls_record[offset];
        if (handshake_type != tls::HANDSHAKE_TYPE_CLIENT_HELLO)
        {
            trace::error("{} not ClientHello: 0x{:02x}", ChTag, handshake_type);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        ++offset;

        // HandshakeLength (3 字节)
        const auto handshake_len = read_u24(raw_tls_record, offset);
        offset += 3;

        // 保存 raw_message（包含 handshake header + body）
        const auto msg_start = tls::RECORD_HEADER_LEN;
        const auto msg_len = 4 + handshake_len;
        if (msg_start + msg_len > raw_tls_record.size())
        {
            trace::error("{} handshake message truncated", ChTag);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        info.raw_message.assign(raw_tls_record.data() + msg_start,
                                raw_tls_record.data() + msg_start + msg_len);

        // ClientVersion (2 字节，legacy）
        offset += 2;

        // Random (32 字节)
        if (offset + 32 > raw_tls_record.size())
        {
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        std::memcpy(info.random.data(), raw_tls_record.data() + offset, 32);
        offset += 32;

        // SessionID (1 字节长度 + 变长数据)
        if (offset >= raw_tls_record.size())
        {
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        const auto session_id_len = raw_tls_record[offset];
        ++offset;
        if (offset + session_id_len > raw_tls_record.size() ||
            session_id_len > tls::SESSION_ID_MAX_LEN)
        {
            trace::error("{} session_id length invalid: {}", ChTag, session_id_len);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        info.session_id.assign(raw_tls_record.data() + offset,
                               raw_tls_record.data() + offset + session_id_len);
        offset += session_id_len;

        // CipherSuites (2 字节长度 + 变长数据)
        if (offset + 2 > raw_tls_record.size())
        {
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        const auto cipher_len = read_u16(raw_tls_record, offset);
        offset += 2;
        if (offset + cipher_len > raw_tls_record.size() || cipher_len % 2 != 0)
        {
            trace::error("{} cipher_suites length invalid: {}", ChTag, cipher_len);
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        offset += cipher_len;

        // CompressionMethods (1 字节长度 + 变长数据)
        if (offset >= raw_tls_record.size())
        {
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        const auto comp_len = raw_tls_record[offset];
        ++offset;
        if (offset + comp_len > raw_tls_record.size())
        {
            return {fault::code::reality_tls_record_error, std::move(info)};
        }
        offset += comp_len;

        // Extensions (2 字节长度 + 变长数据)
        if (offset + 2 <= raw_tls_record.size())
        {
            const auto ext_data = raw_tls_record.subspan(offset);
            parse_extensions(ext_data, info);
        }
        trace::debug("{} parsed result: SNI='{}', has_key={}, versions={}",
                     ChTag, info.server_name, info.has_client_public_key, info.supported_versions.size());

        return {fault::code::success, std::move(info)};
    }
} // namespace psm::protocol::reality
