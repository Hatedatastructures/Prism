/**
 * @file signal.cpp
 * @brief TLS ClientHello 解析器实现
 * @details 从 stealth/reality/request.cpp 提取的通用 TLS 解析逻辑。
 */

#include <prism/protocol/tls/signal.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <cstring>

namespace psm::protocol::tls
{
    constexpr std::string_view Tag = "[TLS.Signal]";

    // ═══════════════════════════════════════════════════════════════════════
    // 内部工具函数
    // ═══════════════════════════════════════════════════════════════════════

    [[nodiscard]] static auto read_u16(const std::span<const std::uint8_t> data, const std::size_t offset)
        -> std::uint16_t
    {
        return static_cast<std::uint16_t>(data[offset]) << 8 | static_cast<std::uint16_t>(data[offset + 1]);
    }

    [[nodiscard]] static auto read_u24(const std::span<const std::uint8_t> data, const std::size_t offset)
        -> std::size_t
    {
        return static_cast<std::size_t>(data[offset]) << 16 | static_cast<std::size_t>(data[offset + 1]) << 8 |
               static_cast<std::size_t>(data[offset + 2]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // read_tls_record
    // ═══════════════════════════════════════════════════════════════════════

    auto read_tls_record(channel::transport::transmission &transport)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        // 1. 读取 TLS 记录头（5 字节）
        std::array<std::byte, RECORD_HEADER_LEN> header{};
        std::size_t header_read = 0;
        while (header_read < RECORD_HEADER_LEN)
        {
            std::error_code ec;
            const auto buf_span = std::span(header.data() + header_read, RECORD_HEADER_LEN - header_read);
            const auto n = co_await transport.async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                trace::error("{} read record header failed: {}", Tag, ec.message());
                co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
            }
            header_read += n;
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const auto content_type = raw[0];
        const auto record_length = read_u16({raw, RECORD_HEADER_LEN}, 3);

        if (content_type != CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("{} unexpected content type: 0x{:02x}", Tag, content_type);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        if (record_length > MAX_RECORD_PAYLOAD)
        {
            trace::error("{} record too large: {}", Tag, record_length);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        // 2. 读取记录体
        const std::size_t total = RECORD_HEADER_LEN + record_length;
        memory::vector<std::uint8_t> record(total);
        std::memcpy(record.data(), raw, RECORD_HEADER_LEN);

        std::size_t read_offset = RECORD_HEADER_LEN;
        while (read_offset < total)
        {
            std::error_code ec;
            const auto buf_span = std::span(reinterpret_cast<std::byte *>(record.data() + read_offset), total - read_offset);
            const auto n = co_await transport.async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                trace::error("{} read failed at offset {}: {}", Tag, read_offset, ec.message());
                co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
            }
            read_offset += n;
        }

        co_return std::pair{fault::code::success, std::move(record)};
    }

    auto read_tls_record(channel::transport::transmission &transport, const std::span<const std::byte> preread)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        if (preread.size() < RECORD_HEADER_LEN)
        {
            // 预读数据不足，从头开始读
            co_return co_await read_tls_record(transport);
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(preread.data());

        if (const auto content_type = raw[0]; content_type != CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("{} not a handshake record: 0x{:02x}", Tag, content_type);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        const auto record_length = read_u16({raw, RECORD_HEADER_LEN}, 3);

        if (record_length > MAX_RECORD_PAYLOAD)
        {
            trace::error("{} record too large: {}", Tag, record_length);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        const std::size_t total = RECORD_HEADER_LEN + record_length;

        if (preread.size() >= total)
        {
            trace::debug("{} preread contains full ClientHello ({} bytes)", Tag, total);
            memory::vector<std::uint8_t> buffer(total);
            std::memcpy(buffer.data(), raw, total);
            co_return std::pair{fault::code::success, std::move(buffer)};
        }

        trace::debug("{} preread partial ({} bytes), need {} total", Tag, preread.size(), total);

        memory::vector<std::uint8_t> buffer(total);
        std::memcpy(buffer.data(), raw, preread.size());

        std::size_t read_offset = preread.size();
        while (read_offset < total)
        {
            std::error_code ec;
            const auto buf_span = std::span(reinterpret_cast<std::byte *>(buffer.data() + read_offset), total - read_offset);
            const auto n = co_await transport.async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                trace::error("{} read remaining failed at offset {}: {}", Tag, read_offset, ec.message());
                co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
            }
            read_offset += n;
        }

        co_return std::pair{fault::code::success, std::move(buffer)};
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 内部解析函数
    // ═══════════════════════════════════════════════════════════════════════

    static auto parse_sni(const std::span<const std::uint8_t> ext_data, client_hello_features &features) -> void
    {
        if (ext_data.size() < 2)
            return;

        std::size_t offset = 0;
        const auto list_len = read_u16(ext_data, offset);
        offset += 2;

        while (offset + 3 <= ext_data.size())
        {
            const auto name_type = ext_data[offset];
            ++offset;

            if (name_type != SERVER_NAME_TYPE_HOSTNAME)
            {
                if (offset + 2 > ext_data.size())
                    break;
                const auto name_len = read_u16(ext_data, offset);
                offset += 2 + name_len;
                continue;
            }

            if (offset + 2 > ext_data.size())
                break;
            const auto name_len = read_u16(ext_data, offset);
            offset += 2;

            if (offset + name_len > ext_data.size())
                break;
            features.server_name.assign(
                reinterpret_cast<const char *>(ext_data.data() + offset),
                name_len);
            return;
        }
    }

    static auto parse_key_share(const std::span<const std::uint8_t> ext_data, client_hello_features &features) -> void
    {
        if (ext_data.size() < 2)
            return;

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
                break;

            if (named_group == NAMED_GROUP_X25519 && key_len == REALITY_KEY_LEN)
            {
                std::memcpy(features.x25519_key.data(), ext_data.data() + offset, REALITY_KEY_LEN);
                features.has_x25519 = true;
                trace::debug("{} using pure X25519 key_share", Tag);
                return;
            }

            if (named_group == NAMED_GROUP_X25519_MLKEM768 && key_len >= REALITY_KEY_LEN)
            {
                const auto x25519_offset = offset + key_len - REALITY_KEY_LEN;
                std::memcpy(features.x25519_key.data(), ext_data.data() + x25519_offset, REALITY_KEY_LEN);
                features.has_x25519 = true;
                trace::debug("{} using X25519MLKEM768 hybrid key_share", Tag);
                return;
            }

            offset += key_len;
        }
    }

    static auto parse_versions(const std::span<const std::uint8_t> ext_data, client_hello_features &features) -> void
    {
        if (ext_data.empty())
            return;

        std::size_t offset = 0;
        const auto list_len = ext_data[offset];
        ++offset;

        while (offset + 2 <= ext_data.size() && offset + 2 <= static_cast<std::size_t>(list_len) + 1)
        {
            features.versions.push_back(read_u16(ext_data, offset));
            offset += 2;
        }
    }

    static auto parse_extensions(const std::span<const std::uint8_t> ext_data, client_hello_features &features) -> void
    {
        if (ext_data.size() < 2)
            return;

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
                break;

            const auto ext_payload = ext_data.subspan(offset, ext_len);

            switch (ext_type)
            {
            case EXT_SERVER_NAME:
                parse_sni(ext_payload, features);
                break;
            case EXT_KEY_SHARE:
                parse_key_share(ext_payload, features);
                break;
            case EXT_SUPPORTED_VERSIONS:
                parse_versions(ext_payload, features);
                break;
            default:
                break;
            }

            offset += ext_len;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // parse_client_hello
    // ═══════════════════════════════════════════════════════════════════════

    auto parse_client_hello(const std::span<const std::uint8_t> record)
        -> std::pair<fault::code, client_hello_features>
    {
        client_hello_features features;

        if (record.size() < 44)
        {
            trace::error("{} record too short: {}", Tag, record.size());
            return {fault::code::reality_tls_record_error, std::move(features)};
        }

        if (record[0] != CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("{} not a handshake record: 0x{:02x}", Tag, record[0]);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }

        const auto record_body_len = read_u16(record, 3);
        if (RECORD_HEADER_LEN + record_body_len > record.size())
        {
            trace::error("{} record body truncated", Tag);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }

        std::size_t offset = RECORD_HEADER_LEN;

        const auto handshake_type = record[offset];
        if (handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO)
        {
            trace::error("{} not ClientHello: 0x{:02x}", Tag, handshake_type);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }
        ++offset;

        const auto handshake_len = read_u24(record, offset);
        offset += 3;

        constexpr auto msg_start = RECORD_HEADER_LEN;
        const auto msg_len = 4 + handshake_len;
        if (msg_start + msg_len > record.size())
        {
            trace::error("{} handshake message truncated", Tag);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }
        features.raw_hs_msg.assign(record.data() + msg_start, record.data() + msg_start + msg_len);

        offset += 2; // ClientVersion

        if (offset + 32 > record.size())
            return {fault::code::reality_tls_record_error, std::move(features)};
        std::memcpy(features.random.data(), record.data() + offset, 32);
        offset += 32;

        if (offset >= record.size())
            return {fault::code::reality_tls_record_error, std::move(features)};
        const auto session_id_len = record[offset];
        ++offset;
        if (offset + session_id_len > record.size() || session_id_len > SESSION_ID_MAX_LEN)
        {
            trace::error("{} session_id length invalid: {}", Tag, session_id_len);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }
        features.session_id.assign(record.data() + offset, record.data() + offset + session_id_len);
        features.session_id_len = static_cast<std::uint8_t>(session_id_len);
        offset += session_id_len;

        if (offset + 2 > record.size())
            return {fault::code::reality_tls_record_error, std::move(features)};
        const auto cipher_len = read_u16(record, offset);
        offset += 2;
        if (offset + cipher_len > record.size() || cipher_len % 2 != 0)
        {
            trace::error("{} cipher_suites length invalid: {}", Tag, cipher_len);
            return {fault::code::reality_tls_record_error, std::move(features)};
        }
        offset += cipher_len;

        if (offset >= record.size())
            return {fault::code::reality_tls_record_error, std::move(features)};
        const auto comp_len = record[offset];
        ++offset;
        if (offset + comp_len > record.size())
            return {fault::code::reality_tls_record_error, std::move(features)};
        offset += comp_len;

        if (offset + 2 <= record.size())
        {
            const auto ext_data = record.subspan(offset);
            parse_extensions(ext_data, features);
        }

        // 保存原始记录
        features.raw_record.resize(record.size());
        std::memcpy(features.raw_record.data(), record.data(), record.size());

        trace::debug("{} parsed result: SNI='{}', has_key={}, versions={}",
                     Tag, features.server_name, features.has_x25519, features.versions.size());

        return {fault::code::success, std::move(features)};
    }

} // namespace psm::protocol::tls
