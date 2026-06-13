#include <prism/stealth/recognition/tls/signal.hpp>

#include <prism/core/fault/handling.hpp>
#include <prism/proto/protocol/tls/record.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/transmission.hpp>

#include <cstring>

using namespace psm::trace;

namespace psm::recognition::tls
{

    namespace tls_proto = ::psm::protocol::tls;

    namespace
    {
        [[nodiscard]] auto read_u16(const std::span<const std::uint8_t> data, const std::size_t offset)
            -> std::uint16_t
        {
            return static_cast<std::uint16_t>(data[offset]) << 8 | static_cast<std::uint16_t>(data[offset + 1]);
        }

        [[nodiscard]] auto read_u24(const std::span<const std::uint8_t> data, const std::size_t offset)
            -> std::size_t
        {
            return static_cast<std::size_t>(data[offset]) << 16 | static_cast<std::size_t>(data[offset + 1]) << 8 |
                   static_cast<std::size_t>(data[offset + 2]);
        }


        void parse_sni(const std::span<const std::uint8_t> ext_data, tls_proto::hello_features &features)
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

                if (name_type != tls_proto::SNAME_TYPE_HOSTNAME)
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
                // 安全：将 uint8_t SNI 扩展数据转为 char* 用于提取服务器名称
                features.server_name.assign(
                    reinterpret_cast<const char *>(ext_data.data() + offset),
                    name_len);
                return;
            }
        }


        void parse_key_share(const std::span<const std::uint8_t> ext_data, tls_proto::hello_features &features)
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

                if (named_group == tls_proto::GROUP_X25519 && key_len == tls_proto::REALITY_KEY_LEN)
                {
                    std::memcpy(features.x25519_key.data(), ext_data.data() + offset, tls_proto::REALITY_KEY_LEN);
                    features.has_x25519 = true;
                    trace::debug<flt::conn | flt::protocol>("using pure X25519 key_share");
                    return;
                }

                if (named_group == tls_proto::GROUP_X25519_MLKEM768 && key_len >= tls_proto::REALITY_KEY_LEN)
                {
                    std::memcpy(features.x25519_key.data(), ext_data.data() + offset, tls_proto::REALITY_KEY_LEN);
                    features.has_x25519 = true;
                    trace::debug<flt::conn | flt::protocol>("using X25519MLKEM768 hybrid key_share");
                    return;
                }

                offset += key_len;
            }
        }


        void parse_versions(const std::span<const std::uint8_t> ext_data, tls_proto::hello_features &features)
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


        void parse_extensions(const std::span<const std::uint8_t> ext_data, tls_proto::hello_features &features)
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
                case tls_proto::EXT_SERVER_NAME:
                    parse_sni(ext_payload, features);
                    break;
                case tls_proto::EXT_KEY_SHARE:
                    parse_key_share(ext_payload, features);
                    break;
                case tls_proto::EXT_SUPPORTED_VERSIONS:
                    parse_versions(ext_payload, features);
                    break;
                case tls_proto::EXT_ENCRYPTED_CLIENT_HELLO:
                    features.has_ech = true;
                    break;
                default:
                    break;
                }

                offset += ext_len;
            }
        }
    } // namespace


    auto read_tls_record(transport::transmission &transport)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        auto [ec, rec] = co_await ::psm::tls::record::read(transport);
        if (fault::failed(ec))
        {
            trace::error<flt::conn | flt::protocol>("read record failed");
            co_return std::pair{ec, memory::vector<std::uint8_t>{}};
        }

        if (rec.header().content_type != tls_proto::CT_HANDSHAKE)
        {
            trace::error<flt::conn | flt::protocol>("unexpected content type: 0x{:02x}", rec.header().content_type);
            co_return std::pair{fault::code::recorderr, memory::vector<std::uint8_t>{}};
        }

        auto raw = rec.serialize();
        memory::vector<std::uint8_t> result(raw.size());
        std::memcpy(result.data(), raw.data(), raw.size());
        co_return std::pair{fault::code::success, std::move(result)};
    }


    auto read_tls_record(transport::transmission &transport, const std::span<const std::byte> preread)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        if (preread.size() < tls_proto::RECORD_HDR_LEN)
        {
            co_return co_await read_tls_record(transport);
        }

        // 安全：将 byte 预读缓冲区转为 uint8_t 以解析 TLS 记录头字段
        const auto *raw = reinterpret_cast<const std::uint8_t *>(preread.data());
        if (const auto content_type = raw[0]; content_type != tls_proto::CT_HANDSHAKE)
        {
            trace::error<flt::conn | flt::protocol>("not a handshake record: 0x{:02x}", content_type);
            co_return std::pair{fault::code::recorderr, memory::vector<std::uint8_t>{}};
        }

        const auto record_length = read_u16({raw, tls_proto::RECORD_HDR_LEN}, 3);

        if (record_length > tls_proto::MAX_RECORD_PAYLOAD)
        {
            trace::error<flt::conn | flt::protocol>("record too large: {}", record_length);
            co_return std::pair{fault::code::recorderr, memory::vector<std::uint8_t>{}};
        }

        const std::size_t total = tls_proto::RECORD_HDR_LEN + record_length;

        if (preread.size() >= total)
        {
            trace::debug<flt::conn | flt::protocol>("preread contains full ClientHello ({} bytes)", total);
            memory::vector<std::uint8_t> buffer(total);
            std::memcpy(buffer.data(), raw, total);
            co_return std::pair{fault::code::success, std::move(buffer)};
        }

        trace::debug<flt::conn | flt::protocol>("preread partial ({} bytes), need {} total", preread.size(), total);

        memory::vector<std::uint8_t> buffer(total);
        std::memcpy(buffer.data(), raw, preread.size());

        std::size_t read_offset = preread.size();
        while (read_offset < total)
        {
            std::error_code ec;
            // 安全：将 uint8_t 向量区域转为可变 byte span 用于异步读取
            const auto buf_span = std::span(reinterpret_cast<std::byte *>(buffer.data() + read_offset), total - read_offset);
            const auto n = co_await transport.async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                trace::error<flt::conn | flt::protocol>("read remaining failed at offset {}: {}", read_offset, ec.message());
                co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
            }
            read_offset += n;
        }

        co_return std::pair{fault::code::success, std::move(buffer)};
    }


    auto parse_client_hello(const std::span<const std::uint8_t> record)
        -> std::pair<fault::code, tls_proto::hello_features>
    {
        tls_proto::hello_features features;

        if (record.size() < 44)
        {
            trace::error<flt::conn | flt::protocol>("record too short: {}", record.size());
            return {fault::code::recorderr, std::move(features)};
        }

        if (record[0] != tls_proto::CT_HANDSHAKE)
        {
            trace::error<flt::conn | flt::protocol>("not a handshake record: 0x{:02x}", record[0]);
            return {fault::code::recorderr, std::move(features)};
        }

        const auto record_body_len = read_u16(record, 3);
        if (tls_proto::RECORD_HDR_LEN + record_body_len > record.size())
        {
            trace::error<flt::conn | flt::protocol>("record body truncated");
            return {fault::code::recorderr, std::move(features)};
        }

        std::size_t offset = tls_proto::RECORD_HDR_LEN;

        const auto handshake_type = record[offset];
        if (handshake_type != tls_proto::HS_CLIENT_HELLO)
        {
            trace::error<flt::conn | flt::protocol>("not ClientHello: 0x{:02x}", handshake_type);
            return {fault::code::recorderr, std::move(features)};
        }
        ++offset;

        const auto handshake_len = read_u24(record, offset);
        offset += 3;

        constexpr auto msg_start = tls_proto::RECORD_HDR_LEN;
        const auto msg_len = 4 + handshake_len;
        if (msg_start + msg_len > record.size())
        {
            trace::error<flt::conn | flt::protocol>("handshake message truncated");
            return {fault::code::recorderr, std::move(features)};
        }
        features.raw_msg.assign(record.data() + msg_start, record.data() + msg_start + msg_len);

        offset += 2; // ClientVersion

        if (offset + 32 > record.size())
            return {fault::code::recorderr, std::move(features)};
        std::memcpy(features.random.data(), record.data() + offset, 32);
        offset += 32;

        if (offset >= record.size())
            return {fault::code::recorderr, std::move(features)};
        const auto session_id_len = record[offset];
        ++offset;
        if (offset + session_id_len > record.size() || session_id_len > tls_proto::SESSION_ID_MAX_LEN)
        {
            trace::error<flt::conn | flt::protocol>("session_id length invalid: {}", session_id_len);
            return {fault::code::recorderr, std::move(features)};
        }
        features.session_id.assign(record.data() + offset, record.data() + offset + session_id_len);
        features.session_id_len = static_cast<std::uint8_t>(session_id_len);
        offset += session_id_len;

        if (offset + 2 > record.size())
            return {fault::code::recorderr, std::move(features)};
        const auto cipher_len = read_u16(record, offset);
        offset += 2;
        if (offset + cipher_len > record.size() || cipher_len % 2 != 0)
        {
            trace::error<flt::conn | flt::protocol>("cipher_suites length invalid: {}", cipher_len);
            return {fault::code::recorderr, std::move(features)};
        }
        offset += cipher_len;

        if (offset >= record.size())
            return {fault::code::recorderr, std::move(features)};
        const auto comp_len = record[offset];
        ++offset;
        if (offset + comp_len > record.size())
            return {fault::code::recorderr, std::move(features)};
        offset += comp_len;

        if (offset + 2 <= record.size())
        {
            const auto ext_data = record.subspan(offset);
            parse_extensions(ext_data, features);
        }

        features.raw_record.resize(record.size());
        std::memcpy(features.raw_record.data(), record.data(), record.size());

        trace::debug<flt::conn | flt::protocol>("parsed result: SNI='{}', has_key={}, versions={}",
                     features.server_name, features.has_x25519, features.versions.size());

        return {fault::code::success, std::move(features)};
    }

} // namespace psm::recognition::tls
