#include <prism/proto/protocol/tls/hello.hpp>

#include <prism/proto/protocol/tls/record.hpp>

#include <cstring>


namespace psm::tls
{

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

        void parse_sni(const std::span<const std::uint8_t> ext_data, memory::string &sni)
        {
            if (ext_data.size() < 2)
            {
                return;
            }

            std::size_t offset = 0;
            const auto list_len = read_u16(ext_data, offset);
            offset += 2;

            while (offset + 3 <= ext_data.size())
            {
                const auto name_type = ext_data[offset];
                ++offset;

                if (name_type != protocol::tls::SNAME_TYPE_HOSTNAME)
                {
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
                sni.assign(
                    reinterpret_cast<const char *>(ext_data.data() + offset),
                    name_len);
                return;
            }
        }

        void parse_keyshare(const std::span<const std::uint8_t> ext_data,
                            bool &has_key, std::array<std::uint8_t, 32> &key)
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

                if (named_group == protocol::tls::GROUP_X25519 && key_len == protocol::tls::REALITY_KEY_LEN)
                {
                    std::memcpy(key.data(), ext_data.data() + offset, protocol::tls::REALITY_KEY_LEN);
                    has_key = true;
                    return;
                }

                if (named_group == protocol::tls::GROUP_X25519_MLKEM768 && key_len >= protocol::tls::REALITY_KEY_LEN)
                {
                    std::memcpy(key.data(), ext_data.data() + offset, protocol::tls::REALITY_KEY_LEN);
                    has_key = true;
                    return;
                }

                offset += key_len;
            }
        }

        void parse_versions(const std::span<const std::uint8_t> ext_data,
                            memory::vector<std::uint16_t> &versions)
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
                versions.push_back(read_u16(ext_data, offset));
                offset += 2;
            }
        }

        struct parse_ctx
        {
            memory::string &sni;
            bool &has_key;
            std::array<std::uint8_t, 32> &key;
            memory::vector<std::uint16_t> &versions;
        };

        void parse_exts(const std::span<const std::uint8_t> ext_data, parse_ctx &state)
        {
            if (ext_data.size() < 2)
            {
                return;
            }

            std::size_t offset = 0;
            const auto ext_len = read_u16(ext_data, offset);
            offset += 2;
            const std::size_t ext_end = offset + ext_len;
            while (offset + 4 <= ext_end && offset + 4 <= ext_data.size())
            {
                const auto ext_type = read_u16(ext_data, offset);
                offset += 2;
                const auto cur_len = read_u16(ext_data, offset);
                offset += 2;

                if (offset + cur_len > ext_data.size())
                {
                    break;
                }

                const auto ext_payload = ext_data.subspan(offset, cur_len);

                switch (ext_type)
                {
                case protocol::tls::EXT_SERVER_NAME:
                    parse_sni(ext_payload, state.sni);
                    break;
                case protocol::tls::EXT_KEY_SHARE:
                    parse_keyshare(ext_payload, state.has_key, state.key);
                    break;
                case protocol::tls::EXT_SUPPORTED_VERSIONS:
                    parse_versions(ext_payload, state.versions);
                    break;
                default:
                    break;
                }

                offset += cur_len;
            }
        }

    } // namespace


    auto client_hello::sni() const noexcept -> std::string_view
    {
        return sni_;
    }


    auto client_hello::session_id() const noexcept -> std::span<const std::uint8_t>
    {
        return session_id_;
    }


    auto client_hello::has_x25519() const noexcept -> bool
    {
        return has_x25519_;
    }


    auto client_hello::x25519_key() const noexcept -> const std::array<std::uint8_t, 32> &
    {
        return x25519_key_;
    }


    auto client_hello::versions() const noexcept -> std::span<const std::uint16_t>
    {
        return versions_;
    }


    auto client_hello::random() const noexcept -> const std::array<std::uint8_t, 32> &
    {
        return random_;
    }


    auto client_hello::raw_msg() const noexcept -> std::span<const std::uint8_t>
    {
        return raw_msg_;
    }


    auto client_hello::raw_record() const noexcept -> std::span<const std::byte>
    {
        return raw_record_;
    }


    auto client_hello::from(const record &rec)
        -> std::pair<fault::code, client_hello>
    {
        auto payload = rec.payload();
        auto raw_u8 = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()),
            payload.size());

        // 构造完整的 TLS 记录字节（header + payload）用于 from_bytes
        auto serialized = rec.serialize();
        memory::vector<std::uint8_t> full(serialized.size());
        std::memcpy(full.data(), serialized.data(), serialized.size());

        return from_bytes(full);
    }


    auto client_hello::from_bytes(std::span<const std::uint8_t> raw)
        -> std::pair<fault::code, client_hello>
    {
        client_hello ch;

        if (raw.size() < 44)
        {
            return {fault::code::recorderr, std::move(ch)};
        }

        if (raw[0] != protocol::tls::CT_HANDSHAKE)
        {
            return {fault::code::recorderr, std::move(ch)};
        }

        const auto body_len = read_u16(raw, 3);
        if (protocol::tls::RECORD_HDR_LEN + body_len > raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }

        std::size_t offset = protocol::tls::RECORD_HDR_LEN;

        const auto handshake_type = raw[offset];
        if (handshake_type != protocol::tls::HS_CLIENT_HELLO)
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        ++offset;

        const auto handshake_len = read_u24(raw, offset);
        offset += 3;

        constexpr auto msg_start = protocol::tls::RECORD_HDR_LEN;
        const auto msg_len = 4 + handshake_len;
        if (msg_start + msg_len > raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        ch.raw_msg_.assign(raw.data() + msg_start, raw.data() + msg_start + msg_len);

        offset += 2; // ClientVersion

        if (offset + 32 > raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        std::memcpy(ch.random_.data(), raw.data() + offset, 32);
        offset += 32;

        if (offset >= raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        const auto sid_len = raw[offset];
        ++offset;
        if (offset + sid_len > raw.size() || sid_len > protocol::tls::SESSION_ID_MAX_LEN)
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        ch.session_id_.assign(raw.data() + offset, raw.data() + offset + sid_len);
        offset += sid_len;

        if (offset + 2 > raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        const auto cipher_len = read_u16(raw, offset);
        offset += 2;
        if (offset + cipher_len > raw.size() || cipher_len % 2 != 0)
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        offset += cipher_len;

        if (offset >= raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        const auto comp_len = raw[offset];
        ++offset;
        if (offset + comp_len > raw.size())
        {
            return {fault::code::recorderr, std::move(ch)};
        }
        offset += comp_len;

        if (offset + 2 <= raw.size())
        {
            const auto ext_data = raw.subspan(offset);
            parse_ctx state{ch.sni_, ch.has_x25519_, ch.x25519_key_, ch.versions_};
            parse_exts(ext_data, state);
        }

        ch.raw_record_.resize(raw.size());
        std::memcpy(ch.raw_record_.data(), raw.data(), raw.size());

        return {fault::code::success, std::move(ch)};
    }


    auto client_hello::to_features() const -> protocol::tls::hello_features
    {
        protocol::tls::hello_features feat;
        feat.server_name = sni_;
        feat.session_id = session_id_;
        feat.session_id_len = static_cast<std::uint8_t>(session_id_.size());
        feat.has_x25519 = has_x25519_;
        feat.x25519_key = x25519_key_;
        feat.versions = versions_;
        feat.random = random_;
        feat.raw_msg = raw_msg_;
        feat.raw_record = raw_record_;
        return feat;
    }

} // namespace psm::tls
