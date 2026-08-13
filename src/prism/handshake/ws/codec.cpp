/**
 * @file codec.cpp
 * @brief WebSocket 帧编解码实现
 */

#include <prism/handshake/ws/codec.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstring>

namespace psm::handshake::ws::codec
{

    auto compute_accept(const std::string_view key, const std::span<char, 28> out) -> bool
    {
        // SHA1(key + GUID) → base64
        std::string combined(key);
        combined.append(ws_guid);

        std::array<std::uint8_t, 20> digest{};
        SHA1(reinterpret_cast<const std::uint8_t *>(combined.data()), combined.size(), digest.data());

        const auto encoded_len = ((digest.size() + 2) / 3) * 4;
        if (encoded_len != out.size())
        {
            return false;
        }
        EVP_EncodeBlock(reinterpret_cast<std::uint8_t *>(out.data()), digest.data(),
                        static_cast<int>(digest.size()));
        return true;
    }

    auto parse_frame_header(const std::span<const std::byte> in, frame_header &header) -> bool
    {
        if (in.size() < 2)
        {
            return false;
        }

        const auto b0 = static_cast<std::uint8_t>(in[0]);
        const auto b1 = static_cast<std::uint8_t>(in[1]);

        header.fin = (b0 & 0x80) != 0;
        header.opcode = static_cast<std::uint8_t>(b0 & 0x0F);
        header.masked = (b1 & 0x80) != 0;

        std::size_t offset = 2;
        std::uint64_t len = static_cast<std::uint64_t>(b1 & 0x7F);
        if (len == 126)
        {
            if (in.size() < offset + 2)
            {
                return false;
            }
            len = (static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset])) << 8) |
                  static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset + 1]));
            offset += 2;
        }
        else if (len == 127)
        {
            if (in.size() < offset + 8)
            {
                return false;
            }
            len = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                len = (len << 8) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset + i]));
            }
            offset += 8;
        }
        header.payload_len = len;

        if (header.masked)
        {
            if (in.size() < offset + 4)
            {
                return false;
            }
            std::memcpy(header.mask.data(), in.data() + offset, 4);
            offset += 4;
        }

        header.header_len = offset;
        return true;
    }

    auto encode_frame(const opcode op, const bool fin, const std::span<const std::byte> payload,
                      const std::span<std::byte> out) -> std::size_t
    {
        const auto len = payload.size();
        std::size_t header_len = 2;
        if (len >= 126 && len <= 0xFFFF)
        {
            header_len += 2;
        }
        else if (len > 0xFFFF)
        {
            header_len += 8;
        }

        if (out.size() < header_len + len)
        {
            return 0;
        }

        const auto b0 = static_cast<std::uint8_t>(static_cast<std::uint8_t>(op)) | (fin ? 0x80 : 0x00);
        out[0] = static_cast<std::byte>(b0);

        std::size_t offset = 2;
        if (len < 126)
        {
            out[1] = static_cast<std::byte>(len);
        }
        else if (len <= 0xFFFF)
        {
            out[1] = std::byte{126};
            out[offset++] = static_cast<std::byte>((len >> 8) & 0xFF);
            out[offset++] = static_cast<std::byte>(len & 0xFF);
        }
        else
        {
            out[1] = std::byte{127};
            for (int i = 7; i >= 0; --i)
            {
                out[offset++] = static_cast<std::byte>((len >> (8 * i)) & 0xFF);
            }
        }

        std::memcpy(out.data() + offset, payload.data(), len);
        return header_len + len;
    }

} // namespace psm::handshake::ws::codec
