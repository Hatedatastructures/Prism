/**
 * @file Tls.hpp
 * @brief TLS ClientHello 记录解析
 * @details 提取 SNI、supported_versions、session_id、key_share 和原始字节。
 *          解析器无状态，不执行 TLS 握手，也不修改底层传输。
 */

#pragma once

#include <algorithm>
#include <array>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace net = boost::asio;

    /// ClientHello 解析结果
    struct ClientHelloFeatures
    {
        std::string ServerName;
        std::vector<std::uint8_t> SessionId;
        std::vector<std::uint16_t> Versions;
        std::uint16_t LegacyVersion{0};
        std::array<std::uint8_t, 32> Random{};
        std::array<std::uint8_t, 32> X25519Key{};
        std::vector<std::uint8_t> RawMessage;
        std::vector<std::uint8_t> RawRecord;
        bool HasX25519{false};
        bool HasAlpn{false};
        bool HasPsk{false};
        bool HasEch{false};
    };

    /**
     * @brief 读取完整 TLS Handshake record
     * @param Transport 入站传输
     * @param Preread 已从 Transport 消费的前缀
     * @return 错误码与完整 record（含 5 字节 record header）
     */
    [[nodiscard]] inline auto ReadTlsRecord(Preview::Transmission &Transport,
                                             std::span<const std::byte> Preread = {})
        -> net::awaitable<std::pair<Error, std::vector<std::uint8_t>>>
    {
        constexpr std::size_t RecordHeaderSize = 5;
        constexpr std::size_t MaxRecordPayload = 16384;

        if (Preread.size() > RecordHeaderSize + MaxRecordPayload)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }

        std::vector<std::uint8_t> Record;
        Record.reserve(RecordHeaderSize + MaxRecordPayload);
        if (!Preread.empty())
        {
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Preread.data());
            Record.insert(Record.end(), Bytes, Bytes + Preread.size());
        }

        while (Record.size() < RecordHeaderSize)
        {
            std::array<std::byte, RecordHeaderSize> Chunk{};
            std::error_code Ec;
            const auto Need = RecordHeaderSize - Record.size();
            const auto Read = co_await Transport.async_read_some(std::span<std::byte>(Chunk).first(Need), Ec);
            if (Ec)
            {
                co_return std::pair{Error::IoError, std::vector<std::uint8_t>{}};
            }
            if (Read == 0 || Read > Need)
            {
                co_return std::pair{Error::UnexpectedEof, std::vector<std::uint8_t>{}};
            }
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Chunk.data());
            Record.insert(Record.end(), Bytes, Bytes + Read);
        }

        if (Record[0] != 0x16)
        {
            co_return std::pair{Error::BadMessage, std::vector<std::uint8_t>{}};
        }
        const auto PayloadLength = static_cast<std::size_t>(Record[3]) << 8 | Record[4];
        if (PayloadLength > MaxRecordPayload)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }
        const auto Total = RecordHeaderSize + PayloadLength;
        if (Record.size() > Total)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }
        const auto AlreadyRead = Record.size();
        Record.resize(Total);
        auto Offset = AlreadyRead;
        while (Offset < Total)
        {
            std::error_code Ec;
            const auto Read = co_await Transport.async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Record.data() + Offset), Total - Offset),
                Ec);
            if (Ec)
            {
                co_return std::pair{Error::IoError, std::vector<std::uint8_t>{}};
            }
            if (Read == 0 || Read > Total - Offset)
            {
                co_return std::pair{Error::UnexpectedEof, std::vector<std::uint8_t>{}};
            }
            Offset += Read;
        }
        co_return std::pair{Error::None, std::move(Record)};
    }

    namespace detail
    {

        [[nodiscard]] inline auto ReadU16(std::span<const std::uint8_t> Data, std::size_t Offset,
                                          std::uint16_t &Value) noexcept -> bool
        {
            if (Offset > Data.size() || Data.size() - Offset < 2)
            {
                return false;
            }
            Value = static_cast<std::uint16_t>(Data[Offset]) << 8 |
                    static_cast<std::uint16_t>(Data[Offset + 1]);
            return true;
        }

        [[nodiscard]] inline auto ReadU24(std::span<const std::uint8_t> Data, std::size_t Offset,
                                          std::size_t &Value) noexcept -> bool
        {
            if (Offset > Data.size() || Data.size() - Offset < 3)
            {
                return false;
            }
            Value = static_cast<std::size_t>(Data[Offset]) << 16 |
                    static_cast<std::size_t>(Data[Offset + 1]) << 8 |
                    static_cast<std::size_t>(Data[Offset + 2]);
            return true;
        }

        [[nodiscard]] inline auto ParseServerName(std::span<const std::uint8_t> Data,
                                                   std::string &ServerName) -> bool
        {
            std::uint16_t ListLength = 0;
            if (!ReadU16(Data, 0, ListLength) || ListLength > Data.size() - 2)
            {
                return false;
            }
            std::size_t Offset = 2;
            const auto End = Offset + ListLength;
            while (Offset < End)
            {
                if (End - Offset < 3)
                {
                    return false;
                }
                const auto NameType = Data[Offset++];
                std::uint16_t NameLength = 0;
                if (!ReadU16(Data, Offset, NameLength))
                {
                    return false;
                }
                Offset += 2;
                if (NameLength > End - Offset)
                {
                    return false;
                }
                if (NameType == 0)
                {
                    ServerName.assign(reinterpret_cast<const char *>(Data.data() + Offset), NameLength);
                    return true;
                }
                Offset += NameLength;
            }
            return true;
        }

        [[nodiscard]] inline auto ParseVersions(std::span<const std::uint8_t> Data,
                                                 std::vector<std::uint16_t> &Versions) -> bool
        {
            if (Data.empty())
            {
                return false;
            }
            const auto ListLength = static_cast<std::size_t>(Data.front());
            if (ListLength != Data.size() - 1 || (ListLength % 2) != 0)
            {
                return false;
            }
            for (std::size_t Offset = 1; Offset < Data.size(); Offset += 2)
            {
                std::uint16_t Version = 0;
                if (!ReadU16(Data, Offset, Version))
                {
                    return false;
                }
                Versions.push_back(Version);
            }
            return true;
        }

        [[nodiscard]] inline auto ParseKeyShare(std::span<const std::uint8_t> Data,
                                                ClientHelloFeatures &Features) -> bool
        {
            std::uint16_t ListLength = 0;
            if (!ReadU16(Data, 0, ListLength) || ListLength > Data.size() - 2)
            {
                return false;
            }
            std::size_t Offset = 2;
            const auto End = Offset + ListLength;
            while (Offset < End)
            {
                if (End - Offset < 4)
                {
                    return false;
                }
                std::uint16_t Group = 0;
                std::uint16_t KeyLength = 0;
                if (!ReadU16(Data, Offset, Group) || !ReadU16(Data, Offset + 2, KeyLength))
                {
                    return false;
                }
                Offset += 4;
                if (KeyLength > End - Offset)
                {
                    return false;
                }
                if (Group == 0x001D && KeyLength == Features.X25519Key.size())
                {
                    std::copy_n(Data.data() + Offset, Features.X25519Key.size(), Features.X25519Key.data());
                    Features.HasX25519 = true;
                }
                Offset += KeyLength;
            }
            return true;
        }

    } // namespace detail

    /**
     * @brief 解析完整 TLS ClientHello record
     * @param Record TLS record（含 5 字节 record header）
     * @return 错误码与解析结果
     */
    [[nodiscard]] inline auto ParseClientHello(std::span<const std::uint8_t> Record)
        -> std::pair<Error, ClientHelloFeatures>
    {
        ClientHelloFeatures Features;
        if (Record.size() < 5 || Record[0] != 0x16)
        {
            return {Error::BadMessage, std::move(Features)};
        }

        std::uint16_t RecordLength = 0;
        if (!detail::ReadU16(Record, 3, RecordLength) || RecordLength > Record.size() - 5)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        const auto RecordEnd = static_cast<std::size_t>(5) + RecordLength;
        if (RecordEnd < 9 || Record[5] != 0x01)
        {
            return {Error::BadMessage, std::move(Features)};
        }

        std::size_t HandshakeLength = 0;
        if (!detail::ReadU24(Record, 6, HandshakeLength) || HandshakeLength > RecordEnd - 9)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        const auto MessageEnd = static_cast<std::size_t>(9) + HandshakeLength;
        if (MessageEnd > RecordEnd || HandshakeLength < 34)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Features.RawMessage.assign(Record.begin() + 5, Record.begin() + MessageEnd);
        Features.RawRecord.assign(Record.begin(), Record.begin() + RecordEnd);

        std::size_t Offset = 9;
        if (!detail::ReadU16(Record, Offset, Features.LegacyVersion))
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Offset += 2; // ClientVersion
        std::copy_n(Record.data() + Offset, Features.Random.size(), Features.Random.data());
        Offset += Features.Random.size();

        if (Offset >= MessageEnd)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        const auto SessionLength = static_cast<std::size_t>(Record[Offset++]);
        if (SessionLength > MessageEnd - Offset)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Features.SessionId.assign(Record.begin() + Offset, Record.begin() + Offset + SessionLength);
        Offset += SessionLength;

        std::uint16_t CipherLength = 0;
        if (!detail::ReadU16(Record, Offset, CipherLength))
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Offset += 2;
        if ((CipherLength % 2) != 0 || CipherLength > MessageEnd - Offset)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Offset += CipherLength;

        if (Offset >= MessageEnd)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        const auto CompressionLength = static_cast<std::size_t>(Record[Offset++]);
        if (CompressionLength > MessageEnd - Offset)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Offset += CompressionLength;
        if (Offset == MessageEnd)
        {
            return {Error::None, std::move(Features)};
        }

        std::uint16_t ExtensionsLength = 0;
        if (!detail::ReadU16(Record, Offset, ExtensionsLength))
        {
            return {Error::BadMessage, std::move(Features)};
        }
        Offset += 2;
        if (ExtensionsLength != MessageEnd - Offset)
        {
            return {Error::BadMessage, std::move(Features)};
        }
        const auto ExtensionsEnd = Offset + ExtensionsLength;
        while (Offset < ExtensionsEnd)
        {
            std::uint16_t Type = 0;
            std::uint16_t Length = 0;
            if (ExtensionsEnd - Offset < 4 || !detail::ReadU16(Record, Offset, Type) ||
                !detail::ReadU16(Record, Offset + 2, Length))
            {
                return {Error::BadMessage, std::move(Features)};
            }
            Offset += 4;
            if (Length > ExtensionsEnd - Offset)
            {
                return {Error::BadMessage, std::move(Features)};
            }
            const auto Payload = Record.subspan(Offset, Length);
            switch (Type)
            {
            case 0x0000:
                if (!detail::ParseServerName(Payload, Features.ServerName))
                {
                    return {Error::BadMessage, std::move(Features)};
                }
                break;
            case 0x002B:
                if (!detail::ParseVersions(Payload, Features.Versions))
                {
                    return {Error::BadMessage, std::move(Features)};
                }
                break;
            case 0x0033:
                if (!detail::ParseKeyShare(Payload, Features))
                {
                    return {Error::BadMessage, std::move(Features)};
                }
                break;
            case 0x0010: Features.HasAlpn = true; break;
            case 0x0029: Features.HasPsk = true; break;
            case 0xFE0D: Features.HasEch = true; break;
            default: break;
            }
            Offset += Length;
        }
        return {Error::None, std::move(Features)};
    }

} // namespace Preview::Recognition
