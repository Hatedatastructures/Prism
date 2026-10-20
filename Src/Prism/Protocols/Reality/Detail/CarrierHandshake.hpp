/**
 * @file CarrierHandshake.hpp
 * @brief Reality carrier 的 ClientHello/ServerHello wire helper。
 * @details 负责解析 Reality 认证所需的 ClientHello 字段，并生成带
 *          X25519 key share 的 TLS 1.3 ServerHello。
 */
#pragma once

#include <Prism/Protocols/Reality/Detail/CarrierRecord.hpp>
#include <Prism/Protocols/Reality/CarrierTypes.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace Prism::Reality::Detail
{

    inline auto AppendU16(Bytes &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value));
    }

    inline auto AppendU24(Bytes &Output, const std::size_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 16));
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value));
    }

    inline auto AddExtension(Bytes &Extensions, const std::uint16_t Type,
                             const Bytes &Payload) -> void
    {
        AppendU16(Extensions, Type);
        AppendU16(Extensions, Payload.size());
        Extensions.insert(Extensions.end(), Payload.begin(), Payload.end());
    }

    [[nodiscard]] inline auto ReadU16(const std::span<const std::uint8_t> Data,
                                      const std::size_t Offset) -> std::uint16_t
    {
        return static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
    }

    struct ClientHelloView final
    {
        Bytes Message;
        std::array<std::uint8_t, 32> Random{};
        std::array<std::uint8_t, SessionIdAuthLen> SessionId{};
        std::array<std::uint8_t, KeyLen> PublicKey{};
        std::string ServerName;
    };

    [[nodiscard]] inline auto ReadClientHelloBody(
        const Bytes &Record, ClientHelloView &Result, std::span<const std::uint8_t> &Body) -> bool
    {
        if (Record.size() < 5 + 4 || Record[0] != 0x16)
        {
            return false;
        }
        const auto RecordLength = static_cast<std::size_t>(Record[3]) << 8 | Record[4];
        if (RecordLength != Record.size() - 5 || RecordLength < 4 || Record[5] != 0x01)
        {
            return false;
        }
        const auto MessageLength = static_cast<std::size_t>(Record[6]) << 16 |
                                   static_cast<std::size_t>(Record[7]) << 8 | Record[8];
        if (MessageLength + 4 != RecordLength)
        {
            return false;
        }
        Result.Message.assign(Record.begin() + 5, Record.end());
        Body = std::span<const std::uint8_t>(Record.data() + 9, MessageLength);
        return Body.size() >= 2 + 32 + 1 + SessionIdAuthLen + 2 + 1 + 1 + 2;
    }

    [[nodiscard]] inline auto ParseClientHelloPrefix(
        const std::span<const std::uint8_t> Body,
        ClientHelloView &Result,
        std::span<const std::uint8_t> &Extensions) -> bool
    {
        std::size_t Offset = 2;
        std::copy_n(Body.data() + Offset, Result.Random.size(), Result.Random.data());
        Offset += Result.Random.size();
        const auto SessionLength = Body[Offset++];
        if (SessionLength != Result.SessionId.size() || Body.size() - Offset < SessionLength)
        {
            return false;
        }
        std::copy_n(Body.data() + Offset, Result.SessionId.size(), Result.SessionId.data());
        Offset += SessionLength;
        if (Body.size() - Offset < 2)
        {
            return false;
        }
        const auto CipherSuitesLength = ReadU16(Body, Offset);
        Offset += 2;
        if (CipherSuitesLength > Body.size() - Offset)
        {
            return false;
        }
        Offset += CipherSuitesLength;
        if (Body.size() - Offset < 1)
        {
            return false;
        }
        const auto CompressionLength = Body[Offset++];
        if (CompressionLength > Body.size() - Offset)
        {
            return false;
        }
        Offset += CompressionLength;
        if (Body.size() - Offset < 2)
        {
            return false;
        }
        const auto ExtensionsLength = ReadU16(Body, Offset);
        Offset += 2;
        if (ExtensionsLength != Body.size() - Offset)
        {
            return false;
        }
        Extensions = Body.subspan(Offset, ExtensionsLength);
        return true;
    }

    [[nodiscard]] inline auto ParseServerNameExtension(
        const std::span<const std::uint8_t> Payload, ClientHelloView &Result) -> bool
    {
        if (Payload.size() < 2)
        {
            return true;
        }
        const auto NamesLength = ReadU16(Payload, 0);
        if (NamesLength != Payload.size() - 2)
        {
            return false;
        }
        std::size_t Offset = 2;
        while (Offset < Payload.size())
        {
            if (Payload.size() - Offset < 3)
            {
                return false;
            }
            const auto NameType = Payload[Offset++];
            const auto NameLength = ReadU16(Payload, Offset);
            Offset += 2;
            if (NameLength > Payload.size() - Offset)
            {
                return false;
            }
            if (NameType == 0)
            {
                Result.ServerName.assign(
                    reinterpret_cast<const char *>(Payload.data() + Offset), NameLength);
            }
            Offset += NameLength;
        }
        return true;
    }

    [[nodiscard]] inline auto ParseKeyShareExtension(
        const std::span<const std::uint8_t> Payload,
        ClientHelloView &Result,
        bool &FoundKeyShare) -> bool
    {
        if (Payload.size() < 2)
        {
            return true;
        }
        const auto SharesLength = ReadU16(Payload, 0);
        if (SharesLength != Payload.size() - 2)
        {
            return false;
        }
        std::size_t Offset = 2;
        while (Offset < Payload.size())
        {
            if (Payload.size() - Offset < 4)
            {
                return false;
            }
            const auto Group = ReadU16(Payload, Offset);
            const auto ShareLength = ReadU16(Payload, Offset + 2);
            Offset += 4;
            if (ShareLength > Payload.size() - Offset)
            {
                return false;
            }
            if (Group == 0x001d && ShareLength == KeyLen)
            {
                std::copy_n(Payload.data() + Offset, KeyLen, Result.PublicKey.data());
                FoundKeyShare = true;
            }
            Offset += ShareLength;
        }
        return true;
    }

    [[nodiscard]] inline auto ParseClientHelloExtensions(
        const std::span<const std::uint8_t> Extensions, ClientHelloView &Result) -> bool
    {
        bool FoundKeyShare = false;
        std::size_t Offset = 0;
        while (Offset < Extensions.size())
        {
            if (Extensions.size() - Offset < 4)
            {
                return false;
            }
            const auto Type = ReadU16(Extensions, Offset);
            const auto Length = ReadU16(Extensions, Offset + 2);
            Offset += 4;
            if (Length > Extensions.size() - Offset)
            {
                return false;
            }
            const auto Payload = Extensions.subspan(Offset, Length);
            if (Type == 0x0000 && !ParseServerNameExtension(Payload, Result))
            {
                return false;
            }
            if (Type == 0x0033 && !ParseKeyShareExtension(Payload, Result, FoundKeyShare))
            {
                return false;
            }
            Offset += Length;
        }
        return FoundKeyShare;
    }

    /**
     * @brief 解析 Reality 服务端需要的 ClientHello 字段。
     * @param Record 包含五字节 TLS record 头的 ClientHello
     * @return 解析成功的视图；格式错误或缺少 X25519 key share 时为空
     */
    [[nodiscard]] inline auto ParseClientHello(const Bytes &Record)
        -> std::optional<ClientHelloView>
    {
        ClientHelloView Result;
        std::span<const std::uint8_t> Body;
        if (!ReadClientHelloBody(Record, Result, Body))
        {
            return std::nullopt;
        }
        std::span<const std::uint8_t> Extensions;
        if (!ParseClientHelloPrefix(Body, Result, Extensions) ||
            !ParseClientHelloExtensions(Extensions, Result))
        {
            return std::nullopt;
        }
        return std::optional{std::move(Result)};
    }

    /**
     * @brief 生成包含 TLS 1.3 X25519 key share 的 ServerHello。
     * @param Client 已解析的 ClientHello
     * @param PublicKey 服务端临时 X25519 公钥
     * @return ServerHello handshake message 和 TLS record
     */
    [[nodiscard]] inline auto BuildServerHello(
        const ClientHelloView &Client,
        const std::array<std::uint8_t, KeyLen> &PublicKey) -> std::pair<Bytes, Bytes>
    {
        std::array<std::uint8_t, 32> Random{};
        RAND_bytes(Random.data(), static_cast<int>(Random.size()));
        Bytes Extensions;
        AddExtension(Extensions, 0x002b, Bytes{0x03, 0x04});
        Bytes KeyShare;
        AppendU16(KeyShare, 0x001d);
        AppendU16(KeyShare, KeyLen);
        KeyShare.insert(KeyShare.end(), PublicKey.begin(), PublicKey.end());
        AddExtension(Extensions, 0x0033, KeyShare);

        Bytes Body{0x03, 0x03};
        Body.insert(Body.end(), Random.begin(), Random.end());
        Body.push_back(static_cast<std::uint8_t>(Client.SessionId.size()));
        Body.insert(Body.end(), Client.SessionId.begin(), Client.SessionId.end());
        AppendU16(Body, 0x1301);
        Body.push_back(0x00);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        Bytes Message{0x02};
        AppendU24(Message, Body.size());
        Message.insert(Message.end(), Body.begin(), Body.end());
        Bytes Record{0x16, 0x03, 0x03};
        AppendU16(Record, Message.size());
        Record.insert(Record.end(), Message.begin(), Message.end());
        return {std::move(Message), std::move(Record)};
    }

} // namespace Prism::Reality::Detail
