/**
 * @file RealityCarrierTestSupport.hpp
 * @brief Reality carrier wire 测试共享的 ClientHello 输入构造器。
 * @details 真实成功握手与错误认证用例共用同一字节构造，避免测试各自重造 wire 输入。
 */
#pragma once

#include <Prism/Protocols/Reality/Detail/Key.hpp>
#include <Prism/Protocols/Reality/Detail/Authentication.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Tests::Protocols::Reality
{
    using Bytes = std::vector<std::uint8_t>;

    struct ClientHelloWire final
    {
        Bytes Message;
        Bytes Record;
        std::array<std::uint8_t, Prism::Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, 32> Random{};
        std::array<std::uint8_t, Prism::Reality::KeyLen> PublicKey{};
        std::array<std::uint8_t, Prism::Reality::SessionIdAuthLen> SessionId{};
    };

    struct ClientHelloKeyMaterial final
    {
        std::array<std::uint8_t, Prism::Reality::KeyLen> ServerPublicKey;
        std::array<std::uint8_t, Prism::Reality::KeyLen> ClientPrivateKey;
        std::array<std::uint8_t, 32> Random;
    };

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

    inline auto AddExtension(Bytes &Extensions, const std::uint16_t Type, const Bytes &Payload) -> void
    {
        AppendU16(Extensions, Type);
        AppendU16(Extensions, static_cast<std::uint16_t>(Payload.size()));
        Extensions.insert(Extensions.end(), Payload.begin(), Payload.end());
    }

    [[nodiscard]] inline auto BuildClientHello(
        ClientHelloKeyMaterial Material,
        const std::array<std::uint8_t, Prism::Reality::MaxShortIdLen> &ShortId,
        const std::string_view ServerName) -> ClientHelloWire
    {
        std::array<std::uint8_t, Prism::Reality::KeyLen> ClientPublicKey{};
        X25519_public_from_private(ClientPublicKey.data(), Material.ClientPrivateKey.data());

        std::array<std::uint8_t, Prism::Reality::KeyLen> Shared{};
        if (Prism::Reality::Detail::X25519Shared(Material.ClientPrivateKey, Material.ServerPublicKey, Shared))
        {
            return {};
        }

        std::array<std::uint8_t, Prism::Reality::KeyLen> AuthKey{};
        if (Prism::Reality::Detail::DeriveAuthKey(Shared, Material.Random, AuthKey))
        {
            return {};
        }

        Bytes Extensions;
        Bytes Name;
        Name.push_back(0);
        AppendU16(Name, static_cast<std::uint16_t>(ServerName.size()));
        Name.insert(Name.end(), ServerName.begin(), ServerName.end());
        Bytes Names;
        AppendU16(Names, static_cast<std::uint16_t>(Name.size()));
        Names.insert(Names.end(), Name.begin(), Name.end());
        AddExtension(Extensions, 0x0000, Names);
        AddExtension(Extensions, 0x002b, Bytes{0x02, 0x03, 0x04});
        AddExtension(Extensions, 0x000a, Bytes{0x00, 0x02, 0x00, 0x1d});

        Bytes KeyShare;
        AppendU16(KeyShare, 0x0024);
        AppendU16(KeyShare, 0x001d);
        AppendU16(KeyShare, Prism::Reality::KeyLen);
        KeyShare.insert(KeyShare.end(), ClientPublicKey.begin(), ClientPublicKey.end());
        AddExtension(Extensions, 0x0033, KeyShare);
        AddExtension(Extensions, 0x000d, Bytes{0x00, 0x02, 0x08, 0x07});

        Bytes Body;
        AppendU16(Body, 0x0303);
        Body.insert(Body.end(), Material.Random.begin(), Material.Random.end());
        Body.push_back(static_cast<std::uint8_t>(Prism::Reality::SessionIdAuthLen));
        Body.insert(Body.end(), Prism::Reality::SessionIdAuthLen, 0);
        AppendU16(Body, 0x0002);
        AppendU16(Body, 0x1301);
        Body.push_back(0x01);
        Body.push_back(0x00);
        AppendU16(Body, static_cast<std::uint16_t>(Extensions.size()));
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        Bytes Message{0x01};
        AppendU24(Message, Body.size());
        Message.insert(Message.end(), Body.begin(), Body.end());

        std::array<std::uint8_t, 16> Plain{};
        Plain[0] = 0x01;
        std::copy(ShortId.begin(), ShortId.end(), Plain.begin() + 8);
        std::array<std::uint8_t, Prism::Reality::SessionIdAuthLen> Sealed{};
        if (Prism::Reality::Detail::SealSessionId(
                Prism::Reality::Detail::SessionIdSealInput{AuthKey, Material.Random, Plain, Message}, Sealed))
        {
            return {};
        }
        std::copy(Sealed.begin(), Sealed.end(), Message.begin() + 39);

        ClientHelloWire Result;
        Result.Message = Message;
        Result.Record = {0x16, 0x03, 0x03,
                         static_cast<std::uint8_t>(Message.size() >> 8),
                         static_cast<std::uint8_t>(Message.size())};
        Result.Record.insert(Result.Record.end(), Message.begin(), Message.end());
        Result.PrivateKey = Material.ClientPrivateKey;
        Result.Random = Material.Random;
        Result.PublicKey = ClientPublicKey;
        Result.SessionId = Sealed;
        return Result;
    }
}
