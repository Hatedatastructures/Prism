/**
 * @file RecognitionWire.hpp
 * @brief 识别策略的标准协议 wire fixture
 * @details 只调用现有 Preview serializer/builder 生成真实首包，避免
 *          ASCII 伪 VLESS、CRLF 伪 Trojan 和单字节 VMess 正例。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Protocols/Http1/Parser.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>

namespace Preview::Testing::RecognitionWire
{

    inline auto Bytes(const std::vector<std::uint8_t> &Input) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(Input.size());
        for (const auto Byte : Input)
        {
            Output.push_back(static_cast<std::byte>(Byte));
        }
        return Output;
    }

    inline auto Bytes(std::string_view Input) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(Input.size());
        for (const auto Byte : Input)
        {
            Output.push_back(static_cast<std::byte>(static_cast<unsigned char>(Byte)));
        }
        return Output;
    }

    inline auto AppendU16(std::vector<std::uint8_t> &Output, std::size_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    inline auto AppendU24(std::vector<std::uint8_t> &Output, std::size_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFFU));
        Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    inline auto MakeTlsClientHello(std::string_view ServerName) -> std::vector<std::byte>
    {
        std::vector<std::uint8_t> Names{0};
        AppendU16(Names, ServerName.size());
        Names.insert(Names.end(), ServerName.begin(), ServerName.end());

        std::vector<std::uint8_t> Sni;
        AppendU16(Sni, Names.size());
        Sni.insert(Sni.end(), Names.begin(), Names.end());

        std::vector<std::uint8_t> Extensions{0x00, 0x00};
        AppendU16(Extensions, Sni.size());
        Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());

        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), 32, 0x42);
        Body.push_back(0);
        AppendU16(Body, 2);
        Body.insert(Body.end(), {0x13, 0x01});
        Body.push_back(1);
        Body.push_back(0);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        std::vector<std::uint8_t> Handshake{0x01};
        AppendU24(Handshake, Body.size());
        Handshake.insert(Handshake.end(), Body.begin(), Body.end());

        std::vector<std::uint8_t> Record{0x16, 0x03, 0x03};
        AppendU16(Record, Handshake.size());
        Record.insert(Record.end(), Handshake.begin(), Handshake.end());
        return Bytes(Record);
    }

    inline auto MakeHttp(std::string_view Payload = "") -> std::vector<std::byte>
    {
        auto Request = Preview::Http11::MakeConnectRequest("example.com", 443);
        Request.append(Payload);
        return Bytes(Request);
    }

    inline auto MakeSocksGreeting(bool UserPass = false) -> std::vector<std::byte>
    {
        Preview::Socks5::Greeting Greeting;
        if (UserPass)
        {
            Greeting.Methods = {Preview::Socks5::AuthUserPass};
        }
        else
        {
            Greeting.Methods = {Preview::Socks5::AuthNone};
        }
        return Bytes(Preview::Socks5::BuildGreeting(Greeting));
    }

    inline auto MakeVless(const std::array<std::uint8_t, 16> &Uuid,
                          std::uint8_t Command = Preview::Vless::CmdTcp)
        -> std::vector<std::byte>
    {
        Preview::Vless::Message Message;
        Message.uuid = Uuid;
        Message.cmd = Command;
        Message.dst.Type = Preview::Vless::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;
        Preview::Vless::Serializer Serializer(Uuid);
        Serializer.Reset(Message);
        std::array<std::uint8_t, 512> Wire{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), Error);
        return Bytes(std::vector<std::uint8_t>(Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(Size)));
    }

    inline auto MakeTrojan(std::string_view Password) -> std::vector<std::byte>
    {
        Preview::Trojan::Message Message;
        Message.dst.Type = Preview::Trojan::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;
        Preview::Trojan::Serializer Serializer(Password);
        Serializer.Reset(Message);
        std::array<std::uint8_t, 512> Wire{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), Error);
        return Bytes(std::vector<std::uint8_t>(Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(Size)));
    }

    inline auto MakeVmess(const std::array<std::uint8_t, 16> &Uuid) -> std::vector<std::byte>
    {
        Preview::Vmess::Message Message;
        Message.Cmd = Preview::Vmess::CmdTcp;
        Message.dst.Type = Preview::Vmess::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;
        for (std::size_t Index = 0; Index < Message.RequestNonce.size(); ++Index)
        {
            Message.RequestNonce[Index] = static_cast<std::uint8_t>(Index + 1);
            Message.RequestKey[Index] = static_cast<std::uint8_t>(0xA0 + Index);
        }
        Message.RespHeader = 0x42;
        Preview::Vmess::Serializer Serializer(Uuid);
        Serializer.Reset(Message, static_cast<std::uint64_t>(
                                   std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count()));
        std::array<std::uint8_t, 1024> Wire{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), Error);
        return Bytes(std::vector<std::uint8_t>(Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(Size)));
    }

    inline auto MakeSs2022At(const std::array<std::uint8_t, 16> &Psk,
                             std::uint64_t TimeSec) -> std::vector<std::byte>
    {
        Preview::Shadowsocks2022::Message Message;
        Message.dst.Type = Preview::Shadowsocks2022::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;
        Preview::Shadowsocks2022::Serializer Serializer(Psk);
        Serializer.Reset(Message, TimeSec);
        std::array<std::uint8_t, 2048> Wire{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), Error);
        return Bytes(std::vector<std::uint8_t>(Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(Size)));
    }

    inline auto MakeSs2022(const std::array<std::uint8_t, 16> &Psk) -> std::vector<std::byte>
    {
        return MakeSs2022At(
            Psk, static_cast<std::uint64_t>(
                     std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count()));
    }

    inline auto MakeUuid(std::uint8_t Seed) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(Seed + Index);
        }
        return Uuid;
    }

    inline auto MakePsk(std::uint8_t Seed) -> std::array<std::uint8_t, 16>
    {
        return MakeUuid(Seed);
    }

} // namespace Preview::Testing::RecognitionWire
