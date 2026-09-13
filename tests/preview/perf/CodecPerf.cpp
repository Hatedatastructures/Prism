/**
 * @file CodecPerf.cpp
 * @brief 协议编解码性能基准（纯热路径，无服务器）
 * @details 测量 7 个代理协议的核心编解码/加密路径，并在编码结果为空
 *          时失败，避免无效输入把基准误报为通过。
 */

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>

namespace
{
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    template <typename Operation>
    [[nodiscard]] auto Bench(
        const char *Name,
        const int Iterations,
        Operation &&OperationValue) -> bool
    {
        std::size_t Sink = 0;
        const auto Start = NowNs();
        for (int Iteration = 0; Iteration < Iterations; ++Iteration)
        {
            Sink += OperationValue();
        }
        const auto End = NowNs();
        std::printf(
            "%-28s %8d iters %10.2f ns/op (sink=%zu)\n",
            Name,
            Iterations,
            static_cast<double>(End - Start) /
                static_cast<double>(Iterations),
            Sink);
        if (Sink == 0)
        {
            std::printf("FAIL %s: 编码结果为空\n", Name);
            return false;
        }
        return true;
    }

    auto MakeDomainAddress(Preview::Socks5::Address &AddressValue) -> void
    {
        AddressValue.Type = Preview::Socks5::AddressType::Domain;
        AddressValue.Host = "example.com";
        AddressValue.Port = 443;
    }
} // namespace

auto main() -> int
{
    bool AllPassed = true;

    {
        using Address = Preview::Socks5::Address;
        using Command = Preview::Socks5::Command;
        using Request = Preview::Socks5::Request;
        using Preview::Socks5::BuildRequest;
        using Preview::Socks5::EncodeAddress;

        Address AddressValue;
        MakeDomainAddress(AddressValue);
        Request RequestValue;
        RequestValue.Ver = Preview::Socks5::Version;
        RequestValue.Cmd = Command::Connect;
        RequestValue.Rsv = 0;
        RequestValue.Target = AddressValue;
        std::vector<std::uint8_t> Buffer;

        auto EncodeAddressOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            EncodeAddress(AddressValue, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("socks5 EncodeAddress", 200000, EncodeAddressOperation) &&
            AllPassed;

        auto BuildRequestOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            BuildRequest(RequestValue, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("socks5 BuildRequest", 200000, BuildRequestOperation) &&
            AllPassed;
    }

    {
        using Address = Preview::Trojan::Address;
        using AddressType = Preview::Trojan::AddressType;
        using Command = Preview::Trojan::Command;
        using RequestParameters = Preview::Trojan::RequestParameters;
        using Preview::Trojan::BuildRequest;

        Address AddressValue;
        AddressValue.Type = AddressType::Domain;
        AddressValue.Host = "example.com";
        AddressValue.Port = 443;
        const std::string Password(56, 'p');
        const RequestParameters Parameters{
            Password,
            Command::Connect,
            AddressValue};
        std::vector<std::uint8_t> Buffer;
        auto BuildRequestOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            BuildRequest(Parameters, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("trojan BuildRequest", 200000, BuildRequestOperation) &&
            AllPassed;
    }

    {
        using AddressType = Preview::Vless::AddressType;
        using Command = Preview::Vless::Command;
        using RequestHeader = Preview::Vless::RequestHeader;
        using Preview::Vless::BuildRequest;

        RequestHeader Header;
        Header.Version = Preview::Vless::ProtocolVersion;
        Header.Uuid.fill(0xAB);
        Header.Cmd = Command::Tcp;
        Header.Target.Type = AddressType::Domain;
        Header.Target.Host = "example.com";
        Header.Target.Port = 443;
        std::vector<std::uint8_t> Buffer;
        auto BuildRequestOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            BuildRequest(Header, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("vless BuildRequest", 200000, BuildRequestOperation) &&
            AllPassed;
    }

    {
        using ChunkEncryptor = Preview::Vmess::ChunkEncryptor;

        const auto Key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        ChunkEncryptor Encryptor(Key, Nonce);
        std::vector<std::uint8_t> Plain(16384);
        for (std::size_t Index = 0; Index < Plain.size(); ++Index)
        {
            Plain[Index] = static_cast<std::uint8_t>(Index);
        }
        std::vector<std::uint8_t> Wire(
            Plain.size() + ChunkEncryptor::Overhead);
        auto SealOperation = [&]() -> std::size_t
        {
            return Encryptor.Seal(Plain, Wire);
        };
        AllPassed =
            Bench("vmess chunk Seal 16KB", 10000, SealOperation) &&
            AllPassed;
    }

    {
        using ChunkCodec = Preview::Shadowsocks2022::ChunkCodec;

        const auto Key = std::array<std::uint8_t, 16>{};
        ChunkCodec Codec(Key);
        std::vector<std::uint8_t> Plain(16384);
        for (std::size_t Index = 0; Index < Plain.size(); ++Index)
        {
            Plain[Index] = static_cast<std::uint8_t>(Index);
        }
        auto SealOperation = [&]() -> std::size_t
        {
            const auto Wire = Codec.Seal(Plain);
            return Wire.size();
        };
        AllPassed =
            Bench("ss2022 chunk Seal 16KB", 10000, SealOperation) &&
            AllPassed;
    }

    {
        using Address = Preview::Hysteria2::Address;
        using AddressType = Preview::Hysteria2::AddressType;
        using UdpFrameInput = Preview::Hysteria2::UdpFrameInput;
        using Preview::Hysteria2::BuildUdp;

        Address AddressValue;
        AddressValue.Type = AddressType::Domain;
        AddressValue.Host = "example.com";
        AddressValue.Port = 443;
        std::vector<std::uint8_t> Payload(128, 0xAB);
        UdpFrameInput Input;
        Input.SessionId = 1;
        Input.PacketId = 2;
        Input.dst = &AddressValue;
        Input.payload = Payload;
        std::vector<std::uint8_t> Buffer;
        auto BuildUdpOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            BuildUdp(Input, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("hysteria2 BuildUdp", 100000, BuildUdpOperation) &&
            AllPassed;
    }

    {
        using AddressType = Preview::Tuic::AddressType;
        using Message = Preview::Tuic::Message;
        using Preview::Tuic::Build;

        Message MessageValue;
        MessageValue.Cmd = Preview::Tuic::CmdPacket;
        MessageValue.AssocId = 1;
        MessageValue.PktId = 2;
        MessageValue.dst.Type = AddressType::Domain;
        MessageValue.dst.Host = "example.com";
        MessageValue.dst.Port = 443;
        MessageValue.payload.assign(128, static_cast<char>(0xCD));
        std::vector<std::uint8_t> Buffer;
        auto BuildPacketOperation = [&]() -> std::size_t
        {
            Buffer.clear();
            Build(MessageValue, Buffer);
            return Buffer.size();
        };
        AllPassed =
            Bench("tuic Build packet", 100000, BuildPacketOperation) &&
            AllPassed;
    }

    if (!AllPassed)
    {
        return 1;
    }
    return 0;
}
