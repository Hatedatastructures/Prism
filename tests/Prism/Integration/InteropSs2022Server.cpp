/**
 * @file InteropSs2022Server.cpp
 * @brief SS2022 互操作测试：C++ common 服务端到 Go 真实客户端
 * @details 保留 TCP 监听、握手解析、服务端响应和 chunk echo 数据面。
 * @param argv[1] 监听地址，默认 127.0.0.1:19080。
 */

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace
{
    namespace Ss2022 = Prism::Shadowsocks2022;
    namespace Net = boost::asio;

    struct HostPort final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct ServerOptions final
    {
        std::string ListenAddress{"127.0.0.1:19080"};
        std::array<std::uint8_t, 16> Psk{
            0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
            0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
    };

    struct ServerHandshake final
    {
        std::array<std::uint8_t, 16 + Ss2022::FixedHdrSize> Head{};
        std::vector<std::uint8_t> ClientKey;
        Ss2022::Address Destination;
    };

    auto ParseHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        const auto Colon = Value.find_last_of(':');
        if (Colon == std::string_view::npos || Colon == 0 || Colon + 1 >= Value.size())
        {
            return std::nullopt;
        }
        const auto PortValue = std::stoul(std::string(Value.substr(Colon + 1)));
        if (PortValue > 65535)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Colon)),
                        static_cast<std::uint16_t>(PortValue)};
    }

    auto ParseServerOptions(int Argc, char *Argv[]) -> ServerOptions
    {
        ServerOptions Options;
        if (Argc > 1)
        {
            Options.ListenAddress = Argv[1];
        }
        return Options;
    }

    auto ReadClientHandshake(Net::ip::tcp::socket &Socket,
                             const ServerOptions &Options) -> std::optional<ServerHandshake>
    {
        ServerHandshake Handshake;
        Net::read(Socket, Net::buffer(Handshake.Head),
                  Net::transfer_exactly(Handshake.Head.size()));
        const auto ClientSalt = std::span<const std::uint8_t>(Handshake.Head).first(16);
        const auto ProbeKey = Ss2022::SessionKey(Options.Psk, ClientSalt, 16);
        Ss2022::ChunkCodec ProbeCodec(ProbeKey);
        const auto FixedCiphertext = std::span<const std::uint8_t>(Handshake.Head).subspan(
            16, Ss2022::FixedHdrSize);
        const auto FixedPlain = ProbeCodec.OpenRaw(FixedCiphertext);
        if (FixedPlain.size() != Ss2022::FixedHdrPlain ||
            FixedPlain[0] != Ss2022::HeaderTypeClient)
        {
            std::fprintf(stderr, "FAIL: fixed Header Decrypt\n");
            return std::nullopt;
        }
        const auto VariableLength = static_cast<std::size_t>((FixedPlain[9] << 8) | FixedPlain[10]);
        std::vector<std::uint8_t> VariableEncrypted(VariableLength + Ss2022::AeadTagLen);
        Net::read(Socket, Net::buffer(VariableEncrypted),
                  Net::transfer_exactly(VariableEncrypted.size()));
        const auto VariablePlain = ProbeCodec.OpenRaw(VariableEncrypted);
        if (VariablePlain.empty())
        {
            std::fprintf(stderr, "FAIL: var Header Decrypt\n");
            return std::nullopt;
        }
        std::span<const std::uint8_t> IgnoredPayload;
        if (Ss2022::ParseVarHeader(VariablePlain, Handshake.Destination, IgnoredPayload) !=
            Prism::Error::None)
        {
            std::fprintf(stderr, "FAIL: handshake Parse\n");
            return std::nullopt;
        }
        Handshake.ClientKey = ProbeKey;
        std::printf("Server: handshake Ok -> %s:%u\n",
                    Handshake.Destination.Host.c_str(), Handshake.Destination.Port);
        return Handshake;
    }

    auto RunEchoSession(Net::ip::tcp::socket &Socket,
                        const ServerOptions &Options,
                        const ServerHandshake &Handshake) -> bool
    {
        const auto Now = static_cast<std::uint64_t>(std::time(nullptr));
        std::array<std::uint8_t, 16> ServerSalt{};
        std::random_device RandomDevice;
        for (auto &Byte : ServerSalt)
        {
            Byte = static_cast<std::uint8_t>(RandomDevice() & 0xFF);
        }
        const auto ResponseKey = Ss2022::SessionKey(Options.Psk, ServerSalt, 16);
        Ss2022::ChunkCodec Codec(Handshake.ClientKey, 2);
        Ss2022::ChunkCodec ResponseCodec(ResponseKey);
        Ss2022::ChunkCodec EchoCodec(ResponseKey, 2);
        std::array<std::uint8_t, Ss2022::RespFixedHdrPlain> ResponseFixed{};
        ResponseFixed[0] = Ss2022::HeaderTypeServer;
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            ResponseFixed[1 + Index] = static_cast<std::uint8_t>(
                (Now >> (56 - static_cast<unsigned>(Index) * 8)) & 0xFF);
        }
        std::memcpy(ResponseFixed.data() + 9, Handshake.Head.data(), 16);
        bool Responded{false};
        for (int Index = 0; Index < 16; ++Index)
        {
            std::array<std::uint8_t, Ss2022::LenBlockSize> LengthEncrypted{};
            boost::system::error_code Error;
            const auto Count = Net::read(
                Socket, Net::buffer(LengthEncrypted),
                Net::transfer_exactly(LengthEncrypted.size()), Error);
            if (Error || Count == 0)
            {
                break;
            }
            const auto Length = Codec.OpenLen(LengthEncrypted);
            if (!Length)
            {
                std::fprintf(stderr, "FAIL: Decrypt chunk length\n");
                return false;
            }
            std::vector<std::uint8_t> BodyEncrypted(*Length + Ss2022::AeadTagLen);
            Net::read(Socket, Net::buffer(BodyEncrypted),
                      Net::transfer_exactly(BodyEncrypted.size()));
            const auto Plain = Codec.OpenPayload(BodyEncrypted);
            if (Plain.empty())
            {
                std::fprintf(stderr, "FAIL: Decrypt chunk body\n");
                return false;
            }
            if (!Responded)
            {
                ResponseFixed[25] = static_cast<std::uint8_t>((Plain.size() >> 8) & 0xFF);
                ResponseFixed[26] = static_cast<std::uint8_t>(Plain.size() & 0xFF);
                const auto FixedEncrypted = ResponseCodec.SealRaw(ResponseFixed);
                const auto PayloadEncrypted = ResponseCodec.SealRaw(Plain);
                std::vector<std::uint8_t> Response;
                Response.reserve(ServerSalt.size() + FixedEncrypted.size() + PayloadEncrypted.size());
                Response.insert(Response.end(), ServerSalt.begin(), ServerSalt.end());
                Response.insert(Response.end(), FixedEncrypted.begin(), FixedEncrypted.end());
                Response.insert(Response.end(), PayloadEncrypted.begin(), PayloadEncrypted.end());
                Net::write(Socket, Net::buffer(Response));
                Responded = true;
            }
            else
            {
                const auto Echo = EchoCodec.Seal(Plain);
                Net::write(Socket, Net::buffer(Echo));
            }
        }
        return true;
    }

    auto RunServer(const ServerOptions &Options) -> int
    {
        const auto Listen = ParseHostPort(Options.ListenAddress);
        if (!Listen)
        {
            std::fprintf(stderr, "bad listen Address: %s\n", Options.ListenAddress.c_str());
            return 1;
        }
        Net::io_context Io;
        const auto Endpoint = Net::ip::tcp::endpoint(
            Net::ip::make_address(Listen->Host), Listen->Port);
        Net::ip::tcp::acceptor Acceptor(Io, Endpoint);
        Net::ip::tcp::socket Socket(Io);
        Acceptor.accept(Socket);
        const auto Handshake = ReadClientHandshake(Socket, Options);
        if (!Handshake)
        {
            Socket.close();
            return 1;
        }
        const auto Succeeded = RunEchoSession(Socket, Options, *Handshake);
        Socket.close();
        return Succeeded ? 0 : 1;
    }
}

auto main(const int Argc, char *Argv[]) -> int
{
    const auto Options = ParseServerOptions(Argc, Argv);
    try
    {
        return RunServer(Options);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", Error.what());
        return 1;
    }
}
