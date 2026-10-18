/**
 * @file InteropSs2022Client.cpp
 * @brief SS2022 互操作测试：C++ common 客户端到 Go 真实服务端
 * @details 保留 TCP 连接、握手首包、加密 chunk、服务端响应和回显校验。
 * @param argv[1] 服务端地址，默认 127.0.0.1:19080。
 * @param argv[2] echo 目标地址，默认 127.0.0.1:19090。
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

#include <Prism/Protocols/Shadowsocks2022/Codec.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>

namespace
{
    namespace Ss2022 = Prism::Shadowsocks2022;
    namespace Net = boost::asio;

    struct HostPort final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct ClientOptions final
    {
        std::string ServerAddress{"127.0.0.1:19080"};
        std::string EchoAddress{"127.0.0.1:19090"};
        std::array<std::uint8_t, 16> Psk{
            0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
            0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
    };

    struct ClientState final
    {
        std::array<std::uint8_t, 16> Psk;
        std::string PayloadText{"hello interop ss2022"};
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

    auto ParseClientOptions(int Argc, char *Argv[]) -> std::optional<ClientOptions>
    {
        ClientOptions Options;
        if (Argc > 1)
        {
            Options.ServerAddress = Argv[1];
        }
        if (Argc > 2)
        {
            Options.EchoAddress = Argv[2];
        }
        if (Argc <= 3)
        {
            return Options;
        }
        const auto Decoded = Prism::Crypto::Base64Decode(Argv[3]);
        if (Decoded.size() != Options.Psk.size())
        {
            return std::nullopt;
        }
        std::memcpy(Options.Psk.data(), Decoded.data(), Options.Psk.size());
        return Options;
    }

    auto WriteClientHandshake(Net::ip::tcp::socket &Socket,
                              const ClientOptions &Options) -> ClientState
    {
        const auto Echo = ParseHostPort(Options.EchoAddress);
        if (!Echo)
        {
            throw std::invalid_argument("bad SS2022 echo endpoint");
        }
        std::random_device RandomDevice;
        std::array<std::uint8_t, 16> Salt{};
        for (auto &Byte : Salt)
        {
            Byte = static_cast<std::uint8_t>(RandomDevice() & 0xFF);
        }
        const auto Key = Ss2022::SessionKey(Options.Psk, Salt, 16);
        Ss2022::Address Destination;
        Destination.Type = Ss2022::AddressType::Ipv4;
        Destination.Host = "127.0.0.1";
        Destination.Port = Echo->Port;
        const auto Now = static_cast<std::uint64_t>(std::time(nullptr));
        const auto Variable = Ss2022::BuildVarHeader(Destination, 1);
        const auto Fixed = Ss2022::ParseFixedHeader(
            Ss2022::HeaderTypeClient, Now,
            static_cast<std::uint16_t>(Variable.size()));
        Ss2022::ChunkCodec Codec(Key);
        const auto FixedEncrypted = Codec.SealRaw(Fixed);
        const auto VariableEncrypted = Codec.SealRaw(Variable);
        std::vector<std::uint8_t> Wire;
        Wire.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
        Wire.insert(Wire.end(), Salt.begin(), Salt.end());
        Wire.insert(Wire.end(), FixedEncrypted.begin(), FixedEncrypted.end());
        Wire.insert(Wire.end(), VariableEncrypted.begin(), VariableEncrypted.end());
        Net::write(Socket, Net::buffer(Wire));

        ClientState State{Options.Psk};
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(State.PayloadText.data()),
            State.PayloadText.size());
        Ss2022::ChunkCodec DataCodec(Key, 2);
        const auto Encoded = DataCodec.Seal(Payload);
        Net::write(Socket, Net::buffer(Encoded));
        return State;
    }

    auto ReadClientResponse(Net::ip::tcp::socket &Socket,
                            const ClientState &State) -> bool
    {
        std::array<std::uint8_t, 16 + 43> ResponseHead{};
        Net::read(Socket, Net::buffer(ResponseHead), Net::transfer_exactly(ResponseHead.size()));
        const auto ResponseSalt = std::span<const std::uint8_t>(ResponseHead).first(16);
        const auto ResponseKey = Ss2022::SessionKey(State.Psk, ResponseSalt, 16);
        Ss2022::ChunkCodec ResponseCodec(ResponseKey);
        const auto ResponseCiphertext = std::span<const std::uint8_t>(ResponseHead).subspan(16, 43);
        const auto FixedPlain = ResponseCodec.OpenRaw(ResponseCiphertext);
        if (FixedPlain.size() != Ss2022::RespFixedHdrPlain ||
            FixedPlain[0] != Ss2022::HeaderTypeServer)
        {
            std::fprintf(stderr, "FAIL: Server response fixed Header\n");
            return false;
        }
        auto PayloadLength = static_cast<std::size_t>((FixedPlain[25] << 8) | FixedPlain[26]);
        if (PayloadLength == 0)
        {
            std::array<std::uint8_t, 16> EmptyBlock{};
            Net::read(Socket, Net::buffer(EmptyBlock));
            std::vector<std::uint8_t> Empty;
            if (!ResponseCodec.OpenRaw(EmptyBlock, Empty))
            {
                return false;
            }
            std::array<std::uint8_t, 18> LengthBlock{};
            Net::read(Socket, Net::buffer(LengthBlock));
            const auto Length = ResponseCodec.OpenRaw(LengthBlock);
            if (Length.size() != 2)
            {
                return false;
            }
            PayloadLength = static_cast<std::size_t>((Length[0] << 8) | Length[1]);
        }
        std::vector<std::uint8_t> PayloadEncrypted(PayloadLength + 16);
        Net::read(Socket, Net::buffer(PayloadEncrypted),
                  Net::transfer_exactly(PayloadEncrypted.size()));
        const auto Plain = ResponseCodec.OpenRaw(PayloadEncrypted);
        if (Plain.empty())
        {
            std::fprintf(stderr, "FAIL: Decrypt Server response payload\n");
            return false;
        }
        const std::string Echo(reinterpret_cast<const char *>(Plain.data()), Plain.size());
        if (Echo != State.PayloadText)
        {
            std::fprintf(stderr, "FAIL: echo mismatch: got %.*s\n",
                         static_cast<int>(Plain.size()),
                         reinterpret_cast<const char *>(Plain.data()));
            return false;
        }
        std::printf("PASS: interop ss2022 echo bytes=%zu payload=%.*s\n", Plain.size(),
                    static_cast<int>(Plain.size()),
                    reinterpret_cast<const char *>(Plain.data()));
        return true;
    }

    auto RunClient(const ClientOptions &Options) -> int
    {
        const auto Server = ParseHostPort(Options.ServerAddress);
        if (!Server)
        {
            std::fprintf(stderr, "bad Server Address: %s\n", Options.ServerAddress.c_str());
            return 1;
        }
        Net::io_context Io;
        Net::ip::tcp::resolver Resolver(Io);
        auto Endpoints = Resolver.resolve(Server->Host, std::to_string(Server->Port));
        Net::ip::tcp::socket Socket(Io);
        Net::connect(Socket, Endpoints);
        const auto State = WriteClientHandshake(Socket, Options);
        const auto Succeeded = ReadClientResponse(Socket, State);
        Socket.close();
        return Succeeded ? 0 : 1;
    }
}

auto main(const int Argc, char *Argv[]) -> int
{
    const auto Options = ParseClientOptions(Argc, Argv);
    if (!Options)
    {
        return 2;
    }
    try
    {
        return RunClient(*Options);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", Error.what());
        return 1;
    }
}
