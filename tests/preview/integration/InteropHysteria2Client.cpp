/**
 * @file InteropHysteria2Client.cpp
 * @brief Preview 原生 HTTP/3 客户端与独立 sing-quic Hysteria2 服务端互操作
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Protocols/Http3/NativeClient.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Protocols/Quic/Native.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Udp = Net::ip::udp;

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct Options
    {
        std::string Address{"127.0.0.1:19089"};
        std::string Password{"hysteria2_password"};
        bool Udp{false};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        std::uint32_t Port = 0;
        if (Value.empty())
        {
            return std::nullopt;
        }
        const auto [End, Error] = std::from_chars(Value.data(), Value.data() + Value.size(), Port);
        if (Error != std::errc{} || End != Value.data() + Value.size() || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Close = Value.find(']');
            if (Close == std::string_view::npos || Close + 1 >= Value.size() || Value[Close + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Close + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Close - 1)), *Port};
        }
        const auto Colon = Value.rfind(':');
        if (Colon == std::string_view::npos || Colon == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Colon + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Colon)), *Port};
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-udp")
            {
                Result.Udp = Value == "1" || Value == "true";
            }
        }
        return Result;
    }

    auto AppendVarint(std::vector<std::byte> &Output, const std::uint64_t Value) -> void
    {
        if (Value <= 63)
        {
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 16383)
        {
            Output.push_back(static_cast<std::byte>((Value >> 8U) | 0x40U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 1073741823)
        {
            Output.push_back(static_cast<std::byte>((Value >> 24U) | 0x80U));
            Output.push_back(static_cast<std::byte>(Value >> 16U));
            Output.push_back(static_cast<std::byte>(Value >> 8U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            const auto Shift = static_cast<unsigned>((7U - Index) * 8U);
            std::uint64_t Prefix = 0;
            if (Index == 0)
            {
                Prefix = 0xC0U;
            }
            Output.push_back(static_cast<std::byte>((Value >> Shift) | Prefix));
        }
    }

    [[nodiscard]] auto ReadVarint(const std::vector<std::byte> &Data, std::size_t &Offset,
                                  std::uint64_t &Value) -> bool
    {
        if (Offset >= Data.size())
        {
            return false;
        }
        const auto First = std::to_integer<std::uint8_t>(Data[Offset]);
        const auto Length = std::size_t{1U} << (First >> 6U);
        if (Offset + Length > Data.size())
        {
            return false;
        }
        Value = First & 0x3FU;
        for (std::size_t Index = 1; Index < Length; ++Index)
        {
            Value = (Value << 8U) | std::to_integer<std::uint8_t>(Data[Offset + Index]);
        }
        Offset += Length;
        return true;
    }

    [[nodiscard]] auto MakeTcpRequest(std::string_view Target, std::span<const std::byte> Payload)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        AppendVarint(Output, 0x401);
        AppendVarint(Output, Target.size());
        for (const auto Character : Target)
        {
            Output.push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
        }
        AppendVarint(Output, 64);
        Output.insert(Output.end(), 64, std::byte{'a'});
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    [[nodiscard]] auto ParseResponse(const std::vector<std::byte> &Data, std::size_t &HeaderSize,
                                     std::uint8_t &Status) -> bool
    {
        if (Data.empty())
        {
            return false;
        }
        Status = std::to_integer<std::uint8_t>(Data[0]);
        std::size_t Offset = 1;
        std::uint64_t MessageLength = 0;
        std::uint64_t PaddingLength = 0;
        if (!ReadVarint(Data, Offset, MessageLength) || MessageLength > 2048 ||
            MessageLength > Data.size() - Offset)
        {
            return false;
        }
        Offset += static_cast<std::size_t>(MessageLength);
        if (!ReadVarint(Data, Offset, PaddingLength) || PaddingLength > 4096 ||
            PaddingLength > Data.size() - Offset)
        {
            return false;
        }
        Offset += static_cast<std::size_t>(PaddingLength);
        HeaderSize = Offset;
        return true;
    }

    auto WriteAll(const Preview::Quic::SharedStreamProvider &Provider,
                  std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Provider->Write(Data.subspan(Offset), Error);
            if (Error || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Remote = SplitHostPort(OptionsValue.Address);
        if (!Remote)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 reference address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Remote->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 reference address is not an IP literal\n");
            co_return 2;
        }

        Ssl::context Tls(Ssl::context::tlsv13_client);
        Tls.set_verify_mode(Ssl::verify_none);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        if (SSL_CTX_set_alpn_protos(Tls.native_handle(), H3Alpn, sizeof(H3Alpn)) != 0)
        {
            std::fprintf(stderr, "FAIL: cannot configure Hysteria2 ALPN\n");
            co_return 1;
        }
        const auto Executor = co_await Net::this_coro::executor;
        const auto LocalEndpoint = Udp::endpoint(Udp::v4(), 0);
        auto Socket = std::make_shared<Udp::socket>(Executor, LocalEndpoint);
        const auto RemoteEndpoint = Udp::endpoint(Address, Remote->Port);
        auto ConnectionOptions = Preview::Quic::ClientOptions{
            Executor,
            Socket,
            RemoteEndpoint,
            Tls.native_handle(),
            "hysteria"};
        auto Connection = std::make_shared<Preview::Quic::Client>(
            std::move(ConnectionOptions));
        auto SessionOptions = Preview::Http3::NativeClientSessionOptions{
            Executor,
            Connection,
            OptionsValue.Password,
            "hysteria",
            "/auth"};
        auto Session = std::make_shared<Preview::Http3::NativeClientSession>(
            std::move(SessionOptions));
        const auto AuthError = co_await Session->Authenticate();
        if (AuthError != Preview::Fault::Code::Success)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 HTTP3 auth: %s\n", Preview::Fault::Describe(AuthError).data());
            Session->Close();
            co_return 1;
        }
        if (OptionsValue.Udp)
        {
            if (!Session->UdpEnabled())
            {
                std::fprintf(stderr, "FAIL: Hysteria2 reference server disabled UDP\n");
                Session->Close();
                co_return 1;
            }
            auto Datagram = Preview::Hysteria2::ConnectPacket(
                Connection->Datagram(), Preview::Hysteria2::ClientConfig{OptionsValue.Password});
            if (!Datagram)
            {
                std::fprintf(stderr, "FAIL: cannot open Hysteria2 UDP datagram provider\n");
                Session->Close();
                co_return 1;
            }
            const Preview::Hysteria2::Address Target{
                Preview::Hysteria2::AddressType::Ipv4, "127.0.0.1", 53};
            const std::string PayloadText{"hello hysteria2 UDP from preview"};
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
            if (co_await Datagram->AsyncSendTo(Target, Payload) != Preview::Error::None)
            {
                Datagram->Close();
                Session->Close();
                co_return 1;
            }
            Preview::Hysteria2::Address EchoTarget;
            std::vector<std::uint8_t> Echo;
            if (co_await Datagram->AsyncReceiveFrom(EchoTarget, Echo) != Preview::Error::None ||
                Echo.size() != Payload.size() || !std::equal(Echo.begin(), Echo.end(), Payload.begin()))
            {
                Datagram->Close();
                Session->Close();
                std::fprintf(stderr, "FAIL: Hysteria2 UDP external echo mismatch\n");
                co_return 1;
            }
            Datagram->Close();
            Session->Close();
            std::printf("PASS: Preview Hysteria2 client authenticated UDP echo (%zu bytes)\n",
                         Payload.size());
            co_return 0;
        }
        const auto Stream = co_await Session->OpenBidirectionalStream();
        if (!Stream)
        {
            std::fprintf(stderr, "FAIL: cannot open Hysteria2 TCP stream\n");
            Session->Close();
            co_return 1;
        }
        const std::string PayloadText{"hello hysteria2 from preview"};
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(PayloadText.data()), PayloadText.size());
        const auto Request = MakeTcpRequest("example.com:443", Payload);
        if (!co_await WriteAll(Stream, Request))
        {
            std::fprintf(stderr, "FAIL: Hysteria2 request write\n");
            Session->Close();
            co_return 1;
        }

        std::vector<std::byte> Response;
        std::array<std::byte, 4096> Buffer{};
        std::size_t HeaderSize = 0;
        std::uint8_t Status = 1;
        while (Response.size() < 65536)
        {
            if (ParseResponse(Response, HeaderSize, Status) &&
                Response.size() >= HeaderSize + Payload.size())
            {
                break;
            }
            std::error_code Error;
            const auto Count = co_await Stream->Read(Buffer, Error);
            if (Error || Count == 0)
            {
                std::fprintf(stderr, "FAIL: Hysteria2 response read\n");
                Session->Close();
                co_return 1;
            }
            const auto ResponseEnd = Buffer.begin() + static_cast<std::ptrdiff_t>(Count);
            Response.insert(Response.end(), Buffer.begin(), ResponseEnd);
        }
        const bool HasPayload = Response.size() >= HeaderSize + Payload.size();
        bool PayloadMatches = false;
        if (HasPayload)
        {
            const auto PayloadBegin = Response.begin() + static_cast<std::ptrdiff_t>(HeaderSize);
            PayloadMatches = std::equal(Payload.begin(), Payload.end(), PayloadBegin);
        }
        const bool Valid = Status == 0 && HasPayload && PayloadMatches;
        Stream->Close();
        Session->Close();
        if (!Valid)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 response mismatch status=%u bytes=%zu\n",
                         static_cast<unsigned>(Status), Response.size());
            co_return 1;
        }
        std::printf("PASS: Preview Hysteria2 client authenticated echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed Hysteria2 client options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    auto Run = [&Io, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunClient(OptionsValue);
        Io.stop();
    };
    auto OnComplete = [&Io, &Failure](std::exception_ptr Exception) -> void
    {
        Failure = std::move(Exception);
        Io.stop();
    };
    Net::co_spawn(Io, Run(), std::move(OnComplete));
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 client coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 client coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
