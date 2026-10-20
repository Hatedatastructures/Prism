/**
 * @file InteropHysteria2Client.cpp
 * @brief Prism 原生 HTTP/3 客户端与独立 sing-quic Hysteria2 服务端互操作
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
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

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Protocols/Http3/NativeClient.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/Native.hpp>

namespace
{

    namespace Net = boost::asio;
    using Net::experimental::awaitable_operators::operator||;
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

    auto WriteAll(const Prism::Quic::SharedStreamProvider &Provider,
                  std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Provider->Write(Data.subspan(Offset), Error);
            const auto Remaining = Data.size() - Offset;
            if (Written > Remaining)
            {
                co_return false;
            }
            Offset += Written;
            if (Error || Written == 0)
            {
                co_return false;
            }
        }
        co_return true;
    }

    struct ClientContext final
    {
        std::shared_ptr<Prism::Quic::Client> Connection;
        std::shared_ptr<Prism::Http3::NativeClientSession> Session;
        std::string Password;
    };

    struct ClientConnectionRequest final
    {
        Net::any_io_executor Executor;
        Udp::endpoint RemoteEndpoint;
        std::shared_ptr<Ssl::context> Tls;
        std::string Password;
        bool RequireUdp;
    };

    auto ReportQuicHealth(const char *Stage, const std::shared_ptr<Prism::Quic::Client> &Connection) -> void
    {
        if (!Connection)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 %s quic_connection=null\n", Stage);
            return;
        }
        const auto Health = Connection->Health();
        std::fprintf(stderr,
            "FAIL: Hysteria2 %s quic socket_ready=%d receive_loop_ready=%d handshake_ready=%d "
            "protocol_ready=%d closed=%d bounded_failure=%d dropped_datagrams=%llu\n",
            Stage,
            Health.SocketReady ? 1 : 0,
            Health.ReceiveLoopReady ? 1 : 0,
            Health.HandshakeReady ? 1 : 0,
            Health.ProtocolReady ? 1 : 0,
            Health.Closed ? 1 : 0,
            Health.BoundedFailure ? 1 : 0,
            static_cast<unsigned long long>(Health.DroppedDatagrams));
    }

    using AuthResponseResult =
        std::expected<Prism::Http3::ResponseHead, Prism::Fault::Failure>;

    auto CaptureAuthResult(
        Net::awaitable<AuthResponseResult> Operation,
        std::optional<AuthResponseResult> &Response,
        std::exception_ptr &Exception) -> Net::awaitable<void>
    {
        try
        {
            Response.emplace(co_await std::move(Operation));
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
    }

    [[nodiscard]] auto DrainClientSession(
        std::shared_ptr<Prism::Http3::NativeClientSession> Session)
        -> Net::awaitable<bool>
    {
        bool DrainSucceeded = false;
        try
        {
            const auto Drained = co_await Session->Drain();
            if (!Drained)
            {
                const auto Message = Prism::Fault::Describe(Drained.error().Code);
                std::fprintf(stderr, "FAIL: Hysteria2 HTTP3 client drain: %s native=%d\n",
                    Message.data(), Drained.error().Native.value());
            }
            else
            {
                DrainSucceeded = true;
            }
        }
        catch (const std::exception &Exception)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 HTTP3 client drain threw: %s\n", Exception.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 HTTP3 client drain threw an unknown exception\n");
        }
        co_return DrainSucceeded;
    }

    auto MakeAuthenticatedClient(ClientConnectionRequest Request)
        -> Net::awaitable<std::optional<ClientContext>>
    {
        auto Socket = std::make_shared<Udp::socket>(Request.Executor, Udp::endpoint(Udp::v4(), 0));
        auto Connection = std::make_shared<Prism::Quic::Client>(
            Prism::Quic::ClientOptions{
                Request.Executor, Socket, Request.RemoteEndpoint,
                Request.Tls, "hysteria"});
        auto Session = std::make_shared<Prism::Http3::NativeClientSession>(
            Prism::Http3::NativeClientSessionOptions{Request.Executor, Connection, {}});
        std::exception_ptr Exception;
        bool Authenticated = false;
        try
        {
            auto AuthOperation = Session->SendRequest(
                Prism::Hysteria2::BuildAuthRequest(
                    Prism::Hysteria2::ClientAuthOptions{
                        .Authority = "hysteria", .Password = Request.Password,
                        .ReceiveRate = 0, .Padding = {}}));
            std::optional<AuthResponseResult> AuthResponse;
            std::exception_ptr AuthException;
            Net::steady_timer AuthDeadline(co_await Net::this_coro::executor);
            AuthDeadline.expires_after(std::chrono::seconds(15));
            const auto WaitResult = co_await (
                CaptureAuthResult(
                    std::move(AuthOperation), AuthResponse, AuthException) ||
                AuthDeadline.async_wait(Net::use_awaitable));
            if (WaitResult.index() == 1)
            {
                ReportQuicHealth("HTTP/3 auth timeout", Connection);
                (void)Session->Close();
                Connection->Close();
            }
            else
            {
                if (AuthException)
                {
                    std::rethrow_exception(AuthException);
                }
                if (!AuthResponse)
                {
                    throw std::system_error(
                        std::make_error_code(std::errc::protocol_error),
                        "Hysteria2 HTTP/3 auth did not produce a response");
                }
                if (!*AuthResponse)
                {
                    std::fprintf(stderr,
                        "FAIL: Hysteria2 HTTP3 auth: %s native=%s/%d\n",
                        Prism::Fault::Describe(AuthResponse->error().Code).data(),
                        AuthResponse->error().Native.category().name(),
                        AuthResponse->error().Native.value());
                    ReportQuicHealth("HTTP/3 auth failure", Connection);
                }
                else
                {
                    auto ParsedAuth = Prism::Hysteria2::ParseAuthResponse(
                        std::move(**AuthResponse));
                    if (!ParsedAuth)
                    {
                        std::fprintf(stderr,
                            "FAIL: Hysteria2 HTTP3 auth response error=%u\n",
                            static_cast<unsigned>(ParsedAuth.error()));
                    }
                    else if (Request.RequireUdp && !ParsedAuth->UdpEnabled)
                    {
                        std::fprintf(stderr, "FAIL: Hysteria2 reference server disabled UDP\n");
                    }
                    else
                    {
                        Authenticated = true;
                    }
                }
            }
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (!Authenticated)
        {
            bool Drained = false;
            try
            {
                Drained = co_await DrainClientSession(Session);
            }
            catch (...)
            {
                if (!Exception)
                {
                    Exception = std::current_exception();
                }
            }
            (void)Drained;
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
            co_return std::nullopt;
        }
        co_return ClientContext{Connection, Session, std::move(Request.Password)};
    }

    auto ReportDatagramCleanupFailure(
        const Prism::Fault::Failure& Failure) -> void
    {
        const auto Message = Prism::Fault::Describe(Failure.Code);
        std::fprintf(stderr, "FAIL: Hysteria2 UDP datagram close/drain: %s native=%d category=%s\n",
            Message.data(), Failure.Native.value(), Failure.Native.category().name());
    }

    auto CloseAndDrainDatagram(Prism::Hysteria2::SharedDgram Datagram)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Datagram)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Activities;
        std::optional<Prism::Fault::Failure> FirstFailure;
        std::exception_ptr FirstException;
        try
        {
            for (Prism::Transmission *Layer = Datagram.get(); Layer;
                 Layer = Layer->NextLayer())
            {
                auto Activity = Layer->Activity();
                if (!Activity)
                {
                    if (!FirstFailure && !FirstException)
                    {
                        FirstFailure = Prism::Fault::Failure{
                            Prism::Fault::Code::ResourceUnavailable};
                    }
                    continue;
                }
                Activities.push_back(std::move(Activity));
            }
        }
        catch (...)
        {
            if (!FirstFailure && !FirstException)
            {
                FirstException = std::current_exception();
            }
        }
        try
        {
            const auto Closed = Datagram->Close();
            if (!Closed && !FirstFailure && !FirstException)
            {
                FirstFailure = Closed.error();
            }
        }
        catch (...)
        {
            if (!FirstFailure && !FirstException)
            {
                FirstException = std::current_exception();
            }
        }
        for (std::size_t Index = 0; Index < Activities.size(); ++Index)
        {
            const auto Activity = Activities[Index];
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained && !FirstFailure && !FirstException)
                {
                    FirstFailure = Drained.error();
                }
            }
            catch (...)
            {
                if (!FirstFailure && !FirstException)
                {
                    FirstException = std::current_exception();
                }
            }
        }
        if (FirstException)
        {
            std::rethrow_exception(FirstException);
        }
        if (FirstFailure)
        {
            co_return std::unexpected(*FirstFailure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunUdpClient(ClientContext Context) -> Net::awaitable<int>
    {
        auto DatagramResult = Prism::Hysteria2::ConnectPacket(
            Context.Connection->Datagram(),
            Prism::Hysteria2::ClientConfig{Context.Password});
        if (!DatagramResult)
        {
            const auto Message = Prism::Fault::Describe(DatagramResult.error().Code);
            std::fprintf(stderr, "FAIL: cannot open Hysteria2 UDP datagram provider: %s native=%d\n",
                Message.data(), DatagramResult.error().Native.value());
            co_return 1;
        }
        auto Datagram = std::move(*DatagramResult);
        const Prism::Hysteria2::Address Target{
            Prism::Hysteria2::AddressType::Ipv4, "127.0.0.1", 53};
        const std::string PayloadText{"hello hysteria2 UDP from preview"};
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
        const auto SendError = co_await Datagram->AsyncSendTo(Target, Payload);
        if (SendError != Prism::Error::None)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 UDP request send error=%u\n",
                         static_cast<unsigned int>(SendError));
            const auto DrainResult = co_await CloseAndDrainDatagram(Datagram);
            if (!DrainResult)
            {
                ReportDatagramCleanupFailure(DrainResult.error());
            }
            co_return 1;
        }
        Prism::Hysteria2::Address EchoTarget;
        std::vector<std::uint8_t> Echo;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(EchoTarget, Echo);
        const bool Valid = ReceiveError == Prism::Error::None &&
                           Echo.size() == Payload.size() &&
                           std::equal(Echo.begin(), Echo.end(), Payload.begin());
        if (!Valid)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 UDP external echo mismatch\n");
        }
        const auto DrainResult = co_await CloseAndDrainDatagram(Datagram);
        if (!DrainResult)
        {
            ReportDatagramCleanupFailure(DrainResult.error());
            co_return 1;
        }
        if (!Valid) co_return 1;
        std::printf("PASS: Prism Hysteria2 client authenticated UDP echo (%zu bytes)\n",
                     Payload.size());
        co_return 0;
    }

    auto RunTcpClient(ClientContext Context) -> Net::awaitable<int>
    {
        auto StreamResult = co_await Context.Session->OpenBidirectionalStream();
        if (!StreamResult)
        {
            const auto Message = Prism::Fault::Describe(StreamResult.error().Code);
            std::fprintf(stderr, "FAIL: cannot open Hysteria2 TCP stream: %s native=%d\n",
                Message.data(), StreamResult.error().Native.value());
            co_return 1;
        }
        auto Stream = std::move(*StreamResult);
        const std::string PayloadText{"hello hysteria2 from preview"};
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(PayloadText.data()), PayloadText.size());
        const auto Request = MakeTcpRequest("example.com:443", Payload);
        if (!co_await WriteAll(Stream, Request))
        {
            std::fprintf(stderr, "FAIL: Hysteria2 request write\n");
            co_return 1;
        }
        std::vector<std::byte> Response;
        std::array<std::byte, 4096> Buffer{};
        std::size_t HeaderSize = 0;
        std::uint8_t Status = 1;
        constexpr std::size_t MaxResponseBytes = 65536;
        bool ResponseComplete = false;
        while (Response.size() < MaxResponseBytes)
        {
            std::error_code Error;
            const auto Count = co_await Stream->Read(Buffer, Error);
            if (Count > Buffer.size() || Count > MaxResponseBytes - Response.size())
            {
                std::fprintf(stderr, "FAIL: Hysteria2 response read returned an invalid byte count\n");
                co_return 1;
            }
            if (Count != 0)
            {
                Response.insert(Response.end(), Buffer.begin(), Buffer.begin() +
                    static_cast<std::ptrdiff_t>(Count));
            }
            ResponseComplete = ParseResponse(Response, HeaderSize, Status) &&
                Response.size() >= HeaderSize + Payload.size();
            if (Error)
            {
                const auto ReadFailure = Prism::Fault::FromNative(Error);
                const bool PeerFin = ReadFailure.Code == Prism::Fault::Code::Eof;
                if (!PeerFin || !ResponseComplete)
                {
                    std::fprintf(stderr,
                        "FAIL: Hysteria2 response read: %s native=%d\n",
                        Prism::Fault::Describe(ReadFailure.Code).data(), Error.value());
                    co_return 1;
                }
                break;
            }
            if (Count == 0)
            {
                std::fprintf(stderr, "FAIL: Hysteria2 response read returned no bytes without terminal\n");
                co_return 1;
            }
            if (ResponseComplete)
            {
                break;
            }
        }
        const bool HasPayload = ResponseComplete;
        const bool PayloadMatches = HasPayload && std::equal(
            Payload.begin(), Payload.end(), Response.begin() +
            static_cast<std::ptrdiff_t>(HeaderSize));
        const bool Valid = Status == 0 && HasPayload && PayloadMatches;
        if (!Valid)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 response mismatch status=%u bytes=%zu\n",
                         static_cast<unsigned>(Status), Response.size());
            co_return 1;
        }
        std::printf("PASS: Prism Hysteria2 client authenticated echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    auto RunClientOperation(ClientContext Context, const bool UseUdp) -> Net::awaitable<int>
    {
        if (UseUdp)
        {
            co_return co_await RunUdpClient(std::move(Context));
        }
        co_return co_await RunTcpClient(std::move(Context));
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
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
        Tls->set_verify_mode(Ssl::verify_none);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        if (SSL_CTX_set_alpn_protos(Tls->native_handle(), H3Alpn, sizeof(H3Alpn)) != 0)
        {
            std::fprintf(stderr, "FAIL: cannot configure Hysteria2 ALPN\n");
            co_return 1;
        }
        const auto Executor = co_await Net::this_coro::executor;
        const auto Context = co_await MakeAuthenticatedClient(
            ClientConnectionRequest{Executor, Udp::endpoint(Address, Remote->Port), Tls,
                                    OptionsValue.Password, OptionsValue.Udp});
        if (!Context)
        {
            co_return 1;
        }
        const auto SessionPin = Context->Session;
        int ExitCode = 1;
        std::exception_ptr OperationException;
        try
        {
            ExitCode = co_await RunClientOperation(std::move(*Context), OptionsValue.Udp);
        }
        catch (...)
        {
            OperationException = std::current_exception();
        }
        bool Drained = false;
        try
        {
            Drained = co_await DrainClientSession(SessionPin);
        }
        catch (...)
        {
            if (!OperationException)
            {
                OperationException = std::current_exception();
            }
        }
        if (OperationException)
        {
            std::rethrow_exception(OperationException);
        }
        co_return Drained ? ExitCode : 1;
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        ExitCode = co_await RunClient(OptionsValue);
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
    Net::co_spawn(Io, RunInterop(*Options, ExitCode),
                  [&Failure](std::exception_ptr Exception) { Failure = std::move(Exception); });
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
