/**
 * @file InteropHysteria2TcpServer.cpp
 * @brief Hysteria2 TCP server 与独立客户端的认证、透明流和 half-close 互操作。
 */

#include "Hysteria2/TcpEcho.hpp"
#include "InteropHysteria2Support.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>
#include <Prism/Protocols/Http3/NativeServer.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include "../../TestSupport/Prism/QuicFactory.hpp"

namespace Prism::Testing::Integration::Hysteria2::Interop
{
    namespace Echo = Prism::Testing::Integration::Hysteria2;
    using Udp = Net::ip::udp;

    namespace
    {
        auto WriteAll(
            const Prism::Quic::SharedStreamProvider &Provider,
            const std::span<const std::byte> Data) -> Net::awaitable<bool>
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

        auto WriteAll(
            const Prism::SharedTransmission &Transmission,
            const std::span<const std::byte> Data) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Result = co_await Transmission->WriteSome(Data.subspan(Offset));
                const auto Remaining = Data.size() - Offset;
                if (Result.Bytes > Remaining || Result.Failure.Failed() || Result.Bytes == 0)
                {
                    co_return false;
                }
                Offset += Result.Bytes;
            }
            co_return true;
        }

        auto ReadExact(
            const Prism::SharedTransmission &Transmission,
            const std::size_t Size)
            -> Net::awaitable<std::expected<std::vector<std::byte>, std::error_code>>
        {
            std::vector<std::byte> Buffer(Size);
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                const auto Result = co_await Transmission->ReadSome(
                    std::span(Buffer).subspan(Offset));
                const auto Remaining = Buffer.size() - Offset;
                if (Result.Bytes > Remaining || Result.Failure.Failed() || Result.Bytes == 0)
                {
                    co_return std::unexpected(Prism::Fault::ToNative(
                        Result.Failure.Failed()
                            ? Result.Failure
                            : Prism::Fault::Failure{Prism::Fault::Code::Eof}));
                }
                Offset += Result.Bytes;
            }
            co_return Buffer;
        }

        [[nodiscard]] auto ParseTargetText(const std::string_view Text,
                                           Prism::Hysteria2::Address &Output) -> bool
        {
            std::string_view Host;
            std::string_view PortText;
            if (Text.starts_with('['))
            {
                const auto Close = Text.find(']');
                if (Close == std::string_view::npos || Close + 1 >= Text.size() ||
                    Text[Close + 1] != ':')
                {
                    return false;
                }
                Host = Text.substr(1, Close - 1);
                PortText = Text.substr(Close + 2);
                Output.Type = Prism::Hysteria2::AddressType::Ipv6;
            }
            else
            {
                const auto Colon = Text.rfind(':');
                if (Colon == std::string_view::npos || Colon == 0)
                {
                    return false;
                }
                Host = Text.substr(0, Colon);
                PortText = Text.substr(Colon + 1);
                Output.Type = Host.find_first_not_of("0123456789.") == std::string_view::npos
                    ? Prism::Hysteria2::AddressType::Ipv4
                    : Prism::Hysteria2::AddressType::Domain;
            }
            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || Error != std::errc{} ||
                End != PortText.data() + PortText.size() || Port > 65535)
            {
                return false;
            }
            Output.Host.assign(Host.data(), Host.size());
            Output.Port = static_cast<std::uint16_t>(Port);
            return true;
        }

        [[nodiscard]] auto ToNetworkTarget(const Prism::Hysteria2::Address &AddressValue)
            -> std::expected<Prism::Network::Target, Prism::Fault::Failure>
        {
            auto Encoding = Prism::Network::HostEncoding::Domain;
            if (AddressValue.Type == Prism::Hysteria2::AddressType::Ipv4)
            {
                Encoding = Prism::Network::HostEncoding::Ipv4Text;
            }
            else if (AddressValue.Type == Prism::Hysteria2::AddressType::Ipv6)
            {
                Encoding = Prism::Network::HostEncoding::Ipv6Bytes;
            }
            else if (AddressValue.Type != Prism::Hysteria2::AddressType::Domain)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::UnsupportedAddress});
            }
            auto Host = Prism::Network::DecodeHost(Encoding, AddressValue.Host);
            if (!Host)
            {
                return std::unexpected(Host.error());
            }
            return Prism::Network::Target{
                std::move(*Host), AddressValue.Port, Prism::Network::RouteKind::Forward};
        }

        auto RecordWrittenPayload(
            Echo::TcpEchoEvidence &Evidence,
            const std::span<const std::byte> Reply,
            const std::span<const std::byte> Expected) -> void
        {
            Evidence.WrittenPayload.assign(Expected.begin(), Expected.end());
            Evidence.PayloadBytes = Reply.size();
            Evidence.PayloadHash = Echo::HashPayload(Expected);
            Evidence.ResponseWriteCompleted =
                Evidence.PayloadBytes == Echo::ExpectedTcpPayload.size();
        }

        auto CloseBoth(
            const Prism::SharedTransmission &Inbound,
            const Prism::SharedTransmission &Outbound) -> void
        {
            (void)Inbound->Close();
            (void)Outbound->Close();
        }

        auto CloseProvider(const Prism::Quic::SharedStreamProvider &Provider) -> void
        {
            const auto Result = Provider->Close();
            if (!Result)
            {
                ReportSessionRunFailure("Hysteria2 raw QUIC stream close", Result.error());
            }
        }

        auto CloseAndDrainTarget(const Prism::SharedTransmission &Outbound)
            -> Net::awaitable<void>
        {
            const auto Closed = Outbound->Close();
            if (!Closed)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Closed.error()),
                    "Hysteria2 TCP target close");
            }
            const auto Activity = Outbound->Activity();
            if (!Activity)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::ResourceUnavailable}),
                    "Hysteria2 TCP target activity");
            }
            const auto Drained = co_await Activity->Drain();
            if (!Drained)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Drained.error()),
                    "Hysteria2 TCP target drain");
            }
        }

        auto RelayRawStream(
            const Prism::Quic::SharedStreamProvider &Provider,
            const std::shared_ptr<Echo::TcpEchoEvidence> &Evidence,
            const Echo::StreamState &State) -> Net::awaitable<void>
        {
            Prism::Hysteria2::Address AddressValue;
            if (!ParseTargetText(State.Target, AddressValue))
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::UnsupportedAddress}),
                    "Hysteria2 TCP request target is malformed");
            }
            auto Target = ToNetworkTarget(AddressValue);
            if (!Target)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Target.error()),
                    "Hysteria2 TCP request target is unsupported");
            }
            const auto Executor = Provider->Executor();
            Prism::Network::Dialer::Dialer Dialer(Executor);
            auto Dialed = co_await Dialer.Connect(std::move(*Target));
            if (!Dialed)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Dialed.error()),
                    "Hysteria2 TCP target dial");
            }
            auto Outbound = std::move(*Dialed);
            const auto Header = Echo::MakeTcpResponse({});
            if (!co_await WriteAll(Provider, Header))
            {
                (void)Outbound->Close();
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::IoError}),
                    "Hysteria2 TCP response header write");
            }
            auto Inbound = std::make_shared<Prism::Quic::StreamAdapter>(
                Executor, Provider);
            if (!co_await WriteAll(Outbound, State.InitialPayload))
            {
                (void)Inbound->Close();
                (void)Outbound->Close();
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::IoError}),
                    "Hysteria2 TCP initial payload write");
            }
            if (!Evidence->RequestParsed)
            {
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::ProtocolError}),
                    "Hysteria2 TCP request was not parsed");
            }
            const auto ExpectedBytes = std::as_bytes(std::span(Echo::ExpectedTcpPayload));
            const auto ReplyRead = co_await ReadExact(Outbound, ExpectedBytes.size());
            if (!ReplyRead)
            {
                CloseBoth(Inbound, Outbound);
                throw std::system_error(ReplyRead.error(), "Hysteria2 TCP target response read");
            }
            const auto &Reply = *ReplyRead;
            if (!std::equal(Reply.begin(), Reply.end(), ExpectedBytes.begin()))
            {
                CloseBoth(Inbound, Outbound);
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::ProtocolError}),
                    "Hysteria2 TCP target response mismatch");
            }
            if (!co_await WriteAll(Provider, Reply))
            {
                CloseBoth(Inbound, Outbound);
                throw std::system_error(
                    Prism::Fault::ToNative(Prism::Fault::Failure{
                        Prism::Fault::Code::IoError}),
                    "Hysteria2 TCP response payload write");
            }
            RecordWrittenPayload(*Evidence, Reply, ExpectedBytes);
            CloseProvider(Provider);
            co_await CloseAndDrainTarget(Outbound);
        }

        auto WriteRawAction(
            const Prism::Quic::SharedStreamProvider &Provider,
            const std::shared_ptr<Echo::TcpEchoEvidence> &Evidence,
            const Echo::RawAction &Action) -> Net::awaitable<bool>
        {
            if (Action.Data.empty())
            {
                co_return true;
            }
            if (!co_await WriteAll(Provider, Action.Data))
            {
                co_return false;
            }
            co_return Echo::RecordWritten(*Evidence, Action);
        }

        auto CloseRawStreamProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void
        {
            const auto Closed = Provider->Close();
            if (!Closed)
            {
                ReportSessionRunFailure("Hysteria2 raw QUIC stream close admission", Closed.error());
            }
        }

        auto RunRawStream(
            Prism::Quic::SharedStreamProvider Provider,
            std::shared_ptr<Echo::TcpEchoEvidence> Evidence) -> Net::awaitable<void>
        {
            if (!Provider)
            {
                co_return;
            }
            Echo::StreamState State;
            std::array<std::byte, 16384> Buffer{};
            while (true)
            {
                std::error_code Error;
                const auto Count = co_await Provider->Read(Buffer, Error);
                if (Count > Buffer.size())
                {
                    CloseRawStreamProvider(Provider);
                    throw std::system_error(
                        Prism::Fault::ToNative(
                            Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}),
                        "Hysteria2 raw QUIC stream read count exceeds buffer");
                }
                const auto Action = Echo::HandleTcpData(Echo::TcpDataInput{
                    State,
                    std::span<const std::byte>(Buffer.data(), Count),
                    false,
                    *Evidence});
                const bool PeerFin = Error &&
                    Prism::Fault::FromNative(Error).Code == Prism::Fault::Code::Eof;
                if (Error && !PeerFin)
                {
                    CloseRawStreamProvider(Provider);
                    throw std::system_error(Error, "Hysteria2 raw QUIC stream read");
                }
                if (PeerFin)
                {
                    const auto FinAction = Echo::HandleTcpData(Echo::TcpDataInput{
                        State, {}, true, *Evidence});
                    (void)FinAction;
                }
                else if (Count == 0)
                {
                    CloseRawStreamProvider(Provider);
                    throw std::system_error(
                        Prism::Fault::ToNative(
                            Prism::Fault::Failure{Prism::Fault::Code::WouldBlock}),
                        "Hysteria2 raw QUIC stream read returned no bytes without terminal");
                }

                if (State.RequestDone)
                {
                    co_await RelayRawStream(Provider, Evidence, State);
                    co_return;
                }
                if (PeerFin || Action.Stop)
                {
                    CloseRawStreamProvider(Provider);
                    co_return;
                }
            }
        }

        struct RawStreamOwner final
        {
            std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
            std::shared_ptr<std::exception_ptr> Failure;
            bool Started{false};
        };

        struct ServerEventRequest final
        {
            std::shared_ptr<Prism::Hysteria2::Http3AuthSession> AuthSession;
            std::shared_ptr<Echo::TcpEchoEvidence> Evidence;
            std::shared_ptr<RawStreamOwner> RawStream;
        };

        auto HandleServerEvent(ServerEventRequest Request, Prism::Http3::ServerEvent Event)
            -> Net::awaitable<Prism::Http3::SessionAction>
        {
            if (auto *HttpRequest = std::get_if<Prism::Http3::RequestEvent>(&Event))
            {
                auto Response = Request.AuthSession->HandleRequest(std::move(*HttpRequest));
                if (Response)
                {
                    co_return Prism::Http3::SessionAction(std::move(*Response));
                }
                co_return Prism::Http3::SessionAction{};
            }
            if (auto *Raw = std::get_if<Prism::Http3::RawStreamEvent>(&Event))
            {
                if (!Request.AuthSession->Authenticated())
                {
                    co_return Prism::Http3::SessionAction{};
                }
                Request.RawStream->Started = true;
                const auto Executor = Raw->Provider->Executor();
                auto Owner = Request.RawStream;
                Net::co_spawn(
                    Executor,
                    RunRawStream(Raw->Provider, Request.Evidence),
                    [Owner](std::exception_ptr ErrorValue)
                    {
                        if (ErrorValue && !*Owner->Failure)
                        {
                            *Owner->Failure = ErrorValue;
                        }
                        (void)Owner->Done->try_send(boost::system::error_code{});
                    });
                co_return Prism::Http3::SessionAction{Prism::Http3::StreamMode::Opaque};
            }
            co_return Prism::Http3::SessionAction{};
        }

        struct TcpSessionRequest final
        {
            Options OptionsValue;
            Net::any_io_executor Executor;
            std::shared_ptr<Prism::Quic::Server> QuicServer;
        };

        struct TcpSessionOwner final
        {
            std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
            std::shared_ptr<std::exception_ptr> Failure;
            std::shared_ptr<SessionRunResult> Result;
        };

        [[nodiscard]] auto StartTcpSession(
            Net::any_io_executor Executor,
            std::shared_ptr<Prism::Http3::NativeServerSession> Session) -> TcpSessionOwner
        {
            TcpSessionOwner Owner{
                std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                    Executor, 1),
                std::make_shared<std::exception_ptr>(),
                std::make_shared<SessionRunResult>()};
            Net::co_spawn(
                Executor,
                Session->Run(),
                [Owner](std::exception_ptr ErrorValue, SessionRunResult Result)
                {
                    *Owner.Result = std::move(Result);
                    if (ErrorValue && !*Owner.Failure)
                    {
                        *Owner.Failure = ErrorValue;
                    }
                    (void)Owner.Done->try_send(boost::system::error_code{});
                });
            return Owner;
        }

        [[nodiscard]] auto WaitTcpSession(
            const TcpSessionOwner &Owner) -> Net::awaitable<SessionRunResult>
        {
            boost::system::error_code WaitError;
            (void)co_await Owner.Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
            {
                throw std::system_error(WaitError);
            }
            if (*Owner.Failure)
            {
                std::rethrow_exception(*Owner.Failure);
            }
            co_return std::move(*Owner.Result);
        }

        auto RunTcpSession(TcpSessionRequest Request) -> Net::awaitable<int>
        {
            auto Evidence = std::make_shared<Echo::TcpEchoEvidence>();
            constexpr auto ExpectedPayload = Echo::ExpectedTcpPayload;
            const auto ExpectedHash = Echo::HashPayload(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(ExpectedPayload.data()), ExpectedPayload.size()));
            const auto Auth = MakeAuthenticator(Request.OptionsValue.Password);
            auto AuthSession = std::make_shared<Prism::Hysteria2::Http3AuthSession>(
                Prism::Hysteria2::Http3AuthSessionOptions{Request.Executor, Auth.Authenticator});
            Prism::Http3::NativeServerSessionOptions SessionOptions;
            SessionOptions.Executor = Request.Executor;
            SessionOptions.OpenUnidirectional = [QuicServer = Request.QuicServer]()
                -> Net::awaitable<QuicStreamResult>
            {
                co_return co_await QuicServer->OpenUnidirectionalStream();
            };
            SessionOptions.AcceptUnidirectional = [QuicServer = Request.QuicServer]()
                -> Net::awaitable<QuicStreamResult>
            {
                co_return co_await QuicServer->AcceptUnidirectionalStream();
            };
            SessionOptions.AcceptBidirectional = [QuicServer = Request.QuicServer]()
                -> Net::awaitable<QuicStreamResult>
            {
                co_return co_await QuicServer->AcceptBidirectionalStream();
            };
            auto RawStream = std::make_shared<RawStreamOwner>(RawStreamOwner{
                std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Request.Executor, 1),
                std::make_shared<std::exception_ptr>()});
            const ServerEventRequest EventRequest{AuthSession, Evidence, RawStream};
            SessionOptions.OnEvent = [EventRequest](Prism::Http3::ServerEvent Event)
            {
                return HandleServerEvent(EventRequest, std::move(Event));
            };
            auto Session = std::make_shared<Prism::Http3::NativeServerSession>(std::move(SessionOptions));
            auto SessionOwner = StartTcpSession(Request.Executor, Session);
            boost::system::error_code RawError;
            (void)co_await RawStream->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, RawError));
            if (RawError)
            {
                throw std::system_error(RawError);
            }
            if (*RawStream->Failure)
            {
                std::rethrow_exception(*RawStream->Failure);
            }
            (void)Session->Close();
            Request.QuicServer->Close();
            const auto SessionResult = co_await WaitTcpSession(SessionOwner);
            const auto QuicDrain = co_await Request.QuicServer->Drain();
            if (!QuicDrain)
            {
                ReportSessionRunFailure("Hysteria2 TCP QUIC drain", QuicDrain.error());
            }
            const auto Authenticated = AuthSession->Authenticated();
            const auto PayloadHashMatches = Evidence->ResponseWriteCompleted &&
                Evidence->PayloadBytes == ExpectedPayload.size() &&
                Evidence->PayloadHash == ExpectedHash;
            const auto EchoedValue = Evidence->ResponseWriteCompleted &&
                PayloadHashMatches;
            const auto SessionCode = SessionResult
                ? Prism::Fault::Code::Success
                : SessionResult.error().Code;
            const auto SessionNative = SessionResult ? 0 : SessionResult.error().Native.value();
            const auto SessionNativeCategory = SessionResult
                ? "none"
                : SessionResult.error().Native.category().name();
            const auto SessionFinished = SessionResult ||
                (!SessionResult && SessionResult.error().Code == Prism::Fault::Code::Canceled);
            if (!SessionFinished || !Authenticated || !EchoedValue || !QuicDrain)
            {
                auto AuthenticatedValue = 0;
                if (Authenticated)
                {
                    AuthenticatedValue = 1;
                }
                std::fprintf(stderr,
                             "FAIL: Hysteria2 session code=%s native=%d category=%s authenticated=%d "
                             "request_parsed=%d response_write_completed=%d "
                             "payload_bytes=%zu payload_hash_match=%d write_fin_requested=%d "
                             "write_fin_code=%d write_fin_native=%d write_fin_category=%s "
                             "peer_delivery_not_inferred=1\n",
                             Prism::Fault::Describe(SessionCode).data(),
                             SessionNative,
                             SessionNativeCategory,
                             AuthenticatedValue,
                             Evidence->RequestParsed ? 1 : 0,
                             Evidence->ResponseWriteCompleted ? 1 : 0,
                             Evidence->PayloadBytes,
                             PayloadHashMatches ? 1 : 0,
                             Evidence->WriteFinRequested ? 1 : 0,
                             Evidence->WriteFinFailure ? static_cast<int>(Evidence->WriteFinFailure->Code) : 0,
                             Evidence->WriteFinFailure ? Evidence->WriteFinFailure->Native.value() : 0,
                             Evidence->WriteFinFailure ? Evidence->WriteFinFailure->Native.category().name() : "none");
                co_return 1;
            }
            std::printf("PASS: Prism Hysteria2 authenticated echo\n");
            std::printf(
                "DETAIL: server_response_payload_bytes=%zu payload_hash_match=%d "
                "write_fin_requested=%d peer_delivery_not_inferred=1 "
                "external_half_close_capability=absent\n",
                Evidence->PayloadBytes,
                PayloadHashMatches ? 1 : 0,
                Evidence->WriteFinRequested ? 1 : 0);
            co_return 0;
        }
    }

    auto RunTcpServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 listen address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = MakeServerTls();
        if (!Tls)
        {
            std::fprintf(stderr, "FAIL: cannot create Hysteria2 self-signed certificate\n");
            co_return 1;
        }

        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(Executor, Udp::endpoint(Address, Listen->Port));
        auto QuicServer = std::make_shared<Prism::Quic::Server>(Prism::Quic::ServerOptions{
            Executor, Socket, Tls, Prism::Testing::Quic::MakeSender(Socket)});
        QuicServer->Start();
        std::printf("READY: Prism Hysteria2 server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        const auto HandshakeOk = co_await WaitQuicHandshakeOrDrain(QuicServer);
        if (!HandshakeOk)
        {
            co_return 1;
        }
        co_return co_await RunTcpSession(
            TcpSessionRequest{std::move(OptionsValue), Executor, std::move(QuicServer)});
    }
}
