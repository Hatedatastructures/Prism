/**
 * @file Hysteria2Factory.hpp
 * @brief Native QUIC Server 到 Hysteria2 HTTP/3 与数据面的接线。
 */
#pragma once

#include <Preview/Ingress/QuicAdmissionContext.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Composition::Quic
{

    namespace Net = boost::asio;

    struct Hysteria2FactoryOptions final
    {
        using AuthenticateHandler = std::function<bool(
            std::string_view, std::string_view, std::string_view)>;
        using RawStreamHandler = std::function<Net::awaitable<void>(
            Preview::Quic::SharedStreamProvider)>;

        std::string Alpn{"h3"};
        Preview::Hysteria2::ServerConfig Config;
        AuthenticateHandler Authenticate{};
        std::function<Net::awaitable<void>(Preview::Hysteria2::Message,
                                           Preview::Hysteria2::SharedConn)> OnStream;
        RawStreamHandler RawStream{};
        std::function<Net::awaitable<void>(Preview::Hysteria2::SharedDgram)> OnDatagram;
        std::function<void()> OnClosed;
    };

    namespace Detail
    {

        enum class RawParseResult : std::uint8_t
        {
            NeedMore,
            Invalid,
            Ready,
        };

        struct RawRequest final
        {
            Preview::Hysteria2::Address Target;
            std::size_t Consumed{0};
        };

        [[nodiscard]] inline constexpr auto MakeTcpResponseHeader()
            -> std::array<std::uint8_t, 3>
        {
            // status=0, message length=0, padding length=0
            return {0x00, 0x00, 0x00};
        }

        [[nodiscard]] inline auto ReadVarint(
            std::span<const std::uint8_t> Data,
            std::size_t &Offset,
            std::uint64_t &Value) -> RawParseResult
        {
            if (Offset >= Data.size())
            {
                return RawParseResult::NeedMore;
            }
            const auto First = Data[Offset];
            const auto Length = std::size_t{1U} << (First >> 6U);
            if (Offset + Length > Data.size())
            {
                return RawParseResult::NeedMore;
            }
            Value = First & 0x3FU;
            for (std::size_t Index = 1; Index < Length; ++Index)
            {
                Value = (Value << 8U) | Data[Offset + Index];
            }
            Offset += Length;
            return RawParseResult::Ready;
        }

        [[nodiscard]] inline auto ParseRawRequest(
            std::span<const std::uint8_t> Data,
            RawRequest &Output) -> RawParseResult
        {
            constexpr std::uint64_t TcpRequestFrameType = 0x401U;
            constexpr std::size_t MaxAddressLength = 2048U;
            constexpr std::size_t MaxPaddingLength = 4096U;
            std::size_t Offset = 0;
            std::uint64_t FrameType = 0;
            auto Result = ReadVarint(Data, Offset, FrameType);
            if (Result != RawParseResult::Ready)
            {
                return Result;
            }
            if (FrameType != TcpRequestFrameType)
            {
                return RawParseResult::Invalid;
            }
            std::uint64_t AddressLength = 0;
            Result = ReadVarint(Data, Offset, AddressLength);
            if (Result != RawParseResult::Ready)
            {
                return Result;
            }
            if (AddressLength == 0U || AddressLength > MaxAddressLength)
            {
                return RawParseResult::Invalid;
            }
            if (Data.size() - Offset < AddressLength)
            {
                return RawParseResult::NeedMore;
            }
            const std::string_view AddressText(
                reinterpret_cast<const char *>(Data.data() + Offset),
                static_cast<std::size_t>(AddressLength));
            std::string_view Host;
            std::string_view PortText;
            if (!AddressText.empty() && AddressText.front() == '[')
            {
                const auto Close = AddressText.find(']');
                if (Close == std::string_view::npos || Close + 2U > AddressText.size() ||
                    AddressText[Close + 1U] != ':')
                {
                    return RawParseResult::Invalid;
                }
                Host = AddressText.substr(1U, Close - 1U);
                PortText = AddressText.substr(Close + 2U);
            }
            else
            {
                const auto Separator = AddressText.rfind(':');
                if (Separator == std::string_view::npos || Separator == 0U ||
                    Separator + 1U >= AddressText.size())
                {
                    return RawParseResult::Invalid;
                }
                Host = AddressText.substr(0U, Separator);
                PortText = AddressText.substr(Separator + 1U);
            }
            std::uint32_t Port = 0;
            const auto PortResult = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || PortResult.ec != std::errc{} ||
                PortResult.ptr != PortText.data() + PortText.size() || Port == 0U ||
                Port > 65535U)
            {
                return RawParseResult::Invalid;
            }
            Output.Target.Type = Preview::Hysteria2::AddressType::Domain;
            Output.Target.Host.assign(Host);
            Output.Target.Port = static_cast<std::uint16_t>(Port);
            Offset += static_cast<std::size_t>(AddressLength);
            std::uint64_t PaddingLength = 0;
            Result = ReadVarint(Data, Offset, PaddingLength);
            if (Result != RawParseResult::Ready)
            {
                return Result;
            }
            if (PaddingLength > MaxPaddingLength || Data.size() - Offset < PaddingLength)
            {
                return PaddingLength > MaxPaddingLength
                           ? RawParseResult::Invalid
                           : RawParseResult::NeedMore;
            }
            Offset += static_cast<std::size_t>(PaddingLength);
            Output.Consumed = Offset;
            return RawParseResult::Ready;
        }

        [[nodiscard]] inline auto WriteAll(
            const Preview::SharedTransmission &Transport,
            std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                std::error_code Error;
                const auto Count = co_await Transport->async_write_some(
                    Preview::AsBytes(Data.subspan(Offset)), Error);
                if (Error || Count == 0U || Count > Data.size() - Offset)
                {
                    co_return false;
                }
                Offset += Count;
            }
            co_return true;
        }

        [[nodiscard]] inline auto RunRawStream(
            const Preview::Ingress::SharedQuicAdmissionContext &Admission,
            const Preview::Quic::SharedStreamProvider &Provider) -> Net::awaitable<void>
        {
            if (!Admission || !Provider || !Admission->Dial)
            {
                if (Provider)
                {
                    Provider->Close();
                }
                co_return;
            }

            auto Inbound = std::make_shared<Preview::Quic::StreamAdapter>(
                Provider->Executor(), Provider);
            std::vector<std::uint8_t> Wire;
            Wire.reserve(1024);
            std::array<std::byte, 16384> Chunk{};
            RawRequest Request;
            bool Parsed = false;

            while (!Parsed)
            {
                std::error_code Error;
                const auto Count = co_await Inbound->async_read_some(Chunk, Error);
                if (Error || Count == 0U)
                {
                    Inbound->Close();
                    co_return;
                }
                Wire.insert(
                    Wire.end(),
                    reinterpret_cast<const std::uint8_t *>(Chunk.data()),
                    reinterpret_cast<const std::uint8_t *>(Chunk.data()) + Count);
                const auto ParseError = ParseRawRequest(
                    std::span<const std::uint8_t>(Wire), Request);
                if (ParseError == RawParseResult::NeedMore)
                {
                    continue;
                }
                if (ParseError != RawParseResult::Ready ||
                    Request.Target.Host.empty() || Request.Target.Port == 0U)
                {
                    Inbound->Close();
                    co_return;
                }
                Parsed = true;
            }

            Preview::Network::Target Target;
            Target.Host.assign(Request.Target.Host);
            Target.Port.assign(std::to_string(Request.Target.Port));
            Target.Positive = true;
            auto [DialError, Outbound] = co_await Admission->Dial(Target);
            if (Preview::Fault::Failed(DialError) || !Outbound)
            {
                Inbound->Close();
                co_return;
            }

            // TCP response: status varint, message length varint, padding
            // length varint. A missing padding-length field makes the first
            // byte of the tunneled payload look like padding to the client.
            constexpr auto SuccessResponse = MakeTcpResponseHeader();
            if (!co_await WriteAll(Inbound, SuccessResponse))
            {
                Outbound->Close();
                Inbound->Close();
                co_return;
            }
            if (Request.Consumed < Wire.size() &&
                !co_await WriteAll(
                    Outbound,
                    std::span<const std::uint8_t>(
                        Wire.data() + Request.Consumed,
                        Wire.size() - Request.Consumed)))
            {
                Outbound->Close();
                Inbound->Close();
                co_return;
            }

            Preview::Middleware::Context RelayContext;
            RelayContext.Inbound = Inbound;
            RelayContext.Outbound = std::move(Outbound);
            RelayContext.Target = std::move(Target);
            RelayContext.AccountId = Admission->AccountId;
            RelayContext.Credential = Admission->Credential;
            RelayContext.ProtocolAuthenticated = true;
            RelayContext.identity = std::to_string(Admission->AccountId.Value());
            RelayContext.traffic = Admission->Metrics.get();
            Preview::Middleware::Builtin::RelayMiddleware Relay(
                nullptr, std::chrono::milliseconds(0));
            (void)co_await Relay.Handle(RelayContext.Inbound, RelayContext);
        }

    } // namespace Detail

    [[nodiscard]] inline auto ConfigureHysteria2Server(
        Preview::Quic::ServerOptions Options,
        Hysteria2FactoryOptions FactoryOptions) -> Preview::Quic::ServerOptions
    {
        Options.ExpectedAlpn = FactoryOptions.Alpn;
        const auto Executor = Options.Executor;
        const auto Config = std::make_shared<Preview::Hysteria2::ServerConfig>(
            std::move(FactoryOptions.Config));
        const auto Authenticate = std::move(FactoryOptions.Authenticate);
        const auto RawStream = std::move(FactoryOptions.RawStream);
        const auto OnClosed = std::move(FactoryOptions.OnClosed);
        const auto SessionOwner =
            std::make_shared<std::shared_ptr<Preview::Http3::NativeServerSession>>();
        const auto ServerOwner = std::make_shared<std::shared_ptr<Preview::Quic::Server>>();

        Options.OnStarted = [ServerOwner](const std::shared_ptr<Preview::Quic::Server> &Server)
        {
            *ServerOwner = Server;
        };
        Options.OnEstablished = [Executor, ServerOwner, SessionOwner, Authenticate, RawStream](
                                    std::string)
        {
            if (!*ServerOwner || *SessionOwner)
            {
                return;
            }
            Preview::Http3::NativeServerSessionOptions SessionOptions;
            SessionOptions.Executor = Executor;
            SessionOptions.Http.EnableUdp = true;
            SessionOptions.Http.authenticate = [Authenticate](
                                                    std::string_view Method,
                                                    std::string_view Path,
                                                    std::string_view Auth)
            {
                return !Authenticate || Authenticate(Method, Path, Auth);
            };
            SessionOptions.OpenUnidirectional = [Server = *ServerOwner]()
                -> Net::awaitable<Preview::Quic::SharedStreamProvider>
            {
                co_return co_await Server->OpenUnidirectionalStream();
            };
            SessionOptions.AcceptUnidirectional = [Server = *ServerOwner]()
                -> Net::awaitable<Preview::Quic::SharedStreamProvider>
            {
                co_return co_await Server->AcceptUnidirectionalStream();
            };
            SessionOptions.AcceptBidirectional = [Server = *ServerOwner]()
                -> Net::awaitable<Preview::Quic::SharedStreamProvider>
            {
                co_return co_await Server->AcceptBidirectionalStream();
            };
            SessionOptions.OnRawStream = [RawStream](Preview::Quic::SharedStreamProvider Provider)
                -> Net::awaitable<void>
            {
                if (RawStream)
                {
                    co_await RawStream(Provider);
                }
            };
            auto Session = std::make_shared<Preview::Http3::NativeServerSession>(
                std::move(SessionOptions));
            *SessionOwner = Session;
            Net::co_spawn(
                Executor,
                [Session]() -> Net::awaitable<void>
                {
                    (void)co_await Session->Run();
                },
                Net::detached);
        };

        // NativeServerSession owns HTTP/3 stream admission after TLS. Keep the
        // legacy callback populated for API compatibility, but do not consume
        // incoming streams here or it would race the HTTP/3 session.
        Options.OnStream = [](Preview::Quic::SharedStreamProvider) {};
        Options.OnDatagram = [Config, Handler = std::move(FactoryOptions.OnDatagram)](
                                 Preview::Quic::SharedDatagramProvider Provider)
        {
            if (!Handler || !Provider)
            {
                return;
            }
            auto Datagram = Preview::Hysteria2::AcceptPacket(Provider, *Config);
            if (!Datagram)
            {
                return;
            }
            Net::co_spawn(
                Provider->Executor(),
                [Handler, Datagram = std::move(Datagram)]() mutable -> Net::awaitable<void>
                {
                    co_await Handler(std::move(Datagram));
                },
                Net::detached);
        };
        Options.OnClosed = [SessionOwner, OnClosed]()
        {
            if (*SessionOwner)
            {
                (*SessionOwner)->Close();
            }
            if (OnClosed)
            {
                OnClosed();
            }
        };
        return Options;
    }

    [[nodiscard]] inline auto ConfigureHysteria2Server(
        Preview::Quic::ServerOptions Options,
        const Preview::Ingress::SharedQuicAdmissionContext &Context)
        -> Preview::Quic::ServerOptions
    {
        if (!Context || !Context->ReadyForHysteria2())
        {
            return Options;
        }
        Options.ExpectedAlpn = Context->ExpectedAlpn;
        Options.ExpectedServerName = Context->ServerName;
        Options.MaxStreams = Context->MaxStreams;
        Options.MaxDatagrams = Context->MaxDatagrams;

        Hysteria2FactoryOptions FactoryOptions;
        FactoryOptions.Alpn = Context->ExpectedAlpn;
        FactoryOptions.Config.AuthenticatorOwner = Context->Authenticator;
        FactoryOptions.Authenticate = [Authenticator = Context->Authenticator](
                                           const std::string_view Method,
                                           const std::string_view Path,
                                           const std::string_view Auth)
        {
            if (Method != "POST" || Path != "/auth" || !Authenticator)
            {
                return false;
            }
            const auto Result = Authenticator->Authenticate(Preview::AuthenticationRequest{
                .AccountId = {},
                .Identity = {},
                .Credential = Preview::Account::CredentialView::Token(Auth),
                .Rate = {}});
            return Result.Accepted;
        };
        FactoryOptions.RawStream = [Context](Preview::Quic::SharedStreamProvider Provider)
            -> Net::awaitable<void>
        {
            co_await Detail::RunRawStream(Context, Provider);
        };
        FactoryOptions.OnStream = Context->Hysteria2Stream;
        FactoryOptions.OnDatagram = Context->Hysteria2Datagram;
        FactoryOptions.OnClosed = Context->CloseOwner;
        return ConfigureHysteria2Server(std::move(Options), std::move(FactoryOptions));
    }

} // namespace Preview::Composition::Quic
