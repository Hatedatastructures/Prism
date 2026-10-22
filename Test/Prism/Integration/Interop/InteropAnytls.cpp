/**
 * @file InteropAnytls.cpp
 * @brief Prism AnyTLS 与独立 Go reference 的双向 TCP 互操作端点
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Anytls/Frame.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Tcp = Net::ip::tcp;

    constexpr std::string_view Payload{"prism-anytls-external-interop-payload"};

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19094"};
        std::string Target;
        std::string Password{"anytls_password"};
        std::string ServerName{"www.cloudflare.com"};
        std::uint8_t SettingsVersion{2};
        bool TlsVerify{false};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        if (Value.empty())
        {
            return std::nullopt;
        }
        std::uint32_t Port = 0;
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

    [[nodiscard]] auto ParseBoolean(std::string_view Value) -> std::optional<bool>
    {
        if (Value == "true" || Value == "1")
        {
            return true;
        }
        if (Value == "false" || Value == "0")
        {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        if ((Argc - 1) % 2 != 0)
        {
            return std::nullopt;
        }
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-mode")
            {
                Result.Mode = Value;
            }
            else if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-target")
            {
                Result.Target = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-server-name")
            {
                Result.ServerName = Value;
            }
            else if (Key == "-settings-version")
            {
                const auto Version = ParsePort(Value);
                if (!Version || (*Version != 1U && *Version != 2U))
                {
                    return std::nullopt;
                }
                Result.SettingsVersion = static_cast<std::uint8_t>(*Version);
            }
            else if (Key == "-tlsverify")
            {
                const auto Parsed = ParseBoolean(Value);
                if (!Parsed)
                {
                    return std::nullopt;
                }
                Result.TlsVerify = *Parsed;
            }
            else
            {
                return std::nullopt;
            }
        }
        return Result;
    }

    [[nodiscard]] auto ConnectNativeTls(Prism::SharedTransmission Raw,
                                         Ssl::context &Tls,
                                         std::string_view ServerName)
        -> Net::awaitable<Prism::SharedTransmission>
    {
        if (!Raw)
        {
            co_return nullptr;
        }
        Prism::Transport::Connector Connector(std::move(Raw));
        auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
            std::move(Connector), Tls);
        if (!ServerName.empty())
        {
            const auto Name = std::string(ServerName);
            if (SSL_set_tlsext_host_name(Stream->native_handle(), Name.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                if (Recovered)
                {
                    (void)Recovered->Close();
                }
                co_return nullptr;
            }
        }
        constexpr unsigned char Alpn[] = {2U, 'h', '2'};
        if (SSL_set_alpn_protos(Stream->native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                (void)Recovered->Close();
            }
            co_return nullptr;
        }

        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto Handshake = [Stream]() -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code Error;
            co_await Stream->async_handshake(Ssl::stream_base::client,
                                             Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        };
        const auto Result = co_await (Handshake() || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1 || std::get<0>(Result))
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                (void)Recovered->Cancel();
                (void)Recovered->Close();
            }
            co_return nullptr;
        }
        auto BytePool = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8U});
        co_return std::make_shared<Prism::Transport::Encrypted>(
            std::move(Stream), std::move(BytePool));
    }

    [[nodiscard]] auto WriteAll(const Prism::SharedTransmission &Transport,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Written = co_await Transport->WriteSome(Data.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto ReadLiteralExact(const Prism::SharedTransmission &Transport,
                                        std::span<std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Read = co_await Transport->ReadSome(Data.subspan(Offset));
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Read.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto SendFrame(const Prism::SharedTransmission &Transport,
                                 Prism::Anytls::Frame Value) -> Net::awaitable<bool>
    {
        const auto Wire = Prism::Anytls::Encode(std::move(Value));
        if (Wire.empty())
        {
            co_return false;
        }
        co_return co_await WriteAll(Transport, Wire);
    }

    [[nodiscard]] auto MakeTargetPayload(const HostPort &Target,
                                         std::string_view Tail) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(Target.Host, Error);
        if (!Error && Address.is_v4())
        {
            Result.push_back(std::byte{1});
            for (const auto Byte : Address.to_v4().to_bytes())
            {
                Result.push_back(std::byte{Byte});
            }
        }
        else if (!Error && Address.is_v6())
        {
            Result.push_back(std::byte{4});
            for (const auto Byte : Address.to_v6().to_bytes())
            {
                Result.push_back(std::byte{Byte});
            }
        }
        else if (!Target.Host.empty() && Target.Host.size() <= 255U)
        {
            Result.push_back(std::byte{3});
            Result.push_back(std::byte{static_cast<unsigned char>(Target.Host.size())});
            for (const auto Byte : Target.Host)
            {
                Result.push_back(std::byte{static_cast<unsigned char>(Byte)});
            }
        }
        else
        {
            return {};
        }
        Result.push_back(std::byte{static_cast<unsigned char>(Target.Port >> 8U)});
        Result.push_back(std::byte{static_cast<unsigned char>(Target.Port)});
        const auto Bytes = std::as_bytes(std::span(Tail));
        Result.insert(Result.end(), Bytes.begin(), Bytes.end());
        return Result;
    }

    [[nodiscard]] auto ReadStreamEcho(Prism::Anytls::FrameReader &Reader,
                                      std::uint32_t StreamId,
                                      bool RequireSynAck) -> Net::awaitable<bool>
    {
        bool SynAck = !RequireSynAck;
        std::size_t ReceivedBytes = 0;
        const auto Expected = std::as_bytes(std::span(Payload));
        for (int Attempt = 0; Attempt < 16 && ReceivedBytes < Expected.size(); ++Attempt)
        {
            const auto Frame = co_await Reader.Read();
            if (!Frame)
            {
                co_return false;
            }
            if (Frame->Kind == Prism::Anytls::Command::Alert ||
                (Frame->Kind == Prism::Anytls::Command::Fin && Frame->StreamId == StreamId))
            {
                co_return false;
            }
            if (Frame->Kind == Prism::Anytls::Command::SynAck && Frame->StreamId == StreamId)
            {
                if (!Frame->Payload.empty())
                {
                    co_return false;
                }
                SynAck = true;
            }
            if (Frame->Kind == Prism::Anytls::Command::Push && Frame->StreamId == StreamId)
            {
                if (Frame->Payload.size() > Expected.size() - ReceivedBytes ||
                    !std::equal(Frame->Payload.begin(), Frame->Payload.end(),
                                Expected.begin() + static_cast<std::ptrdiff_t>(ReceivedBytes)))
                {
                    co_return false;
                }
                ReceivedBytes += Frame->Payload.size();
            }
        }
        co_return SynAck && ReceivedBytes == Expected.size();
    }

    [[nodiscard]] auto ReadServerSettings(Prism::Anytls::FrameReader &Reader)
        -> Net::awaitable<bool>
    {
        for (int Attempt = 0; Attempt < 8; ++Attempt)
        {
            const auto Frame = co_await Reader.Read();
            if (!Frame)
            {
                co_return false;
            }
            if (Frame->Kind == Prism::Anytls::Command::ServerSettings && Frame->StreamId == 0)
            {
                co_return true;
            }
            if (Frame->Kind == Prism::Anytls::Command::Alert)
            {
                co_return false;
            }
        }
        co_return false;
    }

    [[nodiscard]] auto ReadUntilPeerEof(Prism::Anytls::FrameReader &Reader)
        -> Net::awaitable<bool>
    {
        for (;;)
        {
            const auto Frame = co_await Reader.Read();
            if (!Frame)
            {
                co_return Frame.error() == Prism::Error::UnexpectedEof;
            }
        }
    }

    [[nodiscard]] auto WaitForPeerEof(const Prism::SharedTransmission &Transport,
                                      Prism::Anytls::FrameReader &Reader)
        -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Deadline(Transport->Executor());
        Deadline.expires_after(std::chrono::seconds(5));
        const auto Result = co_await (ReadUntilPeerEof(Reader) ||
                                     Deadline.async_wait(Net::use_awaitable));
        co_return Result.index() == 0 && std::get<0>(Result);
    }

    [[nodiscard]] auto RunApplicationSession(
        const Prism::SharedTransmission& Transport,
        const Options& OptionsValue,
        const HostPort& Target) -> Net::awaitable<int>
    {
        Prism::Anytls::FrameReader FrameReader(Transport);

        std::string Auth;
        if (Prism::Anytls::BuildAuthFrame(OptionsValue.Password, 0, Auth) != Prism::Error::None ||
            !co_await WriteAll(Transport, std::as_bytes(std::span(Auth))))
        {
            (void)Transport->Close();
            std::fprintf(stderr, "FAIL: AnyTLS application authentication write\n");
            co_return 1;
        }
        std::printf("PHASE: AnyTLSAuthSent\n");
        std::fflush(stdout);
        const auto Settings = std::string("v=") + std::to_string(OptionsValue.SettingsVersion) +
                              "\nclient=interop-011a\n";
        const auto SettingsBytes = std::as_bytes(std::span(Settings));
        if (!co_await SendFrame(Transport, {Prism::Anytls::Command::Settings, 0,
                                            std::vector<std::byte>(SettingsBytes.begin(), SettingsBytes.end())}) ||
            (OptionsValue.SettingsVersion >= 2 && !co_await ReadServerSettings(FrameReader)))
        {
            (void)Transport->Close();
            std::fprintf(stderr, "FAIL: AnyTLS application SETTINGS exchange\n");
            co_return 1;
        }

        const auto FirstTarget = MakeTargetPayload(Target, Payload);
        if (FirstTarget.empty() ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Syn, 1, {}}) ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Push, 1, FirstTarget}) ||
            !co_await ReadStreamEcho(FrameReader, 1, OptionsValue.SettingsVersion >= 2))
        {
            (void)Transport->Close();
            std::fprintf(stderr, "FAIL: AnyTLS application stream 1\n");
            co_return 1;
        }

        const auto SecondTarget = MakeTargetPayload(Target, Payload);
        const auto PayloadBytes = std::as_bytes(std::span(Payload));
        if (SecondTarget.empty() ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Syn, 3, {}}) ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Push, 3, SecondTarget}) ||
            !co_await ReadStreamEcho(FrameReader, 3, OptionsValue.SettingsVersion >= 2) ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Fin, 1, {}}) ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Push, 3,
                                            std::vector<std::byte>(PayloadBytes.begin(), PayloadBytes.end())}) ||
            !co_await ReadStreamEcho(FrameReader, 3, false) ||
            !co_await SendFrame(Transport, {Prism::Anytls::Command::Fin, 3, {}}))
        {
            (void)Transport->Close();
            std::fprintf(stderr, "FAIL: AnyTLS application stream sibling/FIN\n");
            co_return 1;
        }
        const auto Shutdown = co_await Transport->WriteShutdown();
        const bool ShutdownAccepted = Shutdown.has_value();
        if (!ShutdownAccepted)
        {
            const auto &Failure = Shutdown.error();
            std::fprintf(stderr,
                         "FAIL: AnyTLS application write half-close Code=%u Native=%s:%d\n",
                         static_cast<unsigned>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
        }
        if (!co_await WaitForPeerEof(Transport, FrameReader))
        {
            const auto Closed = Transport->Close();
            if (!Closed.has_value())
            {
                const auto &Failure = Closed.error();
                std::fprintf(stderr,
                             "FAIL: AnyTLS application close after peer EOF wait Code=%u Native=%s:%d\n",
                             static_cast<unsigned>(Failure.Code), Failure.Native.category().name(),
                             Failure.Native.value());
            }
            std::fprintf(stderr, "FAIL: AnyTLS application peer EOF\n");
            co_return 1;
        }
        std::printf("PHASE: PeerEof\n");
        std::fflush(stdout);
        const auto FirstClose = Transport->Close();
        const bool FirstCloseAccepted = FirstClose.has_value();
        if (!FirstCloseAccepted)
        {
            const auto &Failure = FirstClose.error();
            std::fprintf(stderr, "FAIL: AnyTLS application first close Code=%u Native=%s:%d\n",
                         static_cast<unsigned>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
        }
        const auto SecondClose = Transport->Close();
        const bool SecondCloseAccepted = SecondClose.has_value();
        if (!SecondCloseAccepted)
        {
            const auto &Failure = SecondClose.error();
            std::fprintf(stderr, "FAIL: AnyTLS application repeated close Code=%u Native=%s:%d\n",
                         static_cast<unsigned>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
        }
        if (!ShutdownAccepted || !FirstCloseAccepted || !SecondCloseAccepted)
        {
            co_return 1;
        }
        std::printf("PASS: Prism Native TLS + AnyTLS application v%u streams (%zu bytes each)\n",
                     static_cast<unsigned>(OptionsValue.SettingsVersion), Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunApplicationClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = SplitHostPort(OptionsValue.Target);
        if (!Server || !Target)
        {
            std::fprintf(stderr, "FAIL: application mode requires -addr and -target host:port\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: AnyTLS application TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);

        Ssl::context Tls(Ssl::context::tlsv13_client);
        if (OptionsValue.TlsVerify)
        {
            Tls.set_default_verify_paths();
            Tls.set_verify_mode(Ssl::verify_peer);
        }
        else
        {
            Tls.set_verify_mode(Ssl::verify_none);
        }
        auto Transport = co_await ConnectNativeTls(std::move(Raw), Tls, OptionsValue.ServerName);
        if (!Transport)
        {
            std::fprintf(stderr, "FAIL: AnyTLS application Native TLS handshake\n");
            co_return 1;
        }
        std::printf("PHASE: NativeTlsOK\n");
        std::fflush(stdout);
        co_return co_await RunApplicationSession(Transport, OptionsValue, *Target);
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed AnyTLS server address\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: AnyTLS TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);
        auto Connected = co_await Prism::Anytls::Connect(
            std::move(Raw), Prism::Anytls::ClientConfig{OptionsValue.Password});
        if (!Connected)
        {
            const auto Failure = Connected.error();
            std::fprintf(stderr, "FAIL: AnyTLS client handshake (%u)\n",
                         static_cast<unsigned>(Failure.Code));
            co_return 1;
        }
        auto Conn = std::move(*Connected);
        auto &Carrier = static_cast<Prism::Transmission &>(*Conn);
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Carrier.WriteExact(Bytes);
        if (Written.Failure.Failed() || Written.Bytes != Bytes.size())
        {
            (void)Conn->Close();
            std::fprintf(stderr, "FAIL: AnyTLS client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Carrier.ReadExact(Echo);
        (void)Conn->Close();
        if (Read.Failure.Failed() || Read.Bytes != Bytes.size() ||
            std::memcmp(Echo.data(), Bytes.data(), Bytes.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: AnyTLS external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Prism AnyTLS client -> Go reference server (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed AnyTLS listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: AnyTLS listen address is not an IP literal\n");
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v4();
        if (!Address.is_v4())
        {
            Protocol = Tcp::v6();
        }
        Acceptor.open(Protocol, Error);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: AnyTLS listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Prism AnyTLS server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        auto Accepted = co_await Prism::Anytls::Accept(
            std::move(Raw), Prism::Anytls::ServerConfig{OptionsValue.Password});
        if (!Accepted)
        {
            const auto Failure = Accepted.error();
            std::fprintf(stderr, "FAIL: AnyTLS server handshake (%u)\n",
                         static_cast<unsigned>(Failure.Code));
            co_return 1;
        }
        auto Conn = std::move(*Accepted);
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await ReadLiteralExact(Conn, Buffer) || !co_await WriteAll(Conn, Buffer))
        {
            (void)Conn->Close();
            std::fprintf(stderr, "FAIL: AnyTLS server echo\n");
            co_return 1;
        }
        (void)Conn->Close();
        std::printf("PASS: Prism AnyTLS server echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    auto RunMode(Net::io_context &Io, int &ExitCode, Options OptionsValue) -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "server")
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
        else if (OptionsValue.Mode == "application")
        {
            ExitCode = co_await RunApplicationClient(OptionsValue);
        }
        else if (OptionsValue.Mode == "client")
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
        else
        {
            std::fprintf(stderr, "FAIL: unsupported AnyTLS mode '%s'\n", OptionsValue.Mode.c_str());
            ExitCode = 2;
        }
        if (OptionsValue.Mode != "application")
        {
            Io.stop();
        }
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed AnyTLS options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    const bool NaturalApplicationCompletion = Options->Mode == "application";
    auto OnComplete = [&Io, &Failure, NaturalApplicationCompletion](std::exception_ptr Exception) -> void
    {
        Failure = std::move(Exception);
        if (Failure || !NaturalApplicationCompletion)
        {
            Io.stop();
        }
    };
    Net::co_spawn(Io, RunMode(Io, ExitCode, *Options), std::move(OnComplete));
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: AnyTLS interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: AnyTLS interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
