/**
 * @file InteropTuic.cpp
 * @brief Prism TUIC v5 client 与独立 reference 的 TCP/UDP 互操作端点
 * @details 使用 Prism 原生 QUIC 的单向认证流、bidi Connect 流、DATAGRAM
 *          packet 和 TLS exporter，覆盖客户端方向。
 * @note standalone Native harness；不启动 Prism::Application，不能作为
 *       Application ingress 路径的互操作证据。
 */

#include "InteropTuicOptions.hpp"
#include "InteropTuicLifecycle.hpp"
#include "InteropTuicTerminalIo.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>

#include <boost/system/error_code.hpp>

#include <openssl/ssl.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>

namespace Prism::Testing::TuicInterop
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Udp = Net::ip::udp;

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

    [[nodiscard]] auto Hex(std::uint8_t Value) noexcept -> std::optional<std::uint8_t>
    {
        if (Value >= '0' && Value <= '9')
        {
            return static_cast<std::uint8_t>(Value - '0');
        }
        if (Value >= 'a' && Value <= 'f')
        {
            return static_cast<std::uint8_t>(Value - 'a' + 10);
        }
        if (Value >= 'A' && Value <= 'F')
        {
            return static_cast<std::uint8_t>(Value - 'A' + 10);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto ParseUuid(std::string_view Value) -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::array<std::uint8_t, 16> Result{};
        std::size_t Offset = 0;
        bool High = true;
        std::uint8_t Nibble = 0;
        for (const auto Character : Value)
        {
            if (Character == '-')
            {
                continue;
            }
            const auto Digit = Hex(static_cast<std::uint8_t>(Character));
            if (!Digit || Offset >= Result.size())
            {
                return std::nullopt;
            }
            if (High)
            {
                Nibble = static_cast<std::uint8_t>(*Digit << 4);
                High = false;
            }
            else
            {
                Result[Offset++] = static_cast<std::uint8_t>(Nibble | *Digit);
                High = true;
            }
        }
        if (Offset != Result.size() || !High)
        {
            return std::nullopt;
        }
        return Result;
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
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
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-udp")
            {
                Result.Udp = Value == "1" || Value == "true";
            }
            else if (Key == "-uuid")
            {
                const auto Uuid = ParseUuid(Value);
                if (!Uuid)
                {
                    return std::nullopt;
                }
                Result.Uuid = *Uuid;
            }
        }
        return Result;
    }

    [[nodiscard]] auto WriteAll(const Prism::Tuic::SharedConn &Conn,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        auto &Carrier = static_cast<Prism::Transmission &>(*Conn);
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Written = co_await Carrier.WriteSome(Data.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    using DrainResult = std::expected<void, Prism::Fault::Failure>;

    auto PreserveDrainFailure(DrainResult &FirstFailure, DrainResult Candidate) -> void
    {
        if (!Candidate && FirstFailure)
        {
            FirstFailure = std::unexpected(Candidate.error());
        }
    }

    /** @brief 关闭 TUIC datagram 装饰器，并等待 Dgram 与 QUIC adapter 的活动退栈。 */
    auto CloseAndDrainTuicDgram(const Prism::Tuic::SharedDgram &Datagram)
        -> Net::awaitable<DrainResult>
    {
        if (!Datagram)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Underlying = Datagram->Stream();
        const auto Closed = Datagram->Close();
        DrainResult FirstFailure{};
        if (!Closed)
        {
            PreserveDrainFailure(FirstFailure, std::unexpected(Closed.error()));
        }

        const std::array<Prism::SharedTransmission, 2> Chain{
            std::static_pointer_cast<Prism::Transmission>(Datagram),
            Underlying};
        for (std::size_t Index = 0; Index < Chain.size(); ++Index)
        {
            const auto &Carrier = Chain[Index];
            if (!Carrier || (Index != 0 && Carrier == Chain[0]))
            {
                continue;
            }
            const auto Activity = Carrier->Activity();
            if (!Activity)
            {
                PreserveDrainFailure(FirstFailure, std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
                continue;
            }
            PreserveDrainFailure(FirstFailure, co_await Activity->Drain());
        }
        co_return FirstFailure;
    }

    /** @brief 关闭 QUIC 客户端并等待 Native connection owner 退栈。 */
    auto CloseAndDrainTuicClient(
        const std::shared_ptr<Prism::Quic::Client> &Connection)
        -> Net::awaitable<DrainResult>
    {
        if (!Connection)
        {
            co_return DrainResult{};
        }
        Connection->Close();
        co_return co_await Connection->Drain();
    }

    struct ClientContext final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Quic::Client> Connection;
        Prism::Tuic::ClientConfig Config;
    };

    auto RunTcpClient(ClientContext &Context) -> Net::awaitable<bool>
    {
        auto DataProviderResult = co_await Context.Connection->OpenBidirectionalStream();
        if (!DataProviderResult)
        {
            std::fprintf(stderr, "FAIL: TUIC data stream\n");
            co_return false;
        }
        auto DataProvider = std::move(*DataProviderResult);
        auto DataStream = std::make_shared<Prism::Quic::StreamAdapter>(
            Context.Executor, DataProvider);
        const Prism::Tuic::Address Target{
            Prism::Tuic::AddressType::Domain, "example.com", 443};
        auto [HandshakeError, Conn] = co_await Prism::Tuic::Connect(
            DataStream, Context.Config, Target);
        if (HandshakeError != Prism::Error::None || !Conn)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP handshake (%u)\n",
                         static_cast<unsigned>(HandshakeError));
            const auto Drained = co_await Detail::CloseAndDrainStreamChain(
                DataStream, Prism::SharedTransmission{});
            if (!Drained)
            {
                std::fprintf(stderr, "FAIL: TUIC data stream drain after handshake failure\n");
            }
            co_return false;
        }
        auto &Carrier = static_cast<Prism::Transmission &>(*Conn);
        constexpr std::string_view Text{"prism-tuic-external-tcp-payload"};
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Text.data()), Text.size());
        bool Succeeded = co_await WriteAll(Conn, Payload);
        if (!Succeeded)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP client write payload\n");
        }
        if (Succeeded)
        {
            const auto Shutdown = co_await Conn->WriteShutdown();
            Succeeded = static_cast<bool>(Shutdown);
            if (!Succeeded)
            {
                std::fprintf(stderr, "FAIL: TUIC TCP client write half-close\n");
            }
        }
        std::vector<std::byte> Echo(Text.size());
        if (Succeeded)
        {
            const auto ReadResult = co_await Detail::ReadExpectedPayload(
                Carrier, std::span<std::byte>(Echo));
            Succeeded = ReadResult && ReadResult->Bytes == Echo.size();
            if (!Succeeded)
            {
                std::fprintf(stderr, "FAIL: TUIC TCP client echo read\n");
            }
        }
        const auto Drained = co_await Detail::CloseAndDrainTuicConnection(Conn);
        if (!Drained)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP stream activity drain\n");
            Succeeded = false;
        }
        if (Succeeded && std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP echo mismatch\n");
            Succeeded = false;
        }
        co_return Succeeded;
    }

    auto RunUdpClient(ClientContext &Context) -> Net::awaitable<bool>
    {
        auto DatagramResult = Prism::Tuic::ConnectPacket(
            Context.Connection->Datagram(), Context.Config);
        if (!DatagramResult)
        {
            std::fprintf(stderr, "FAIL: TUIC UDP datagram provider\n");
            co_return false;
        }
        auto Datagram = std::move(*DatagramResult);
        const std::string Text{"prism-tuic-external-udp-payload"};
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
        const Prism::Tuic::Address Target{
            Prism::Tuic::AddressType::Ipv4, "127.0.0.1", 53};
        const auto SendError = co_await Datagram->AsyncSendTo(Target, Payload);
        bool Valid = SendError == Prism::Error::None;
        Prism::Tuic::Address EchoTarget;
        std::vector<std::uint8_t> Echo;
        if (Valid)
        {
            const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(EchoTarget, Echo);
            Valid = ReceiveError == Prism::Error::None &&
                    Echo.size() == Payload.size() &&
                    std::equal(Echo.begin(), Echo.end(), Payload.begin());
        }
        const auto Closed = co_await CloseAndDrainTuicDgram(Datagram);
        Valid = Valid && static_cast<bool>(Closed);
        if (!Valid)
        {
            std::fprintf(stderr, "FAIL: TUIC UDP echo mismatch\n");
            co_return false;
        }
        co_return true;
    }

    auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Remote = SplitHostPort(OptionsValue.Address);
        if (!Remote)
        {
            std::fprintf(stderr, "FAIL: malformed TUIC reference address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Remote->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: TUIC reference address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
        Tls->set_verify_mode(Ssl::verify_none);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        if (SSL_CTX_set_alpn_protos(Tls->native_handle(), H3Alpn, sizeof(H3Alpn)) != 0)
        {
            std::fprintf(stderr, "FAIL: cannot configure TUIC ALPN\n");
            co_return 1;
        }
        const auto Executor = co_await Net::this_coro::executor;
        auto Connection = std::make_shared<Prism::Quic::Client>(
            Prism::Quic::ClientOptions{
                Executor, std::make_shared<Udp::socket>(Executor, Udp::endpoint(Udp::v4(), 0)),
                Udp::endpoint(Address, Remote->Port), Tls, "tuic"});
        Connection->Start();
        if (!co_await Connection->WaitHandshake())
        {
            const auto Closed = co_await CloseAndDrainTuicClient(Connection);
            if (!Closed)
            {
                std::fprintf(stderr, "FAIL: TUIC QUIC drain after handshake failure\n");
            }
            std::fprintf(stderr, "FAIL: TUIC QUIC handshake\n");
            co_return 1;
        }
        auto AuthProviderResult = co_await Connection->OpenUnidirectionalStream();
        if (!AuthProviderResult)
        {
            const auto Closed = co_await CloseAndDrainTuicClient(Connection);
            if (!Closed)
            {
                std::fprintf(stderr, "FAIL: TUIC QUIC drain after auth stream failure\n");
            }
            std::fprintf(stderr, "FAIL: TUIC auth stream\n");
            co_return 1;
        }
        auto AuthProvider = std::move(*AuthProviderResult);
        auto AuthStream = std::make_shared<Prism::Quic::StreamAdapter>(Executor, AuthProvider);
        const auto Exporter = [Connection](std::span<std::uint8_t> Output,
                                            std::span<const std::uint8_t> Label,
                                            std::string_view Context)
        {
            return Connection->ExportKeyingMaterial(Output, Label, Context);
        };
        ClientContext Context{Executor, Connection, {}};
        Context.Config.uuid = OptionsValue.Uuid;
        Context.Config.password = OptionsValue.Password;
        Context.Config.AuthStream = AuthStream;
        Context.Config.Exporter = Exporter;
        bool Succeeded = false;
        if (OptionsValue.Udp)
        {
            auto AuthOnly = std::make_shared<Prism::Tuic::Conn<>>(
                AuthStream, Context.Config.uuid);
            const auto AuthError = co_await AuthOnly->WriteAuthentication(
                Context.Config.AuthStream, Context.Config.Exporter, Context.Config.password);
            if (AuthError != Prism::Error::None)
            {
                const auto Closed = co_await CloseAndDrainTuicClient(Connection);
                if (!Closed)
                {
                    std::fprintf(stderr, "FAIL: TUIC QUIC drain after UDP auth failure\n");
                }
                std::fprintf(stderr, "FAIL: TUIC UDP authentication (%u)\n",
                             static_cast<unsigned>(AuthError));
                co_return 1;
            }
            Succeeded = co_await RunUdpClient(Context);
        }
        else
        {
            Succeeded = co_await RunTcpClient(Context);
        }
        const auto Closed = co_await CloseAndDrainTuicClient(Connection);
        if (!Succeeded || !Closed)
        {
            if (!Succeeded)
            {
                std::fprintf(stderr, "FAIL: TUIC %s endpoint\n",
                             OptionsValue.Udp ? "UDP" : "TCP");
            }
            co_return 1;
        }
        std::printf("PASS: Prism TUIC client -> reference server %s\n",
                    OptionsValue.Udp ? "UDP" : "TCP");
        co_return 0;
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "client")
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
    }

} // namespace Prism::Testing::TuicInterop

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = Prism::Testing::TuicInterop::ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed TUIC options\n");
        return 2;
    }
    boost::asio::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    boost::asio::co_spawn(Io, Prism::Testing::TuicInterop::RunInterop(*Options, ExitCode),
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
            std::fprintf(stderr, "FAIL: TUIC interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: TUIC interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
