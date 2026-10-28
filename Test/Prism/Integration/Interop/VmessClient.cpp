/**
 * @file VmessClient.cpp
 * @brief Prism VMess client 与独立 sing-vmess reference server 的真实 TCP/UDP 互操作端点。
 * @details 普通 client 请求分别验证 VMess TCP stream 和 UDP datagram；mux 请求由
 *          VmessMux.cpp 负责，server accept/echo 由 VmessServer.cpp 负责。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>

namespace
{
    namespace Net = boost::asio;

    struct Options final
    {
        std::string Address{"127.0.0.1:19083"};
        std::string Target{"example.com:443"};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        bool Invalid{false};
    };

    struct HostPort final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        if (Value.empty()) return std::nullopt;
        std::uint32_t Port = 0;
        const auto *Begin = Value.data();
        const auto *End = Begin + Value.size();
        const auto [Parsed, Error] = std::from_chars(Begin, End, Port);
        if (Error != std::errc{} || Parsed != End || Port > 65535) return std::nullopt;
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        const auto Separator = Value.find_last_of(':');
        if (Separator == std::string_view::npos || Separator == 0) return std::nullopt;
        const auto Port = ParsePort(Value.substr(Separator + 1));
        if (!Port) return std::nullopt;
        return HostPort{std::string(Value.substr(0, Separator)), *Port};
    }

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Prism::Vmess::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue) return std::nullopt;
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        const auto Type = Error ? Prism::Vmess::AddressType::Domain
                                : Address.is_v4() ? Prism::Vmess::AddressType::Ipv4
                                                  : Prism::Vmess::AddressType::Ipv6;
        return Prism::Vmess::Address{Type, HostPortValue->Host, HostPortValue->Port};
    }

    [[nodiscard]] auto ParseUuidText(std::string_view Value)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::array<std::uint8_t, 16> Result{};
        if (!Prism::Vmess::ParseUuid(Value, Result)) return std::nullopt;
        return Result;
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> Options
    {
        Options Result;
        if ((Argc - 1) % 2 != 0) { Result.Invalid = true; return Result; }
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr") Result.Address = Value;
            else if (Key == "-target") Result.Target = Value;
            else if (Key == "-uuid")
            {
                if (const auto Uuid = ParseUuidText(Value)) Result.Uuid = *Uuid;
                else Result.Invalid = true;
            }
            else Result.Invalid = true;
        }
        return Result;
    }

    struct VmessClientRequest final
    {
        Prism::Network::Dialer::Dialer &Dialer;
        Prism::Network::Target DialTarget;
        Prism::Vmess::ClientConfig Config;
        Prism::Vmess::Address Target;
    };

    [[nodiscard]] auto RunTcpClient(VmessClientRequest Request) -> Net::awaitable<int>
    {
        auto TcpDial = co_await Request.Dialer.Connect(Request.DialTarget);
        if (!TcpDial)
        {
            const auto &Failure = TcpDial.error();
            std::fprintf(stderr, "FAIL: VMess TCP dial: code=%d native=%s:%d\n",
                         static_cast<int>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
            co_return 1;
        }
        auto ConnectResult = co_await Prism::Vmess::Connect(
            Prism::Vmess::ConnectParameters{
                std::move(*TcpDial), Request.Config, Request.Target,
                Prism::Vmess::Command::Tcp});
        if (!ConnectResult)
        {
            const auto Native = Prism::Fault::ToNative(ConnectResult.error());
            std::fprintf(stderr, "FAIL: VMess TCP handshake (%u): %s\n",
                         static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Conn = std::move(*ConnectResult);
        constexpr std::string_view TcpText{"prism-vmess-external-tcp-payload"};
        const auto TcpPayload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(TcpText.data()), TcpText.size());
        std::size_t Written = 0;
        while (Written < TcpPayload.size())
        {
            const auto Window = TcpPayload.subspan(Written);
            const auto Write = co_await Conn->WriteSome(Window);
            if (Write.Bytes > Window.size())
            {
                Conn->Close();
                co_return 1;
            }
            Written += Write.Bytes;
            if (Write.Failure.Failed() || Write.Bytes == 0)
            {
                Conn->Close();
                co_return 1;
            }
        }
        std::vector<std::byte> Echo(TcpText.size());
        std::size_t Done = 0;
        while (Done < Echo.size())
        {
            const auto ReadWindow = std::span<std::byte>(Echo).subspan(Done);
            const auto Read = co_await Conn->ReadSome(ReadWindow);
            if (Read.Bytes > ReadWindow.size())
            {
                Conn->Close();
                co_return 1;
            }
            Done += Read.Bytes;
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                Conn->Close();
                co_return 1;
            }
        }
        Conn->Close();
        if (std::memcmp(Echo.data(), TcpPayload.data(), TcpPayload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: VMess TCP echo mismatch\n");
            co_return 1;
        }
        co_return 0;
    }

    [[nodiscard]] auto RunUdpClient(VmessClientRequest Request) -> Net::awaitable<int>
    {
        auto UdpDial = co_await Request.Dialer.Connect(Request.DialTarget);
        if (!UdpDial)
        {
            const auto &Failure = UdpDial.error();
            std::fprintf(stderr, "FAIL: VMess UDP dial: code=%d native=%s:%d\n",
                         static_cast<int>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
            co_return 1;
        }
        auto DatagramResult = co_await Prism::Vmess::ConnectPacket(
            std::move(*UdpDial), Request.Config, Request.Target);
        if (!DatagramResult)
        {
            const auto Native = Prism::Fault::ToNative(DatagramResult.error());
            std::fprintf(stderr, "FAIL: VMess UDP handshake (%u): %s\n",
                         static_cast<unsigned>(DatagramResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        auto Datagram = std::move(*DatagramResult);
        constexpr std::string_view UdpText{"prism-vmess-external-udp-payload"};
        const auto UdpPayload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(UdpText.data()), UdpText.size());
        if ((co_await Datagram->AsyncSendDatagram(UdpPayload)).Failure.Failed())
        {
            Datagram->Close();
            co_return 1;
        }
        std::vector<std::uint8_t> UdpEcho;
        const auto ReceiveError = co_await Datagram->AsyncReceiveDatagram(UdpEcho);
        const bool Matches = ReceiveError.Failure.Succeeded() &&
            UdpEcho.size() == UdpPayload.size() &&
            std::equal(UdpEcho.begin(), UdpEcho.end(), UdpPayload.begin());
        Datagram->Close();
        if (!Matches)
        {
            std::fprintf(stderr, "FAIL: VMess UDP echo mismatch\n");
            co_return 1;
        }
        co_return 0;
    }

    [[nodiscard]] auto RunClient(const Options &OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = MakeTarget(OptionsValue.Target);
        if (!Server || !Target)
        {
            std::fprintf(stderr, "FAIL: malformed VMess server address\n");
            co_return 2;
        }
        const auto Executor = co_await Net::this_coro::executor;
        Prism::Network::Dialer::Dialer Dialer(Executor);
        const Prism::Network::Target DialTarget{
            Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}),
            Server->Port};
        const VmessClientRequest Request{
            Dialer, DialTarget, Prism::Vmess::ClientConfig{OptionsValue.Uuid}, *Target};
        if (co_await RunTcpClient(Request) != 0 || co_await RunUdpClient(Request) != 0)
        {
            co_return 1;
        }
        std::printf("PASS: Prism VMess client -> sing-vmess reference server TCP+UDP\n");
        co_return 0;
    }

    auto ReportCompletion(const std::exception_ptr &Exception) -> void
    {
        if (!Exception) return;
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: VMess client coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: VMess client coroutine exception: unknown\n");
        }
    }
}

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported VMess client option\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [&Io, &ExitCode, OptionsValue]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunClient(OptionsValue);
        (void)Io;
    };
    Net::co_spawn(Io, Run(),
        [&Io, &ExitCode](const std::exception_ptr &Exception)
        {
            ReportCompletion(Exception);
            if (Exception) ExitCode = 1;
        });
    Io.run();
    return ExitCode;
}
