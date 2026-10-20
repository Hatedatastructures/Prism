/**
 * @file InteropVmessMux.cpp
 * @brief Prism VMess application-mux client 与独立 server 的真实互操作端点。
 * @details VMess 认证和 mux request 由本文件负责；SMUX/YAMUX/H2Mux wire、partial
 *          I/O 和 close/drain owner 由 MuxInterop.hpp 与 Trojan mux client 共享。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/this_coro.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
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
#include "MuxInterop.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Prism::Testing::Integration::Mux;
    using HostPort = Mux::HostPort;

    struct Options final
    {
        std::string Address{"127.0.0.1:19083"};
        std::string Target{"example.com:443"};
        std::string Mux{"Smux"};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        bool Invalid{false};
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
        if (Value.starts_with('['))
        {
            const auto Closing = Value.find(']');
            if (Closing == std::string_view::npos || Closing + 2 > Value.size() ||
                Value[Closing + 1] != ':') return std::nullopt;
            const auto Port = ParsePort(Value.substr(Closing + 2));
            if (!Port) return std::nullopt;
            return HostPort{std::string(Value.substr(1, Closing - 1)), *Port};
        }
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
            else if (Key == "-mux") Result.Mux = Value;
            else if (Key == "-uuid")
            {
                if (const auto Uuid = ParseUuidText(Value)) Result.Uuid = *Uuid;
                else Result.Invalid = true;
            }
            else Result.Invalid = true;
        }
        return Result;
    }

    [[nodiscard]] auto RunApplicationMux(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto TargetHost = SplitHostPort(OptionsValue.Target);
        const auto Mode = Mux::ParseMuxMode(OptionsValue.Mux);
        const auto Target = MakeTarget(OptionsValue.Target);
        if (!Server || !TargetHost || !Target || !Mode)
        {
            std::fprintf(stderr, "FAIL: VMess application-mux requires -addr -target -uuid and -mux\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        const Prism::Network::Target DialTarget{
            Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}),
            Server->Port};
        auto DialResult = co_await Dialer.Connect(DialTarget);
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: VMess application-mux TCP dial: code=%d native=%s:%d\n",
                         static_cast<int>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);
        const Prism::Vmess::ClientConfig Config{OptionsValue.Uuid};
        auto ConnectResult = co_await Prism::Vmess::Connect(
            Prism::Vmess::ConnectParameters{
                std::move(Raw), Config, *Target, Prism::Vmess::Command::Mux});
        if (!ConnectResult)
        {
            const auto Native = Prism::Fault::ToNative(ConnectResult.error());
            std::fprintf(stderr, "FAIL: VMess application-mux authentication (%u): %s\n",
                         static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Connection = std::move(*ConnectResult);

        constexpr std::string_view FirstPayload{"prism-vmess-mux-first"};
        constexpr std::string_view SecondPayload{"prism-vmess-mux-second"};
        constexpr std::string_view ContinuationPayload{"prism-vmess-mux-continuation"};
        Mux::MuxTransferRequest Request{
            *TargetHost, *Mode,
            std::vector<std::byte>(std::as_bytes(std::span(FirstPayload)).begin(),
                                   std::as_bytes(std::span(FirstPayload)).end()),
            std::vector<std::byte>(std::as_bytes(std::span(SecondPayload)).begin(),
                                   std::as_bytes(std::span(SecondPayload)).end()),
            std::vector<std::byte>(std::as_bytes(std::span(ContinuationPayload)).begin(),
                                   std::as_bytes(std::span(ContinuationPayload)).end())};
        bool Ok = false;
        try
        {
            if (*Mode == Mux::MuxMode::Smux)
                Ok = co_await Mux::RunMuxClient<Prism::Mux::Smux::Client<>>(
                    std::move(Connection), std::move(Request));
            else if (*Mode == Mux::MuxMode::Yamux)
                Ok = co_await Mux::RunMuxClient<Prism::Mux::Yamux::Client<>>(
                    std::move(Connection), std::move(Request));
            else
                Ok = co_await Mux::RunH2MuxClient(std::move(Connection), std::move(Request));
        }
        catch (...)
        {
            if (Connection)
            {
                Connection->Cancel();
                Connection->Close();
            }
            co_return 1;
        }
        if (!Ok)
        {
            std::fprintf(stderr, "FAIL: VMess application-mux %s wire/EOF\n", OptionsValue.Mux.c_str());
            co_return 1;
        }
        std::printf("PASS: Prism VMess application-mux %s two-stream payload/EOF\n",
                     OptionsValue.Mux.c_str());
        co_return 0;
    }
}

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported VMess mux option\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [OptionsValue, &ExitCode]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunApplicationMux(OptionsValue);
    };
    Net::co_spawn(Io, Run(),
        [](std::exception_ptr Exception)
        {
            if (Exception) std::fprintf(stderr, "FAIL: VMess mux coroutine exception\n");
        });
    Io.run();
    return ExitCode;
}
