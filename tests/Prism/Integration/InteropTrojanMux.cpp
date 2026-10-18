/**
 * @file InteropTrojanMux.cpp
 * @brief Prism Trojan application-mux client 与独立 server 的真实互操作端点。
 * @details 认证与 mux 请求由本文件负责；mux frame、partial I/O 和 close/drain
 *          owner 由 MuxInterop.hpp 与 VMess mux client 共享。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/this_coro.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include "MuxInterop.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Prism::Testing::Integration::Mux;
    using HostPort = Mux::HostPort;

    struct Options final
    {
        std::string Address{"127.0.0.1:19081"};
        std::string Password{"prism"};
        std::string Target{"example.com:443"};
        std::string MuxMode{"Smux"};
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

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Prism::Trojan::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue) return std::nullopt;
        return Prism::Trojan::Address{
            Prism::Trojan::AddressType::Domain, HostPortValue->Host, HostPortValue->Port};
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
            else if (Key == "-password") Result.Password = Value;
            else if (Key == "-target") Result.Target = Value;
            else if (Key == "-mux") Result.MuxMode = Value;
            else Result.Invalid = true;
        }
        return Result;
    }

    [[nodiscard]] auto RunApplicationMux(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = SplitHostPort(OptionsValue.Target);
        const auto Mode = Mux::ParseMuxMode(OptionsValue.MuxMode);
        if (!Server || !Target || !Mode)
        {
            std::fprintf(stderr, "FAIL: Trojan mux requires -addr -target and -mux Smux|Yamux|H2Mux\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto Dialed = co_await Dialer.Connect({Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}), Server->Port});
        if (!Dialed)
        {
            const auto DialError = Prism::Fault::ToNative(Dialed.error());
            std::fprintf(stderr, "FAIL: Trojan application-mux TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        auto Raw = std::move(*Dialed);
        const Prism::Trojan::ClientConfig Config{OptionsValue.Password};
        const auto WireTarget = Prism::Trojan::Address{
            Prism::Trojan::AddressType::Domain, Target->Host, Target->Port};
        auto ConnectResult = co_await Prism::Trojan::Connect(
            Prism::Trojan::ConnectParameters{
                std::move(Raw), Config, WireTarget, Prism::Trojan::Command::Mux});
        if (!ConnectResult)
        {
            const auto Native = Prism::Fault::ToNative(ConnectResult.error());
            std::fprintf(stderr, "FAIL: Trojan application-mux authentication (%u): %s\n",
                         static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Connection = std::move(*ConnectResult);

        constexpr std::string_view FirstPayload{"prism-trojan-mux-first"};
        constexpr std::string_view SecondPayload{"prism-trojan-mux-second"};
        constexpr std::string_view ContinuationPayload{"prism-trojan-mux-continuation"};
        Mux::MuxTransferRequest Request{
            *Target, *Mode,
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
            std::fprintf(stderr, "FAIL: Trojan application-mux %s wire/EOF\n",
                         OptionsValue.MuxMode.c_str());
            co_return 1;
        }
        std::printf("PASS: Prism Trojan application-mux %s two-stream payload/EOF\n",
                     OptionsValue.MuxMode.c_str());
        co_return 0;
    }
}

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported Trojan mux option\n");
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
            if (Exception) std::fprintf(stderr, "FAIL: Trojan mux coroutine exception\n");
        });
    Io.run();
    return ExitCode;
}
