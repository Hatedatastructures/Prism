/**
 * @file InteropTrojanClient.cpp
 * @brief Prism Trojan 普通 TCP client 与独立 Go reference server 的真实互操作端点。
 * @details 只拥有 client 认证、payload echo、半关闭后的最终 close；application-mux
 *          请求由 InteropTrojanMux.cpp 独立负责，server 由 InteropTrojanServer.cpp 负责。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/this_coro.hpp>

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

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>

namespace
{
    namespace Net = boost::asio;

    struct Options final
    {
        std::string Address{"127.0.0.1:19081"};
        std::string Password{"prism"};
        std::string Target{"example.com:443"};
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
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        const auto Type = Error ? Prism::Trojan::AddressType::Domain
                                : Address.is_v4() ? Prism::Trojan::AddressType::Ipv4
                                                  : Prism::Trojan::AddressType::Ipv6;
        return Prism::Trojan::Address{Type, HostPortValue->Host, HostPortValue->Port};
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
            else Result.Invalid = true;
        }
        return Result;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = MakeTarget(OptionsValue.Target);
        if (!Server || !Target)
        {
            std::fprintf(stderr, "FAIL: malformed server or target address\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect(Prism::Network::Target{
            Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto Native = Prism::Fault::ToNative(DialResult.error());
            std::fprintf(stderr, "FAIL: TCP dial: %s\n", Native.message().c_str());
            co_return 1;
        }
        const Prism::Trojan::ClientConfig Config{OptionsValue.Password};
        auto ConnectResult = co_await Prism::Trojan::Connect(
            Prism::Trojan::ConnectParameters{std::move(*DialResult), Config, *Target});
        if (!ConnectResult)
        {
            const auto Native = Prism::Fault::ToNative(ConnectResult.error());
            std::fprintf(stderr, "FAIL: Trojan client handshake (%u): %s\n",
                         static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Conn = std::move(*ConnectResult);
        constexpr std::string_view Payload{"prism-trojan-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Conn->WriteExact(PayloadBytes);
        if (Written.Failure.Failed() || Written.Bytes != PayloadBytes.size())
        {
            const auto Close = Conn->Close();
            const auto Drain = co_await Conn->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: Trojan close drain\n");
            std::fprintf(stderr, "FAIL: Trojan client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Conn->ReadExact(std::span<std::byte>(Echo));
        const auto Close = Conn->Close();
        const auto Drain = co_await Conn->Activity()->Drain();
        if (!Close || !Drain || Read.Failure.Failed() || Read.Bytes != Payload.size() ||
            std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: Trojan external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Prism Trojan client -> Go reference server\n");
        co_return 0;
    }
}

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported Trojan client option\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [OptionsValue, &ExitCode]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunClient(OptionsValue);
    };
    Net::co_spawn(Io, Run(),
        [](std::exception_ptr Exception)
        {
            if (Exception) std::fprintf(stderr, "FAIL: Trojan client coroutine exception\n");
        });
    Io.run();
    return ExitCode;
}
