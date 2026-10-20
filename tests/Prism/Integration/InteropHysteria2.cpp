/**
 * @file InteropHysteria2.cpp
 * @brief Hysteria2 互操作进程入口、命令行选项和 listener 地址解析。
 */

#include "InteropHysteria2Support.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Testing::Integration::Hysteria2::Interop
{
    namespace
    {
        [[nodiscard]] auto ParsePort(const std::string_view Value) -> std::optional<std::uint16_t>
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
    }

    [[nodiscard]] auto SplitHostPort(const std::string_view Value) -> std::optional<HostPort>
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

    [[nodiscard]] auto ParseOptions(const int Argc, char **Argv) -> std::optional<Options>
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
                Result.Udp = Value == "1";
            }
        }
        return Result;
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        if (OptionsValue.Udp)
        {
            ExitCode = co_await RunUdpServer(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunTcpServer(OptionsValue);
        }
    }
}

auto main(const int Argc, char **Argv) -> int
{
    namespace Interop = Prism::Testing::Integration::Hysteria2::Interop;
    const auto Options = Interop::ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed Hysteria2 options\n");
        return 2;
    }
    Interop::Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Interop::Net::co_spawn(Io, Interop::RunInterop(*Options, ExitCode),
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
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
