/**
 * @file InteropTrojanServer.cpp
 * @brief Prism Trojan 服务端与独立 Go reference client 的真实 TCP 互操作端点。
 * @details 只拥有 server accept、认证、echo 和最终 close；客户端与 mux 请求由
 *          独立 integration target 负责，避免测试进程混合两套关闭责任。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <charconv>
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

#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options final
    {
        std::string Address{"127.0.0.1:19081"};
        std::string Password{"prism"};
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
            else Result.Invalid = true;
        }
        return Result;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket, const Options &OptionsValue)
        -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const Prism::Trojan::ServerConfig Config{OptionsValue.Password, true, false, false};
        auto AcceptResult = co_await Prism::Trojan::Accept(Raw, Config);
        if (!AcceptResult)
        {
            const auto Native = Prism::Fault::ToNative(AcceptResult.error());
            const auto Close = Raw->Close();
            const auto Drain = co_await Raw->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: Trojan reject close drain\n");
            std::fprintf(stderr, "FAIL: Trojan server handshake (%u): %s\n",
                         static_cast<unsigned>(AcceptResult.error().Code), Native.message().c_str());
            co_return false;
        }
        if (!AcceptResult->Connection)
        {
            const auto Close = Raw->Close();
            const auto Drain = co_await Raw->Activity()->Drain();
            if (!Close || !Drain)
            {
                std::fprintf(stderr, "FAIL: protocol reject close drain\n");
            }
            std::fprintf(stderr, "FAIL: protocol Accept returned an empty owner\n");
            co_return false;
        }
        auto Conn = std::move(AcceptResult->Connection);

        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            const auto Read = co_await Conn->ReadSome(Buffer);
            if (Read.Failure.Failed() || Read.Bytes == 0) break;
            const auto Write = co_await Conn->WriteExact(
                std::span<const std::byte>(Buffer.data(), Read.Bytes));
            if (Write.Failure.Failed() || Write.Bytes != Read.Bytes)
            {
                const auto Close = Conn->Close();
                const auto Drain = co_await Conn->Activity()->Drain();
                if (!Close || !Drain) std::fprintf(stderr, "FAIL: Trojan relay close drain\n");
                co_return true;
            }
        }
        const auto Close = Conn->Close();
        const auto Drain = co_await Conn->Activity()->Drain();
        if (!Close || !Drain) std::fprintf(stderr, "FAIL: Trojan relay close drain\n");
        co_return true;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: listen address is not an IP literal\n");
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        Acceptor.open(Address.is_v4() ? Tcp::v4() : Tcp::v6(), Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: acceptor open: %s\n", Error.message().c_str());
            co_return 1;
        }
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: acceptor bind: %s\n", Error.message().c_str());
            co_return 1;
        }
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Prism Trojan server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        while (true)
        {
            boost::system::error_code AcceptError;
            auto Socket = co_await Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, AcceptError));
            if (AcceptError) co_return 1;
            if (co_await ServeConnection(std::move(Socket), OptionsValue)) co_return 0;
        }
    }

    auto ReportCompletion(const std::exception_ptr &Exception) -> void
    {
        if (!Exception) return;
        std::fprintf(stderr, "FAIL: Trojan server coroutine exception\n");
    }
}

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported Trojan server option\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [&Io, &ExitCode, OptionsValue]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunServer(OptionsValue);
        (void)Io;
    };
    Net::co_spawn(Io, Run(),
        [&Io, &ExitCode](std::exception_ptr Exception)
        {
            ReportCompletion(Exception);
            if (Exception) ExitCode = 1;
        });
    Io.run();
    return ExitCode;
}
