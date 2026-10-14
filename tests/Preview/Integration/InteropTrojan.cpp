/**
 * @file InteropTrojan.cpp
 * @brief Preview Trojan 与独立 Go reference 的双向 TCP 互操作端点
 * @details client 模式连接 Go reference server；server 模式接受 Go
 *          reference client。两种模式都使用真实 Trojan 握手和 TCP echo，
 *          供外部矩阵 runner 编排，避免用 Preview 自回环冒充外部证据。
 */

#include <boost/asio/any_io_executor.hpp>
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
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19081"};
        std::string Password{"prism"};
        std::string Target{"example.com:443"};
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
        const auto *Begin = Value.data();
        const auto *End = Begin + Value.size();
        const auto [Parsed, Error] = std::from_chars(Begin, End, Port);
        if (Error != std::errc{} || Parsed != End || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Closing = Value.find(']');
            if (Closing == std::string_view::npos || Closing + 2 > Value.size() ||
                Value[Closing + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Closing + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Closing - 1)), *Port};
        }

        const auto Separator = Value.find_last_of(':');
        if (Separator == std::string_view::npos || Separator == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Separator + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Separator)), *Port};
    }

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Preview::Trojan::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue)
        {
            return std::nullopt;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        Preview::Trojan::AddressType Type;
        if (Error)
        {
            Type = Preview::Trojan::AddressType::Domain;
        }
        else if (Address.is_v4())
        {
            Type = Preview::Trojan::AddressType::Ipv4;
        }
        else
        {
            Type = Preview::Trojan::AddressType::Ipv6;
        }
        return Preview::Trojan::Address{Type, HostPortValue->Host, HostPortValue->Port};
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> Options
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
            else if (Key == "-password" || Key == "-pass")
            {
                Result.Password = Value;
            }
            else if (Key == "-target")
            {
                Result.Target = Value;
            }
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

        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Preview::Network::ParseHost(Server->Host).value_or(Preview::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);

        const Preview::Trojan::ClientConfig Config{OptionsValue.Password};
        auto ConnectResult = co_await Preview::Trojan::Connect(
            Preview::Trojan::ConnectParameters{std::move(Raw), Config, *Target});
        if (!ConnectResult)
        {
            const auto &Failure = ConnectResult.error();
            std::fprintf(stderr, "FAIL: Trojan client handshake Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
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
        std::printf("PASS: Preview Trojan client -> Go reference server\n");
        co_return 0;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket, const Options &OptionsValue)
        -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const Preview::Trojan::ServerConfig Config{OptionsValue.Password, true, false, false};
        auto AcceptResult = co_await Preview::Trojan::Accept(Raw, Config);
        if (!AcceptResult)
        {
            const auto &Failure = AcceptResult.error();
            std::fprintf(stderr, "FAIL: Trojan server handshake Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            const auto Close = Raw->Close();
            const auto Drain = co_await Raw->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: Trojan reject close drain\n");
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
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
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

        boost::system::error_code OpenError;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v4();
        if (!Address.is_v4())
        {
            Protocol = Tcp::v6();
        }
        Acceptor.open(Protocol, OpenError);
        if (OpenError)
        {
            std::fprintf(stderr, "FAIL: acceptor open: %s\n", OpenError.message().c_str());
            co_return 1;
        }
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), OpenError);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), OpenError);
        if (OpenError)
        {
            std::fprintf(stderr, "FAIL: acceptor bind: %s\n", OpenError.message().c_str());
            co_return 1;
        }
        Acceptor.listen(Net::socket_base::max_listen_connections, OpenError);
        if (OpenError)
        {
            std::fprintf(stderr, "FAIL: acceptor listen: %s\n", OpenError.message().c_str());
            co_return 1;
        }
        std::printf("READY: Preview Trojan server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);

        while (true)
        {
            boost::system::error_code AcceptError;
            auto Socket = co_await Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, AcceptError));
            if (AcceptError)
            {
                co_return 1;
            }
            if (co_await ServeConnection(std::move(Socket), OptionsValue))
            {
                co_return 0;
            }
        }
    }

    /** @brief 按模式运行 Trojan 互操作端点并返回进程退出码。 */
    [[nodiscard]] auto RunInterop(Options OptionsValue) -> Net::awaitable<int>
    {
        if (OptionsValue.Mode == "server")
        {
            co_return co_await RunServer(OptionsValue);
        }
        co_return co_await RunClient(OptionsValue);
    }

    /** @brief 把互操作协程终态写回进程并停止调度。 */
    struct InteropCompletion final
    {
        Net::io_context &Io;
        int &ExitCode;

        auto operator()(std::exception_ptr Exception, const int Result) const -> void
        {
            if (Exception)
            {
                std::fprintf(stderr, "FAIL: Trojan interop coroutine exception\n");
                ExitCode = 1;
            }
            else
            {
                ExitCode = Result;
            }
            Io.stop();
        }
    };

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    Net::co_spawn(Io, RunInterop(OptionsValue), InteropCompletion{Io, ExitCode});
    Io.run();
    return ExitCode;
}
