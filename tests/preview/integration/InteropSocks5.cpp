/**
 * @file InteropSocks5.cpp
 * @brief Preview SOCKS5 与独立 Go reference 的双向 TCP 互操作端点
 * @details client/server 使用真实 SOCKS5 方法协商、CONNECT 请求和 TCP
 *          echo。端点只用于外部矩阵，不依赖生产库或 TestSupport。
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

#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19085"};
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

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Preview::Socks5::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue)
        {
            return std::nullopt;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        Preview::Socks5::AddressType Type;
        if (Error)
        {
            Type = Preview::Socks5::AddressType::Domain;
        }
        else if (Address.is_v4())
        {
            Type = Preview::Socks5::AddressType::Ipv4;
        }
        else
        {
            Type = Preview::Socks5::AddressType::Ipv6;
        }
        return Preview::Socks5::Address{Type, HostPortValue->Host, HostPortValue->Port};
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
        std::error_code DialError;
        auto Raw = co_await Dialer.Connect(Server->Host, Server->Port, DialError);
        if (!Raw)
        {
            std::fprintf(stderr, "FAIL: TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        const Preview::Socks5::ClientConfig Config{};
        auto [HandshakeError, Conn] = co_await Preview::Socks5::Connect(
            Preview::Socks5::ConnectParameters{std::move(Raw), Config, *Target});
        if (HandshakeError != Preview::Error::None || !Conn)
        {
            std::fprintf(stderr, "FAIL: SOCKS5 client handshake (%u)\n",
                         static_cast<unsigned>(HandshakeError));
            co_return 1;
        }
        constexpr std::string_view Payload{"prism-socks5-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        std::error_code Error;
        const auto Written = co_await Conn->AsyncWrite(PayloadBytes, Error);
        if (Error || Written != PayloadBytes.size())
        {
            Conn->Close();
            std::fprintf(stderr, "FAIL: SOCKS5 client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Conn->AsyncRead(Echo, Error);
        Conn->Close();
        if (Error || Read != Payload.size() ||
            std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: SOCKS5 external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Preview SOCKS5 client -> Go reference server\n");
        co_return 0;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket) -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const Preview::Socks5::ServerConfig Config{};
        auto [HandshakeError, Request, Conn] = co_await Preview::Socks5::Accept(Raw, Config);
        if (HandshakeError != Preview::Error::None || !Conn || Request.Cmd != Preview::Socks5::Command::Connect)
        {
            Raw->Close();
            co_return false;
        }
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            std::error_code ReadError;
            const auto Count = co_await Conn->async_read_some(Buffer, ReadError);
            if (ReadError || Count == 0)
            {
                break;
            }
            std::size_t Offset = 0;
            while (Offset < Count)
            {
                std::error_code WriteError;
                const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                    Offset, Count - Offset);
                const auto Written = co_await Conn->async_write_some(WriteWindow, WriteError);
                if (WriteError || Written == 0)
                {
                    Conn->Close();
                    co_return true;
                }
                Offset += Written;
            }
        }
        Conn->Close();
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
        auto Protocol = Tcp::v4();
        if (!Address.is_v4())
        {
            Protocol = Tcp::v6();
        }
        Acceptor.open(Protocol, Error);
        if (Error)
        {
            co_return 1;
        }
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        if (Error)
        {
            co_return 1;
        }
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            co_return 1;
        }
        std::printf("READY: Preview SOCKS5 server on %s\n", OptionsValue.Address.c_str());
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
            if (co_await ServeConnection(std::move(Socket)))
            {
                co_return 0;
            }
        }
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [OptionsValue, &Io, &ExitCode]() -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "server")
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
        Io.stop();
    };
    auto OnComplete = [&Io](const std::exception_ptr &Exception) -> void
    {
        if (Exception)
        {
            try
            {
                std::rethrow_exception(Exception);
            }
            catch (const std::exception &Error)
            {
                std::fprintf(stderr, "FAIL: SOCKS5 interop coroutine exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "FAIL: SOCKS5 interop coroutine exception: unknown\n");
            }
        }
        Io.stop();
    };
    Net::co_spawn(Io, Run(), std::move(OnComplete));
    Io.run();
    return ExitCode;
}
