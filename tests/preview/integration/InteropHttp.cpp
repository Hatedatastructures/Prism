/**
 * @file InteropHttp.cpp
 * @brief Preview HTTP/1.1 CONNECT 与独立 Go reference 的双向 TCP 端点
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

#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Protocols/Http1/Conn.hpp>
#include <preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19086"};
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
        }
        return Result;
    }

    [[nodiscard]] auto Echo(Preview::SharedTransmission Transport) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            std::error_code ReadError;
            const auto Count = co_await Transport->async_read_some(Buffer, ReadError);
            if (ReadError || Count == 0)
            {
                break;
            }
            std::size_t Offset = 0;
            while (Offset < Count)
            {
                std::error_code WriteError;
                const auto Written = co_await Transport->async_write_some(
                    std::span<const std::byte>(Buffer).subspan(Offset, Count - Offset), WriteError);
                if (WriteError || Written == 0)
                {
                    Transport->Close();
                    co_return;
                }
                Offset += Written;
            }
        }
        Transport->Close();
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed server address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        std::error_code DialError;
        auto Transport = co_await Dialer.Connect(Server->Host, Server->Port, DialError);
        if (!Transport)
        {
            std::fprintf(stderr, "FAIL: TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        if (co_await Preview::Http11::SendConnect(Transport, "example.com", 443) !=
            Preview::Fault::Code::Success)
        {
            Transport->Close();
            co_return 1;
        }
        std::error_code Error;
        if (co_await Preview::Http11::ReadResponse(Transport, Error) != 200 || Error)
        {
            Transport->Close();
            co_return 1;
        }
        constexpr std::string_view Payload{"prism-http-connect-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Transport->AsyncWrite(PayloadBytes, Error);
        if (Error || Written != Payload.size())
        {
            Transport->Close();
            co_return 1;
        }
        std::array<std::byte, Payload.size()> EchoBuffer{};
        const auto Read = co_await Transport->AsyncRead(EchoBuffer, Error);
        Transport->Close();
        if (Error || Read != Payload.size() ||
            std::memcmp(EchoBuffer.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: HTTP CONNECT external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Preview HTTP CONNECT client -> Go reference server\n");
        co_return 0;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket) -> Net::awaitable<bool>
    {
        auto Transport = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        Preview::Http11::ServerConn Server(Transport);
        Preview::Http11::HttpRequest Request;
        if (co_await Server.ReadRequest(Request) != Preview::Fault::Code::Success ||
            Request.Method != "CONNECT")
        {
            Transport->Close();
            co_return false;
        }
        if (co_await Server.SendResponse(Preview::Http11::Status::Ok) != Preview::Fault::Code::Success)
        {
            Transport->Close();
            co_return false;
        }
        co_await Echo(Server.Release());
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
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        if (Address.is_v4())
        {
            Acceptor.open(Tcp::v4(), Error);
        }
        else
        {
            Acceptor.open(Tcp::v6(), Error);
        }
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            co_return 1;
        }
        std::printf("READY: Preview HTTP CONNECT server on %s\n", OptionsValue.Address.c_str());
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

int main(const int Argc, char **Argv)
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    Net::co_spawn(
        Io,
        [OptionsValue, &Io, &ExitCode]() -> Net::awaitable<void>
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
        },
        [&Io](const std::exception_ptr &Exception)
        {
            if (Exception)
            {
                try
                {
                    std::rethrow_exception(Exception);
                }
                catch (const std::exception &Error)
                {
                    std::fprintf(stderr, "FAIL: HTTP interop coroutine exception: %s\n", Error.what());
                }
                catch (...)
                {
                    std::fprintf(stderr, "FAIL: HTTP interop coroutine exception: unknown\n");
                }
            }
            Io.stop();
        });
    Io.run();
    return ExitCode;
}
