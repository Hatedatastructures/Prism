/**
 * @file InteropGun.cpp
 * @brief Preview gun-lite 与独立 Go reference 的双向 TCP 互操作端点
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
#include <preview/Protocols/Gun/Gun.hpp>
#include <preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    constexpr std::string_view Payload{"prism-gun-lite-external-interop-payload"};

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19095"};
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
            else
            {
                return std::nullopt;
            }
        }
        return Result;
    }

    [[nodiscard]] auto WriteAll(const Preview::SharedTransmission &Transport,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            auto WriteOperation = Transport->async_write_some(Data.subspan(Offset), Error);
            const auto Written = co_await std::move(WriteOperation);
            if (Error || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    [[nodiscard]] auto ReadExact(const Preview::SharedTransmission &Transport,
                                 std::span<std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            auto ReadOperation = Transport->async_read_some(Data.subspan(Offset), Error);
            const auto Read = co_await std::move(ReadOperation);
            if (Error || Read == 0 || Read > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed gun-lite server address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        std::error_code DialError;
        auto DialOperation = Dialer.Connect(Server->Host, Server->Port, DialError);
        auto Raw = co_await std::move(DialOperation);
        if (!Raw)
        {
            std::fprintf(stderr, "FAIL: gun-lite TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        auto ConnectOperation = Preview::Gun::Connect(std::move(Raw), "example.com");
        auto [HandshakeError, Conn] = co_await std::move(ConnectOperation);
        if (HandshakeError != Preview::Error::None || !Conn)
        {
            std::fprintf(stderr, "FAIL: gun-lite client handshake (%u)\n",
                         static_cast<unsigned>(HandshakeError));
            co_return 1;
        }
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!co_await WriteAll(Conn, Bytes))
        {
            Conn->Close();
            std::fprintf(stderr, "FAIL: gun-lite client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto ReadOk = co_await ReadExact(Conn, Echo);
        bool EchoMatches = false;
        if (ReadOk)
        {
            EchoMatches = std::memcmp(Echo.data(), Bytes.data(), Bytes.size()) == 0;
        }
        if (!ReadOk || !EchoMatches)
        {
            Conn->Close();
            std::fprintf(stderr, "FAIL: gun-lite external echo mismatch\n");
            co_return 1;
        }
        Conn->Close();
        std::printf("PASS: Preview gun-lite client -> Go reference server (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed gun-lite listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: gun-lite listen address is not an IP literal\n");
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v6();
        if (Address.is_v4())
        {
            Protocol = Tcp::v4();
        }
        Acceptor.open(Protocol, Error);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: gun-lite listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Preview gun-lite server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto AcceptOperation = Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        auto Socket = co_await std::move(AcceptOperation);
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        auto GunAcceptOperation = Preview::Gun::Accept(Raw);
        auto [HandshakeError, Host, Conn] = co_await std::move(GunAcceptOperation);
        if (HandshakeError != Preview::Error::None || Host != "example.com" || !Conn)
        {
            Raw->Close();
            std::fprintf(stderr, "FAIL: gun-lite server handshake (%u)\n",
                         static_cast<unsigned>(HandshakeError));
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Buffer{};
        const auto ReadOk = co_await ReadExact(Conn, Buffer);
        bool WriteOk = false;
        if (ReadOk)
        {
            WriteOk = co_await WriteAll(Conn, Buffer);
        }
        if (!ReadOk || !WriteOk)
        {
            Conn->Close();
            std::fprintf(stderr, "FAIL: gun-lite server echo\n");
            co_return 1;
        }
        Conn->Close();
        std::printf("PASS: Preview gun-lite server echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed gun-lite options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(
        Io,
        [&Io, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
        {
            auto Operation = RunClient(OptionsValue);
            if (OptionsValue.Mode == "server")
            {
                Operation = RunServer(OptionsValue);
            }
            ExitCode = co_await std::move(Operation);
            Io.stop();
        },
        [&Io, &Failure](std::exception_ptr Exception)
        {
            Failure = std::move(Exception);
            Io.stop();
        });
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: gun-lite interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: gun-lite interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
