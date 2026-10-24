/**
 * @file InteropHttp.cpp
 * @brief Prism HTTP/1.1 CONNECT 与独立 Go reference 的双向 TCP 端点
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
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19086"};
        std::string Target{"example.com:443"};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto CloseAndDrain(
        Prism::SharedTransmission Transport) -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return false;
        }
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Activities;
        bool HasAllActivities = true;
        for (auto *Layer = Transport.get(); Layer != nullptr; Layer = Layer->NextLayer())
        {
            auto Activity = Layer->Activity();
            if (!Activity)
            {
                HasAllActivities = false;
                continue;
            }
            Activities.push_back(std::move(Activity));
        }
        const auto CloseResult = Transport->Close();
        bool AllDrained = HasAllActivities;
        for (const auto &Activity : Activities)
        {
            try
            {
                const auto DrainResult = co_await Activity->Drain();
                AllDrained = DrainResult.has_value() && AllDrained;
            }
            catch (...)
            {
                AllDrained = false;
            }
        }
        co_return CloseResult.has_value() && AllDrained;
    }

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
            else if (Key == "-target")
            {
                Result.Target = Value;
            }
        }
        return Result;
    }

    [[nodiscard]] auto Echo(Prism::SharedTransmission Transport) -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        bool EchoedBytes = false;
        while (true)
        {
            const auto ReadResult = co_await Transport->ReadSome(Buffer);
            if (ReadResult.Bytes > Buffer.size())
            {
                (void)co_await CloseAndDrain(std::move(Transport));
                co_return false;
            }
            std::size_t Offset = 0;
            while (Offset < ReadResult.Bytes)
            {
                const auto Remaining = ReadResult.Bytes - Offset;
                const auto WriteResult = co_await Transport->WriteSome(
                    std::span<const std::byte>(Buffer).subspan(Offset, Remaining));
                if (WriteResult.Bytes > Remaining)
                {
                    (void)co_await CloseAndDrain(std::move(Transport));
                    co_return false;
                }
                Offset += WriteResult.Bytes;
                if (WriteResult.Failure.Failed() || WriteResult.Bytes == 0)
                {
                    (void)co_await CloseAndDrain(std::move(Transport));
                    co_return false;
                }
            }
            EchoedBytes = EchoedBytes || ReadResult.Bytes != 0;
            if (ReadResult.Failure.Failed())
            {
                const bool PeerClosed =
                    ReadResult.Failure.Code == Prism::Fault::Code::Eof;
                const auto Closed = co_await CloseAndDrain(std::move(Transport));
                co_return PeerClosed && EchoedBytes && Closed;
            }
            if (ReadResult.Bytes == 0)
            {
                (void)co_await CloseAndDrain(std::move(Transport));
                co_return false;
            }
        }
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed server address\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Transport = std::move(*DialResult);
        const auto Target = SplitHostPort(OptionsValue.Target);
        if (!Target)
        {
            std::fprintf(stderr, "FAIL: malformed target address\n");
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return 2;
        }
        if (co_await Prism::Http11::SendConnect(Transport, Target->Host, Target->Port) !=
            Prism::Fault::Code::Success)
        {
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return 1;
        }
        std::error_code Error;
        const auto StatusCode = co_await Prism::Http11::ReadResponse(
            Transport, Error, std::make_shared<Prism::Memory::BytePool>());
        if (StatusCode != 200 || Error)
        {
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return 1;
        }
        constexpr std::string_view Payload{"prism-http-connect-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto WriteResult = co_await Transport->WriteExact(PayloadBytes);
        if (WriteResult.Failure.Failed() || WriteResult.Bytes != Payload.size())
        {
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return 1;
        }
        std::array<std::byte, Payload.size()> EchoBuffer{};
        const auto ReadResult = co_await Transport->ReadExact(EchoBuffer);
        const auto Closed = co_await CloseAndDrain(std::move(Transport));
        if (!Closed || ReadResult.Failure.Failed() || ReadResult.Bytes != Payload.size() ||
            std::memcmp(EchoBuffer.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: HTTP CONNECT external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Prism HTTP CONNECT client -> Go reference server\n");
        co_return 0;
    }

    [[nodiscard]] auto RunEcho(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed echo address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: malformed echo host\n");
            co_return 2;
        }

        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        Acceptor.open(Address.is_v4() ? Tcp::v4() : Tcp::v6(), Error);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: echo listen: %s\n", Error.message().c_str());
            co_return 1;
        }

        std::printf("READY: HTTP raw echo server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }

        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            Error.clear();
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0)
            {
                break;
            }

            std::size_t Offset = 0;
            while (Offset < Count)
            {
                Error.clear();
                const auto Written = co_await Socket.async_write_some(
                    Net::buffer(Buffer.data() + Offset, Count - Offset),
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Written == 0)
                {
                    boost::system::error_code CloseError;
                    Socket.close(CloseError);
                    co_return 1;
                }
                Offset += Written;
            }
        }
        boost::system::error_code CloseError;
        Socket.close(CloseError);
        co_return 0;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket) -> Net::awaitable<bool>
    {
        auto Transport = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        Prism::Http11::ServerConn Server(
            Transport,
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{64U * 1024U, 64U}));
        Prism::Http11::HttpRequest Request;
        const auto ReadFailure = co_await Server.ReadRequest(Request);
        if (ReadFailure.Failed() || Request.Method != "CONNECT")
        {
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return false;
        }
        const auto WriteFailure = co_await Server.SendResponse(Prism::Http11::Status::Ok);
        if (WriteFailure.Failed())
        {
            (void)co_await CloseAndDrain(std::move(Transport));
            co_return false;
        }
        co_return co_await Echo(Server.Release());
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
        std::printf("READY: Prism HTTP CONNECT server on %s\n", OptionsValue.Address.c_str());
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

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "server")
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
        else if (OptionsValue.Mode == "echo")
        {
            ExitCode = co_await RunEcho(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
    }

} // namespace

int main(const int Argc, char **Argv)
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RunInterop(OptionsValue, ExitCode),
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
            std::fprintf(stderr, "FAIL: HTTP interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: HTTP interop coroutine exception: unknown\n");
        }
        return 1;
    }
    return ExitCode;
}
