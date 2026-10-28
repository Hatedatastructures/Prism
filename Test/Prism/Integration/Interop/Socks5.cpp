/**
 * @file Socks5.cpp
 * @brief Prism SOCKS5 与独立 Go reference 的双向 TCP 互操作端点
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
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19085"};
        std::string Target{"example.com:443"};
        std::string Username;
        std::string Password;
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto CloseAndDrain(
        std::shared_ptr<Prism::Transmission> Carrier) -> Net::awaitable<bool>
    {
        if (!Carrier)
        {
            co_return false;
        }
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Activities;
        bool HasAllActivities = true;
        for (auto *Layer = Carrier.get(); Layer != nullptr; Layer = Layer->NextLayer())
        {
            auto Activity = Layer->Activity();
            if (!Activity)
            {
                HasAllActivities = false;
                continue;
            }
            Activities.push_back(std::move(Activity));
        }
        const auto CloseResult = Carrier->Close();
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

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Prism::Socks5::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue)
        {
            return std::nullopt;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        Prism::Socks5::AddressType Type;
        if (Error)
        {
            Type = Prism::Socks5::AddressType::Domain;
        }
        else if (Address.is_v4())
        {
            Type = Prism::Socks5::AddressType::Ipv4;
        }
        else
        {
            Type = Prism::Socks5::AddressType::Ipv6;
        }
        return Prism::Socks5::Address{Type, HostPortValue->Host, HostPortValue->Port};
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
            else if (Key == "-username") Result.Username = Value;
            else if (Key == "-password") Result.Password = Value;
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
        const Prism::Socks5::ClientConfig Config{!OptionsValue.Username.empty(),
            OptionsValue.Username, OptionsValue.Password};
        auto ConnectResult = co_await Prism::Socks5::Connect(
            Prism::Socks5::ConnectParameters{std::move(*DialResult), Config, *Target});
        if (!ConnectResult || !*ConnectResult)
        {
            if (!ConnectResult)
            {
                const auto Native = Prism::Fault::ToNative(ConnectResult.error());
                std::fprintf(stderr, "FAIL: SOCKS5 client handshake code=%u error=%s\n",
                    static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            }
            else
            {
                std::fprintf(stderr, "FAIL: SOCKS5 client handshake returned an empty connection\n");
            }
            co_return 1;
        }
        auto Conn = std::move(*ConnectResult);
        constexpr std::string_view Payload{"prism-socks5-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Conn->WriteExact(PayloadBytes);
        if (Written.Failure.Failed() || Written.Bytes != PayloadBytes.size())
        {
            const auto Close = Conn->Close();
            const auto Drain = co_await Conn->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: SOCKS5 close drain\n");
            std::fprintf(stderr, "FAIL: SOCKS5 client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Conn->ReadExact(std::span<std::byte>(Echo));
        const auto Close = Conn->Close();
        const auto Drain = co_await Conn->Activity()->Drain();
        if (!Close || !Drain || Read.Failure.Failed() || Read.Bytes != Payload.size() ||
            std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: SOCKS5 external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: SOCKS5 literal echo bytes=%zu payload=%.*s\n", Payload.size(),
            static_cast<int>(Payload.size()), Payload.data());
        co_return 0;
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket) -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const Prism::Socks5::ServerConfig Config{};
        auto AcceptResult = co_await Prism::Socks5::Accept(Raw, Config);
        if (!AcceptResult || !AcceptResult->Connection ||
            AcceptResult->RequestValue.Cmd != Prism::Socks5::Command::Connect)
        {
            const auto Closed = co_await CloseAndDrain(Raw);
            if (!Closed) std::fprintf(stderr, "FAIL: SOCKS5 reject close drain\n");
            co_return false;
        }
        auto Conn = std::move(AcceptResult->Connection);
        std::array<std::byte, 4096> Buffer{};
        bool EchoedBytes = false;
        while (true)
        {
            const auto ReadResult = co_await Conn->ReadSome(Buffer);
            if (ReadResult.Bytes > Buffer.size())
            {
                (void)co_await CloseAndDrain(Conn);
                co_return false;
            }
            if (ReadResult.Bytes != 0)
            {
                const auto WriteResult = co_await Conn->WriteExact(
                    std::span<const std::byte>(Buffer.data(), ReadResult.Bytes));
                if (WriteResult.Bytes != ReadResult.Bytes || WriteResult.Failure.Failed())
                {
                    (void)co_await CloseAndDrain(Conn);
                    co_return false;
                }
                EchoedBytes = true;
            }
            if (ReadResult.Failure.Failed())
            {
                const bool PeerClosed = ReadResult.Failure.Code == Prism::Fault::Code::Eof;
                const auto Closed = co_await CloseAndDrain(Conn);
                if (!Closed) std::fprintf(stderr, "FAIL: SOCKS5 relay close drain\n");
                co_return PeerClosed && EchoedBytes && Closed;
            }
            if (ReadResult.Bytes == 0)
            {
                (void)co_await CloseAndDrain(Conn);
                co_return false;
            }
        }
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
        std::printf("READY: Prism SOCKS5 server on %s\n", OptionsValue.Address.c_str());
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
        else
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
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
            std::fprintf(stderr, "FAIL: SOCKS5 interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: SOCKS5 interop coroutine exception: unknown\n");
        }
        return 1;
    }
    return ExitCode;
}
