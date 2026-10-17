/**
 * @file InteropWs.cpp
 * @brief Preview WebSocket 与独立 Go RFC 6455 reference 的双向 TCP 互操作端点
 */

#include "../Protocols/Ws/WsFactorySupport.hpp"
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

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    constexpr std::string_view Payload{"prism-websocket-external-interop-payload"};

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19093"};
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

    /**
     * @brief 在原 executor 关闭 WS 装饰链，并等待每层真实活动退栈。
     * @param Transport 按值保活稳定的装饰链；调用者已停止读写与移交。
     * @return 保留首次控制或 drain 失败；无半关闭、无线程外释放。
     */
    [[nodiscard]] auto CloseAndDrain(Preview::SharedTransmission Transport)
        -> Net::awaitable<Preview::Transmission::ControlResult>
    {
        auto Result = Transport->Close();
        for (auto *Layer = Transport.get(); Layer; Layer = Layer->NextLayer())
        {
            const auto Drained = co_await Layer->Activity()->Drain();
            if (Result && !Drained)
            {
                Result = std::unexpected(Drained.error());
            }
        }
        co_return Result;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed WebSocket server address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        const auto Host = Preview::Network::ParseHost(Server->Host);
        if (!Host)
        {
            std::fprintf(stderr, "FAIL: malformed WebSocket server host\n");
            co_return 2;
        }
        auto DialResult = co_await Dialer.Connect({*Host, Server->Port});
        if (!DialResult)
        {
            const auto DialError = Preview::Fault::ToNative(DialResult.error());
            std::fprintf(stderr, "FAIL: WebSocket TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        Preview::Ws::ClientOptions Config;
        Config.Host = "example.com";
        auto Connected = co_await Preview::Ws::Connect(
            Preview::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                *DialResult, Config));
        if (!Connected)
        {
            const auto Failure = Connected.error();
            const auto Native = Preview::Fault::ToNative(Failure);
            std::fprintf(stderr, "FAIL: WebSocket client handshake (%u, %s)\n",
                         static_cast<unsigned>(Failure.Code), Native.message().c_str());
            co_return 1;
        }
        auto Conn = std::move(Connected->Connection);
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Conn->WriteExact(Bytes);
        if (Written.Failure.Failed() || Written.Bytes != Bytes.size())
        {
            const auto Cleanup = co_await CloseAndDrain(Conn);
            (void)Cleanup;
            std::fprintf(stderr, "FAIL: WebSocket client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Conn->ReadExact(Echo);
        const auto Cleanup = co_await CloseAndDrain(Conn);
        if (Read.Failure.Failed() || Read.Bytes != Bytes.size() ||
            std::memcmp(Echo.data(), Bytes.data(), Bytes.size()) != 0 || !Cleanup)
        {
            std::fprintf(stderr, "FAIL: WebSocket external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Preview WebSocket client -> Go reference server (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed WebSocket listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: WebSocket listen address is not an IP literal\n");
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
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: WebSocket listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Preview WebSocket server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        auto Accepted = co_await Preview::Ws::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Raw, Preview::Ws::ServerOptions{}));
        if (!Accepted)
        {
            const auto Failure = Accepted.error();
            const auto Native = Preview::Fault::ToNative(Failure);
            std::fprintf(stderr, "FAIL: WebSocket server handshake (%u, %s)\n",
                         static_cast<unsigned>(Failure.Code), Native.message().c_str());
            co_return 1;
        }
        auto Conn = std::move(Accepted->Connection);
        std::array<std::byte, Payload.size()> Buffer{};
        const auto Read = co_await Conn->ReadExact(Buffer);
        if (Read.Failure.Failed() || Read.Bytes != Buffer.size() ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0)
        {
            const auto Cleanup = co_await CloseAndDrain(Conn);
            (void)Cleanup;
            std::fprintf(stderr, "FAIL: WebSocket server echo\n");
            co_return 1;
        }
        const auto Written = co_await Conn->WriteExact(Buffer);
        const auto Cleanup = co_await CloseAndDrain(Conn);
        if (Written.Failure.Failed() || Written.Bytes != Buffer.size() || !Cleanup)
        {
            std::fprintf(stderr, "FAIL: WebSocket server echo\n");
            co_return 1;
        }
        std::printf("PASS: Preview WebSocket server echo (%zu bytes)\n", Payload.size());
        co_return 0;
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
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed WebSocket options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RunInterop(*Options, ExitCode),
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
            std::fprintf(stderr, "FAIL: WebSocket interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: WebSocket interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
