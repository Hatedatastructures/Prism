/**
 * @file InteropGunGrpc.cpp
 * @brief 标准 gRPC/HTTP2 Gun endpoint 与 Go h2c reference 的双向业务端点。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcSession.hpp>
#include <Prism/Transport/Reliable.hpp>

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

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options final
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19098"};
    };

    [[nodiscard]] auto ParseOptions(const int Argc, char **Argv) -> std::optional<Options>
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

    [[nodiscard]] auto SplitAddress(std::string_view Value) -> std::optional<Tcp::endpoint>
    {
        const auto Colon = Value.rfind(':');
        if (Colon == std::string_view::npos || Colon == 0U)
        {
            return std::nullopt;
        }
        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(
            Value.data() + Colon + 1U, Value.data() + Value.size(), Port);
        if (Error != std::errc{} || End != Value.data() + Value.size() || Port > 65535U)
        {
            return std::nullopt;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Value.substr(0U, Colon), AddressError);
        if (AddressError)
        {
            return std::nullopt;
        }
        return Tcp::endpoint(Address, static_cast<std::uint16_t>(Port));
    }

    /** @brief 输出 gRPC interop 的领域失败和原生错误身份。 */
    auto LogFailure(const std::string_view Phase, const Prism::Fault::Failure &Failure) -> void
    {
        const auto Description = Prism::Fault::Describe(Failure.Code);
        const auto Native = Failure.Native ? Failure.Native : Prism::Fault::ToNative(Failure);
        std::fprintf(stderr, "FAIL: Gun gRPC %.*s code=%.*s native=%s:%d\n",
                     static_cast<int>(Phase.size()), Phase.data(),
                     static_cast<int>(Description.size()), Description.data(),
                     Native.category().name(), Native.value());
    }

    [[nodiscard]] auto RunServer(const Options &OptionsValue) -> Net::awaitable<int>
    {
        const auto Endpoint = SplitAddress(OptionsValue.Address);
        if (!Endpoint)
        {
            std::fprintf(stderr, "FAIL: malformed Gun gRPC listen address\n");
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        Acceptor.open(Endpoint->protocol(), Error);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(*Endpoint, Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: Gun gRPC listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Prism standard Gun gRPC server on %s\n",
                    OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        auto Transport = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        auto Session = std::make_shared<Prism::Gun::Grpc::Detail::ServerSession>(
            Transport, Prism::Gun::Grpc::Config{},
            [](std::span<const std::byte> Payload)
            { return std::vector<std::byte>(Payload.begin(), Payload.end()); });
        const auto Failure = co_await Session->Run();
        if (Failure.Failed())
        {
            LogFailure("server", Failure);
            co_return 1;
        }
        const auto Description = Prism::Fault::Describe(Failure.Code);
        const auto Native = Failure.Native.message();
        std::printf("PASS: Prism standard Gun gRPC server status=%.*s native=%s\n",
                    static_cast<int>(Description.size()), Description.data(), Native.c_str());
        co_return 0;
    }

    [[nodiscard]] auto RunClient(const Options &OptionsValue) -> Net::awaitable<int>
    {
        const auto Endpoint = SplitAddress(OptionsValue.Address);
        if (!Endpoint)
        {
            std::fprintf(stderr, "FAIL: malformed Gun gRPC server address\n");
            co_return 2;
        }
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({
            Prism::Network::FromIpAddress(Endpoint->address()).value_or(Prism::Network::Host{}),
            Endpoint->port()});
        if (!DialResult)
        {
            LogFailure("TCP dial", DialResult.error());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);
        auto Session = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(std::move(Raw));
        constexpr std::string_view Payload{"prism-standard-grpc-gun-payload"};
        const auto Result = co_await Session->Run(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        bool Failed = false;
        if (Result.Terminal.Failed() &&
            (!Result.Response || Result.Terminal.Code != Prism::Fault::Code::Eof))
        {
            LogFailure("terminal", Result.Terminal);
            Failed = true;
        }
        if (Result.CloseFailure.Failed())
        {
            LogFailure("close", Result.CloseFailure);
            Failed = true;
        }
        if (Result.DrainFailure.Failed())
        {
            LogFailure("drain", Result.DrainFailure);
            Failed = true;
        }
        if (!Result.Response)
        {
            if (!Result.Terminal.Failed())
            {
                std::fprintf(stderr, "FAIL: Gun gRPC response missing\n");
            }
            co_return 1;
        }
        const auto &Response = *Result.Response;
        if (Response.GrpcStatus != 0U || Response.Payload.size() != Payload.size() ||
            std::memcmp(Response.Payload.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: Gun gRPC status=%u payload=%zu\n",
                         Response.GrpcStatus, Response.Payload.size());
            co_return 1;
        }
        if (Failed)
        {
            co_return 1;
        }
        std::printf("PASS: Prism standard Gun gRPC client status=%u payload=%zu\n",
                    Response.GrpcStatus, Response.Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunSelectedMode(const Options &OptionsValue) -> Net::awaitable<int>
    {
        if (OptionsValue.Mode == "server")
            co_return co_await RunServer(OptionsValue);
        co_return co_await RunClient(OptionsValue);
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed Gun gRPC options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(
        Io,
        [&Io, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
        {
            ExitCode = co_await RunSelectedMode(OptionsValue);
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
        catch (const std::exception &Exception)
        {
            std::fprintf(stderr, "FAIL: Gun gRPC exception: %s\n", Exception.what());
        }
        return 1;
    }
    return ExitCode;
}
