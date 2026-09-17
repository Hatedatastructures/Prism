/**
 * @file InteropGunGrpc.cpp
 * @brief 标准 gRPC/HTTP2 Gun endpoint 与 Go h2c reference 的双向业务端点。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Gun/Grpc.hpp>
#include <Preview/Transport/Reliable.hpp>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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
        std::printf("READY: Preview standard Gun gRPC server on %s\n",
                    OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        auto Transport = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        auto Session = std::make_shared<Preview::Gun::Grpc::ServerSession>(
            Transport, Preview::Gun::Grpc::Config{},
            [](std::span<const std::byte> Payload)
            { return std::vector<std::byte>(Payload.begin(), Payload.end()); });
        const auto Code = co_await Session->Run();
        const auto Description = Preview::Fault::Describe(Code);
        std::printf("PASS: Preview standard Gun gRPC server status=%.*s\n",
                    static_cast<int>(Description.size()), Description.data());
        co_return Code == Preview::Fault::Code::Success ? 0 : 1;
    }

    [[nodiscard]] auto RunClient(const Options &OptionsValue) -> Net::awaitable<int>
    {
        const auto Endpoint = SplitAddress(OptionsValue.Address);
        if (!Endpoint)
        {
            std::fprintf(stderr, "FAIL: malformed Gun gRPC server address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        std::error_code DialError;
        auto Raw = co_await Dialer.Connect(
            Endpoint->address().to_string(), Endpoint->port(), DialError);
        if (!Raw)
        {
            std::fprintf(stderr, "FAIL: Gun gRPC TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        auto Session = std::make_shared<Preview::Gun::Grpc::ClientSession>(Raw);
        constexpr std::string_view Payload{"prism-standard-grpc-gun-payload"};
        const auto Result = co_await Session->Run(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        if (Result.Code != Preview::Fault::Code::Success || Result.GrpcStatus != 0U ||
            Result.Payload.size() != Payload.size() ||
            std::memcmp(Result.Payload.data(), Payload.data(), Payload.size()) != 0)
        {
            const auto Description = Preview::Fault::Describe(Result.Code);
            std::fprintf(stderr, "FAIL: Gun gRPC status=%u payload=%zu code=%.*s\n",
                         Result.GrpcStatus, Result.Payload.size(),
                         static_cast<int>(Description.size()), Description.data());
            co_return 1;
        }
        std::printf("PASS: Preview standard Gun gRPC client status=%u payload=%zu\n",
                    Result.GrpcStatus, Result.Payload.size());
        co_return 0;
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
            ExitCode = co_await (OptionsValue.Mode == "server"
                                     ? RunServer(OptionsValue)
                                     : RunClient(OptionsValue));
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
