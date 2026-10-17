/**
 * @file OperationsHttpAuthTestSupport.hpp
 * @brief 多个 Operations HTTP 测试共享的本地 listener、Bootstrap 和请求夹具。
 */
#pragma once

#include <Preview/Operations/HttpServer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Testing::OperationsHttp
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using HttpServer = Preview::Operations::HttpServer;
    using Router = Preview::Operations::Router;

    struct Exchange final
    {
        std::string Response;
        boost::system::error_code Error;
    };

    enum class TokenMode
    {
        FetchForPost,
        Omit
    };

    struct ExchangePlan final
    {
        HttpServer &Server;
        std::string Request;
        TokenMode Token{TokenMode::FetchForPost};
    };

    struct ExchangeInput final
    {
        HttpServer &Server;
        Exchange &Result;
        std::string Request;
        TokenMode Token;
    };

    /** @brief 为单进程 listener 测试创建固定身份；请求仍从 Bootstrap 读取 token。 */
    [[nodiscard]] inline auto MakeTestBootstrap()
        -> std::shared_ptr<const Preview::Operations::BootstrapIdentity>
    {
        Preview::Operations::BootstrapIdentity::Incarnation Incarnation{};
        Preview::Operations::BootstrapIdentity::CommandToken Token{};
        for (std::size_t Index = 0; Index < Incarnation.size(); ++Index)
        {
            Incarnation[Index] = static_cast<std::uint8_t>(Index + 1U);
        }
        for (std::size_t Index = 0; Index < Token.size(); ++Index)
        {
            Token[Index] = static_cast<std::uint8_t>(0x80U + Index);
        }
        Preview::Operations::BootstrapIdentity::Options Options;
        Options.InstanceKey = "operations-test-instance";
        Options.Process = Preview::ProcessId{1};
        Options.ProcessIncarnation = std::move(Incarnation);
        Options.Token = std::move(Token);
        return std::make_shared<const Preview::Operations::BootstrapIdentity>(
            std::move(Options));
    }

    /** @brief 构造测试 socket 实际使用的 loopback authority。 */
    [[nodiscard]] inline auto MakeAuthority(const Tcp::endpoint &Endpoint) -> std::string
    {
        auto Address = Endpoint.address().to_string();
        if (Endpoint.address().is_v6())
        {
            Address = "[" + Address + "]";
        }
        Address.append(":").append(std::to_string(Endpoint.port()));
        return Address;
    }

    /** @brief 读取一个有界 HTTP/1.1 response 头和 Content-Length body。 */
    [[nodiscard]] inline auto ReadResponse(Tcp::socket &Socket) -> Net::awaitable<std::string>
    {
        std::array<char, 4096> Buffer{};
        std::string Response;
        while (Response.find("\r\n\r\n") == std::string::npos)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0U || Response.size() + Count > 65536U)
            {
                co_return Response;
            }
            Response.append(Buffer.data(), Count);
        }
        const auto HeaderEnd = Response.find("\r\n\r\n");
        const auto LengthStart = Response.find("Content-Length:");
        if (LengthStart == std::string::npos)
        {
            co_return Response;
        }
        const auto ValueStart = Response.find_first_not_of(" \t", LengthStart + 15U);
        const auto ValueEnd = Response.find("\r\n", ValueStart);
        const auto Length = static_cast<std::size_t>(
            std::stoull(Response.substr(ValueStart, ValueEnd - ValueStart)));
        const auto BodyStart = HeaderEnd + 4U;
        while (Response.size() < BodyStart + Length)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0U)
            {
                break;
            }
            Response.append(Buffer.data(), Count);
        }
        co_return Response;
    }

    /** @brief 通过真实 GET Bootstrap 响应读取本测试 listener 的 token。 */
    [[nodiscard]] inline auto ReadBootstrapToken(const Tcp::endpoint &Endpoint)
        -> Net::awaitable<std::optional<std::string>>
    {
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(Endpoint, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::nullopt;
        }
        const auto Request = "GET /Operations/Bootstrap HTTP/1.1\r\nHost: " +
            MakeAuthority(Endpoint) + "\r\nConnection: close\r\n\r\n";
        co_await Net::async_write(Socket, Net::buffer(Request),
                                  Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::nullopt;
        }
        const auto Response = co_await ReadResponse(Socket);
        constexpr std::string_view Key{"\"command_token\":\""};
        const auto Begin = Response.find(Key);
        if (Begin == std::string::npos)
        {
            co_return std::nullopt;
        }
        const auto First = Begin + Key.size();
        const auto End = Response.find('"', First);
        if (End == std::string::npos || End - First != 64U)
        {
            co_return std::nullopt;
        }
        co_return Response.substr(First, End - First);
    }

    /** @brief 替换测试占位 Host，并仅在有效命令夹具中附加 Bootstrap token。 */
    [[nodiscard]] inline auto PrepareRequest(
        std::string &Request,
        const Tcp::endpoint &Endpoint,
        const std::optional<std::string> &Token) -> bool
    {
        const auto LocalHost = Request.find("Host: localhost\r\n");
        if (LocalHost != std::string::npos)
        {
            Request.replace(LocalHost, 17U, "Host: " + MakeAuthority(Endpoint) + "\r\n");
        }
        if (!Token)
        {
            return true;
        }
        const auto HeaderEnd = Request.find("\r\n\r\n");
        if (HeaderEnd == std::string::npos)
        {
            return false;
        }
        Request.insert(HeaderEnd, "Authorization: Bearer " + std::string(*Token) + "\r\n");
        return true;
    }

    /** @brief 创建绑定 loopback ephemeral port 且带固定测试 Bootstrap 的 server。 */
    [[nodiscard]] inline auto MakeServer(Router RouterValue, Net::io_context &Io) -> HttpServer
    {
        HttpServer::Options Options{
            Io.get_executor(), Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
            std::move(RouterValue), std::chrono::milliseconds{5000},
            std::chrono::milliseconds{5000}, MakeTestBootstrap()};
        return HttpServer(Options);
    }

    /** @brief 启动 server、执行一条 wire 请求，并完成 Close+Drain。 */
    inline auto RunHttpExchange(ExchangeInput Input) -> Net::awaitable<void>
    {
        const auto Started = co_await Input.Server.Start();
        if (!Started)
        {
            Input.Result.Error = Started.error();
            co_return;
        }
        std::optional<std::string> Token;
        if (Input.Token == TokenMode::FetchForPost && Input.Request.starts_with("POST ") &&
            Input.Request.find("Authorization:") == std::string::npos)
        {
            Token = co_await ReadBootstrapToken(*Started);
            if (!Token)
            {
                Input.Result.Error = make_error_code(boost::system::errc::permission_denied);
                (void)Input.Server.CloseAdmission();
                (void)co_await Input.Server.Drain(HttpServer::Deadline::max());
                co_return;
            }
        }
        if (!PrepareRequest(Input.Request, *Started, Token))
        {
            Input.Result.Error = make_error_code(boost::system::errc::invalid_argument);
            (void)Input.Server.CloseAdmission();
            (void)co_await Input.Server.Drain(HttpServer::Deadline::max());
            co_return;
        }
        Tcp::socket Socket(co_await Net::this_coro::executor);
        co_await Socket.async_connect(
            *Started, Net::redirect_error(Net::use_awaitable, Input.Result.Error));
        if (!Input.Result.Error)
        {
            co_await Net::async_write(Socket, Net::buffer(Input.Request),
                Net::redirect_error(Net::use_awaitable, Input.Result.Error));
        }
        if (!Input.Result.Error)
        {
            Input.Result.Response = co_await ReadResponse(Socket);
        }
        boost::system::error_code CloseError;
        Socket.close(CloseError);
        (void)Input.Server.CloseAdmission();
        (void)co_await Input.Server.Drain(HttpServer::Deadline::max());
    }

    /** @brief 在测试 io_context 完整运行一条请求及其 listener drain。 */
    [[nodiscard]] inline auto RunExchangeCore(Net::io_context &Io, ExchangePlan Plan)
        -> Exchange
    {
        Exchange Result;
        Io.restart();
        Net::co_spawn(
            Io, RunHttpExchange(ExchangeInput{
                Plan.Server, Result, std::move(Plan.Request), Plan.Token}),
            [&](std::exception_ptr Failure)
            {
                if (Failure)
                {
                    Result.Error = make_error_code(boost::system::errc::operation_canceled);
                }
                Io.stop();
            });
        Io.run();
        return Result;
    }

    /** @brief 对普通 POST 测试从 listener 的真实 Bootstrap 获取并发送 token。 */
    [[nodiscard]] inline auto RunExchange(Net::io_context &Io, HttpServer &Server,
                                          std::string Request) -> Exchange
    {
        return RunExchangeCore(
            Io, ExchangePlan{Server, std::move(Request), TokenMode::FetchForPost});
    }

    /** @brief 保留缺失 token 的原始请求，用于验证拒绝发生在 Router dispatch 前。 */
    [[nodiscard]] inline auto RunExchangeWithoutToken(
        Net::io_context &Io, HttpServer &Server, std::string Request) -> Exchange
    {
        return RunExchangeCore(Io, ExchangePlan{Server, std::move(Request), TokenMode::Omit});
    }

} // namespace Preview::Testing::OperationsHttp
