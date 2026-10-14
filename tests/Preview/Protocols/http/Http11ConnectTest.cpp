/**
 * @file Http11ConnectTest.cpp
 * @brief HTTP/1.1 CONNECT 站点协议测试（T3-5 / D4）
 * @details 覆盖：
 *          - CONNECT 请求解析（方法/目标/Host/Proxy-Authorization）
 *          - 客户端请求构造与响应状态码提取
 *          - Basic 认证（407/200）
 *          - CONNECT E2E：握手 + 隧道双向转发
 *          - 异常路径：畸形请求 400 / 读失败
 */

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http1/Conn.hpp>
#include <Preview/Protocols/Http1/Parser.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include <gtest/gtest.h>
#include <TestSupport/Preview/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Preview::Error;
    using Preview::SharedTransmission;

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    struct ReleasedForwardScenario final
    {
        SharedTransmission Client;
        Preview::Http11::ServerConn &Server;
        std::string_view Request;
        std::string &Received;
    };

    /** @brief 写入合并的 request/body 并通过释放后的 forward transport 读取原始字节。 */
    auto RunReleasedForwardScenario(ReleasedForwardScenario Scenario) -> Net::awaitable<void>
    {
        std::error_code Error;
        co_await Scenario.Client->AsyncWrite(Preview::AsBytesSpan(Scenario.Request), Error);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Scenario.Client->Shutdown();

        Preview::Http11::HttpRequest Request;
        const auto ReadResult = co_await Scenario.Server.ReadRequest(Request);
        if (ReadResult != Preview::Fault::Code::Success)
        {
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Scenario.Server.ReleaseForward();
        if (!Forwarded)
        {
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }

        std::array<std::byte, 512> Buffer{};
        const auto Count = co_await Forwarded->AsyncRead(Buffer, Error);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Scenario.Received.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
    }

    /** @brief 接受单条 CONNECT 并按解析结果发送原有成功响应。 */
    auto ServeConnectHandshake(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        auto Transport = Preview::Transport::MakeReliable(std::move(Socket));
        Preview::Http11::ServerConn Server(Transport);
        Preview::Http11::HttpRequest Request;
        const auto Result = co_await Server.ReadRequest(Request);
        if (Result == Preview::Fault::Code::Success && Request.Method == "CONNECT")
        {
            co_await Server.SendResponse(Preview::Http11::Status::Ok);
        }
    }

    struct ConnectHandshakeScenario final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        Preview::Fault::Failure &DialFailure;
        SharedTransmission &Client;
        std::error_code &Error;
        int &Status;
    };

    /** @brief 驱动一次真实 CONNECT 拨号与 200 响应读取。 */
    auto RunConnectHandshake(ConnectHandshakeScenario Scenario) -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario.Acceptor.get_executor(),
                      ServeConnectHandshake(Scenario.Acceptor), Net::detached);
        auto DialResult = co_await Preview::Network::Dialer::Dialer(
            Scenario.Acceptor.get_executor()).Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Scenario.Port});
        if (!DialResult)
        {
            Scenario.DialFailure = DialResult.error();
            co_return;
        }
        Scenario.Client = std::move(*DialResult);
        co_await Preview::Http11::SendConnect(Scenario.Client, "example.com", 443);
        Scenario.Status = co_await Preview::Http11::ReadResponse(Scenario.Client, Scenario.Error);
    }

    /** @brief 顺序处理原来的两次认证请求并返回对应 407 或 200。 */
    auto ServeAuthenticatedConnects(
        Tcp::acceptor &Acceptor,
        const Preview::Authenticator &Auth) -> Net::awaitable<void>
    {
        for (int Round = 0; Round < 2; ++Round)
        {
            auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
            auto Transport = Preview::Transport::MakeReliable(std::move(Socket));
            Preview::Http11::ServerConn Server(Transport);
            Preview::Http11::HttpRequest Request;
            const auto Result = co_await Server.ReadRequest(Request);
            if (Result == Preview::Fault::Code::Success)
            {
                const auto AuthResult = Preview::Http11::CheckBasic(Request.authorization, Auth);
                auto ResponseStatus = Preview::Http11::Status::ProxyAuthRequired;
                if (AuthResult.Ok)
                {
                    ResponseStatus = Preview::Http11::Status::Ok;
                }
                co_await Server.SendResponse(ResponseStatus);
            }
        }
    }

    struct AuthenticatedConnectScenario final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        const Preview::Authenticator &Auth;
        std::error_code &Error;
        Preview::Fault::Failure &FirstDialFailure;
        Preview::Fault::Failure &SecondDialFailure;
        SharedTransmission &Client;
        int &StatusWithoutAuth;
        int &StatusWithAuth;
    };

    /** @brief 依序验证未认证 407 和正确 Basic 凭据 200。 */
    auto RunAuthenticatedConnects(AuthenticatedConnectScenario Scenario)
        -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario.Acceptor.get_executor(),
                      ServeAuthenticatedConnects(Scenario.Acceptor, Scenario.Auth), Net::detached);
        auto FirstDial = co_await Preview::Network::Dialer::Dialer(
            Scenario.Acceptor.get_executor()).Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Scenario.Port});
        if (FirstDial)
        {
            Scenario.Client = std::move(*FirstDial);
            co_await Preview::Http11::SendConnect(Scenario.Client, "example.com", 443);
            Scenario.StatusWithoutAuth = co_await Preview::Http11::ReadResponse(
                Scenario.Client, Scenario.Error);
            Scenario.Client->Close();
        }
        else
        {
            Scenario.FirstDialFailure = FirstDial.error();
        }

        auto SecondDial = co_await Preview::Network::Dialer::Dialer(
            Scenario.Acceptor.get_executor()).Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Scenario.Port});
        if (SecondDial)
        {
            Scenario.Client = std::move(*SecondDial);
            co_await Preview::Http11::SendConnect(
                {Scenario.Client, "example.com", 443, "Basic dXNlcjpwYXNz"});
            Scenario.StatusWithAuth = co_await Preview::Http11::ReadResponse(
                Scenario.Client, Scenario.Error);
            Scenario.Client->Close();
        }
        else
        {
            Scenario.SecondDialFailure = SecondDial.error();
        }
    }

    /** @brief 读取单条畸形请求并发送既有 400/200 判定结果。 */
    auto ServeBadRequestProbe(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        auto Transport = Preview::Transport::MakeReliable(std::move(Socket));
        Preview::Http11::ServerConn Server(Transport);
        Preview::Http11::HttpRequest Request;
        const auto Result = co_await Server.ReadRequest(Request);
        auto ResponseStatus = Preview::Http11::Status::BadRequest;
        if (Result == Preview::Fault::Code::Success)
        {
            ResponseStatus = Preview::Http11::Status::Ok;
        }
        co_await Server.SendResponse(ResponseStatus);
    }

    struct BadRequestScenario final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        std::error_code &Error;
        Preview::Fault::Failure &DialFailure;
        SharedTransmission &Client;
        std::string &Reply;
    };

    /** @brief 发送原畸形 CRLF 请求并保留真实响应头。 */
    auto RunBadRequestScenario(BadRequestScenario Scenario) -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario.Acceptor.get_executor(),
                      ServeBadRequestProbe(Scenario.Acceptor), Net::detached);
        auto DialResult = co_await Preview::Network::Dialer::Dialer(
            Scenario.Acceptor.get_executor()).Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Scenario.Port});
        if (!DialResult)
        {
            Scenario.DialFailure = DialResult.error();
            co_return;
        }
        Scenario.Client = std::move(*DialResult);
        const std::string BadRequest = "\r\n\r\n";
        co_await Scenario.Client->async_write_some(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(BadRequest.data()), BadRequest.size()),
            Scenario.Error);
        std::array<std::byte, 64> Buffer{};
        const auto Count = co_await Scenario.Client->async_read_some(Buffer, Scenario.Error);
        Scenario.Reply.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
    }

    /** @brief 接受 CONNECT 隧道并执行原有一次 echo 转发。 */
    auto ServeConnectTunnel(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        auto Transport = Preview::Transport::MakeReliable(std::move(Socket));
        Preview::Http11::ServerConn Server(Transport);
        Preview::Http11::HttpRequest Request;
        const auto Result = co_await Server.ReadRequest(Request);
        if (Result == Preview::Fault::Code::Success)
        {
            co_await Server.SendResponse(Preview::Http11::Status::Ok);
            std::array<std::byte, 128> Buffer{};
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer, Error);
            if (Count > 0)
            {
                co_await Transport->async_write_some(
                    std::span<const std::byte>(Buffer.data(), Count), Error);
            }
        }
    }

    struct ConnectTunnelScenario final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        std::error_code &Error;
        Preview::Fault::Failure &DialFailure;
        SharedTransmission &Client;
        int &Status;
        std::string &EchoBack;
    };

    /** @brief 交换固定隧道 payload 并保留响应状态和 echo 字节。 */
    auto RunConnectTunnel(ConnectTunnelScenario Scenario) -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario.Acceptor.get_executor(),
                      ServeConnectTunnel(Scenario.Acceptor), Net::detached);
        auto DialResult = co_await Preview::Network::Dialer::Dialer(
            Scenario.Acceptor.get_executor()).Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Scenario.Port});
        if (!DialResult)
        {
            Scenario.DialFailure = DialResult.error();
            co_return;
        }
        Scenario.Client = std::move(*DialResult);
        co_await Preview::Http11::SendConnect(Scenario.Client, "example.com", 443);
        Scenario.Status = co_await Preview::Http11::ReadResponse(Scenario.Client, Scenario.Error);
        const std::string Message = "tunnel-echo";
        co_await Scenario.Client->async_write_some(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Message.data()), Message.size()),
            Scenario.Error);
        std::array<std::byte, 128> Buffer{};
        const auto Count = co_await Scenario.Client->async_read_some(Buffer, Scenario.Error);
        Scenario.EchoBack.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
    }

    struct ServerPayloadScenario final
    {
        SharedTransmission Client;
        Preview::Http11::ServerConn &Server;
        std::string_view Wire;
        std::string &Received;
    };

    /** @brief 读取 CONNECT 请求后从 ServerConn 的 tunnel release 取得首包 payload。 */
    auto RunServerPayloadScenario(ServerPayloadScenario Scenario) -> Net::awaitable<void>
    {
        std::error_code Error;
        co_await Scenario.Client->AsyncWrite(Preview::AsBytesSpan(Scenario.Wire), Error);
        Scenario.Client->Shutdown();
        Preview::Http11::HttpRequest Request;
        EXPECT_EQ(co_await Scenario.Server.ReadRequest(Request), Preview::Fault::Code::Success);
        auto Released = Scenario.Server.Release();
        std::array<std::byte, 64> Buffer{};
        const auto Count = co_await Released->AsyncRead(std::span<std::byte>(Buffer), Error);
        Scenario.Received.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
    }

    struct ClientPayloadScenario final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::string_view Wire;
        int &Status;
        std::string &Received;
    };

    /** @brief 读取 coalesced 200 响应后的首段 tunnel payload。 */
    auto RunClientPayloadScenario(ClientPayloadScenario Scenario) -> Net::awaitable<void>
    {
        std::error_code Error;
        co_await Scenario.Server->AsyncWrite(Preview::AsBytesSpan(Scenario.Wire), Error);
        Scenario.Server->Shutdown();
        Scenario.Status = co_await Preview::Http11::ReadResponse(Scenario.Client, Error);
        std::array<std::byte, 64> Buffer{};
        const auto Count = co_await Scenario.Client->AsyncRead(std::span<std::byte>(Buffer), Error);
        Scenario.Received.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
    }
} // namespace

TEST(Http11Connect, ParseRequestOk)
{
    const std::string raw = "CONNECT example.com:443 HTTP/1.1\r\n"
                            "Host: example.com:443\r\n"
                            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                            "User-Agent: test\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest req;
    const auto rc = Preview::Http11::ParseRequest(raw, req);
    EXPECT_EQ(rc, Preview::Fault::Code::Success);
    EXPECT_EQ(req.Method, "CONNECT");
    EXPECT_EQ(req.Target, "example.com:443");
    EXPECT_EQ(req.version, "HTTP/1.1");
    EXPECT_EQ(req.host, "example.com:443");
    EXPECT_EQ(req.authorization, "Basic dXNlcjpwYXNz");
}

TEST(Http11Connect, ParsesAbsoluteFormAndBuildsOriginRequest)
{
    const std::string Raw = "POST http://example.com:8080/api?q=1 HTTP/1.1\r\n"
                             "Host: example.com:8080\r\n"
                             "X-Request: keep\r\n"
                             "Content-Length: 7\r\n"
                             "\r\n"
                             "payload";
    Preview::Http11::HttpRequest Request;

    ASSERT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::Success);
    ASSERT_TRUE(Preview::Http11::ResolveTarget(Request).has_value());
    const auto Target = *Preview::Http11::ResolveTarget(Request);
    EXPECT_EQ(Target.Form, Preview::Http11::RequestForm::Absolute);
    EXPECT_EQ(Target.Host, "example.com");
    EXPECT_EQ(Target.Port, 8080);

    EXPECT_EQ(
        Preview::Http11::BuildForwardRequest(Raw, Request),
        "POST /api?q=1 HTTP/1.1\r\n"
        "Host: example.com:8080\r\n"
        "X-Request: keep\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "payload");
}

TEST(Http11Connect, ReleaseForwardPreservesCoalescedRequestAndBody)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Preview::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerEnd));
    Preview::Http11::ServerConn Server(ServerTransport);
    const std::string Raw = "POST http://example.com/upload HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Content-Length: 7\r\n"
                             "\r\n"
                             "payload";
    std::string Received;

    RunCoroutine(Io, RunReleasedForwardScenario(
        ReleasedForwardScenario{Client, Server, Raw, Received}));

    EXPECT_EQ(Received,
              "POST /upload HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Content-Length: 7\r\n"
              "\r\n"
              "payload");
}

TEST(Http11Connect, ParseCaseInsensitiveHeaders)
{
    const std::string raw = "CONNECT host:80 HTTP/1.1\r\n"
                            "hOsT: host:80\r\n"
                            "PrOxY-aUtHoRiZaTiOn: Basic abc\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest req;
    const auto rc = Preview::Http11::ParseRequest(raw, req);
    EXPECT_EQ(rc, Preview::Fault::Code::Success);
    EXPECT_EQ(req.host, "host:80");
    EXPECT_EQ(req.authorization, "Basic abc");
}

TEST(Http11Connect, ParseMalformed)
{
    Preview::Http11::HttpRequest req;
    // 缺请求行
    EXPECT_EQ(Preview::Http11::ParseRequest("GET\r\n\r\n", req), Preview::Fault::Code::ParseError);
    // 缺头结束
    EXPECT_EQ(Preview::Http11::ParseRequest("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n", req),
              Preview::Fault::Code::ParseError);
    // 空数据
    EXPECT_EQ(Preview::Http11::ParseRequest("", req), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, RejectsOverreportedHeaderRead)
{
    Net::io_context ioc;
    auto raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
    raw->OverreportRead = true;
    Preview::Http11::ServerConn server(raw);
    Preview::Http11::HttpRequest request;
    Preview::Fault::Code result = Preview::Fault::Code::Success;

    RunCoroutine(ioc,
             [&]() -> Net::awaitable<void>
             {
                 result = co_await server.ReadRequest(request);
             });

    EXPECT_EQ(result, Preview::Fault::Code::IoError);
}

TEST(Http11Connect, ParseRejectsDuplicateSecurityHeaders)
{
    const std::string raw = "CONNECT host:80 HTTP/1.1\r\n"
                            "Host: host:80\r\n"
                            "Host: other:80\r\n"
                            "Proxy-Authorization: Basic abc\r\n"
                            "Proxy-Authorization: Basic def\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest req;
    EXPECT_EQ(Preview::Http11::ParseRequest(raw, req), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseRejectsObsoleteFoldingAndInvalidCharacters)
{
    const std::string folded = "CONNECT host:80 HTTP/1.1\r\n"
                               "Host: host:80\r\n"
                               "\tcontinued\r\n"
                               "\r\n";
    const std::string invalid_name = "CONNECT host:80 HTTP/1.1\r\n"
                                     "Bad Header: value\r\n"
                                     "\r\n";
    const std::string invalid_value = "CONNECT host:80 HTTP/1.1\r\n"
                                      "Host: host:\x01\r\n"
                                      "\r\n";
    Preview::Http11::HttpRequest req;
    EXPECT_EQ(Preview::Http11::ParseRequest(folded, req), Preview::Fault::Code::ParseError);
    EXPECT_EQ(Preview::Http11::ParseRequest(invalid_name, req), Preview::Fault::Code::ParseError);
    EXPECT_EQ(Preview::Http11::ParseRequest(invalid_value, req), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseRejectsOversizedHeaderBlock)
{
    std::string raw = "CONNECT host:80 HTTP/1.1\r\nHost: host:80\r\nX-Pad: ";
    raw.append(Preview::Http11::MaxHdrSize, 'x');
    raw.append("\r\n\r\n");
    Preview::Http11::HttpRequest req;
    EXPECT_EQ(Preview::Http11::ParseRequest(raw, req), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseStatusCode)
{
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 200 Connection Established\r\n\r\n"), 200);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), 407);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("garbage"), 0);
}

TEST(Http11Connect, MakeConnectRequest)
{
    const auto req = Preview::Http11::MakeConnectRequest("example.com", 443);
    EXPECT_TRUE(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    EXPECT_TRUE(req.find("Host: example.com:443\r\n") != std::string::npos);
    EXPECT_EQ(req.find("Proxy-Authorization"), std::string::npos);

    const auto with_auth = Preview::Http11::MakeConnectRequest("h", 80, "Basic dXNlcjpwYXNz");
    EXPECT_TRUE(with_auth.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != std::string::npos);
}

TEST(Http11Connect, CheckBasicAuth)
{
    // user:pass 的 base64
    constexpr std::string_view auth_ok = "Basic dXNlcjpwYXNz";
    constexpr std::string_view auth_bad = "Basic dXNlcjpiYWQ=";
    const auto AuthOwner = Preview::Testing::ProviderAccount(
        Preview::Testing::ProviderAccountInput{Preview::AccountId{1U},
            Preview::Account::Credential::Password("pass"), "user", "user", {}});
    const auto& Auth = *AuthOwner->Authenticator;

    auto Ok = Preview::Http11::CheckBasic(auth_ok, Auth);
    EXPECT_TRUE(Ok.Ok);
    EXPECT_EQ(Ok.Identity, "user");

    EXPECT_FALSE(Preview::Http11::CheckBasic(auth_bad, Auth).Ok);
    EXPECT_FALSE(Preview::Http11::CheckBasic("Bearer token", Auth).Ok);
    EXPECT_FALSE(Preview::Http11::CheckBasic("", Auth).Ok);
}

TEST(Http11Connect, HandshakeOkE2E)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Tcp::endpoint(Tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    Preview::Fault::Failure DialFailure;
    SharedTransmission Client;
    int status = 0;
    RunCoroutine(ioc, RunConnectHandshake(
        ConnectHandshakeScenario{acceptor, port, DialFailure, Client, ec, status}));
    EXPECT_TRUE(DialFailure.Succeeded());
    EXPECT_EQ(DialFailure.Code, Preview::Fault::Code::Success);
    EXPECT_FALSE(ec);
    EXPECT_EQ(status, 200);
}

TEST(Http11Connect, AuthRequired407)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Tcp::endpoint(Tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    const auto AuthOwner = Preview::Testing::ProviderAccount(
        Preview::Testing::ProviderAccountInput{Preview::AccountId{1U},
            Preview::Account::Credential::Password("pass"), "user", "user", {}});
    const auto& Auth = *AuthOwner->Authenticator;
    std::error_code ec;
    Preview::Fault::Failure FirstDialFailure;
    Preview::Fault::Failure SecondDialFailure;
    SharedTransmission Client;
    int status_no_auth = 0;
    int status_ok = 0;
    RunCoroutine(ioc, RunAuthenticatedConnects(AuthenticatedConnectScenario{
        acceptor, port, Auth, ec, FirstDialFailure, SecondDialFailure,
        Client, status_no_auth, status_ok}));
    EXPECT_TRUE(FirstDialFailure.Succeeded());
    EXPECT_EQ(FirstDialFailure.Code, Preview::Fault::Code::Success);
    EXPECT_TRUE(SecondDialFailure.Succeeded());
    EXPECT_EQ(SecondDialFailure.Code, Preview::Fault::Code::Success);
    EXPECT_EQ(status_no_auth, 407);
    EXPECT_EQ(status_ok, 200);
}

TEST(Http11Connect, BadRequest400)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Tcp::endpoint(Tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    Preview::Fault::Failure DialFailure;
    SharedTransmission Client;
    std::string Reply;
    RunCoroutine(ioc, RunBadRequestScenario(
        BadRequestScenario{acceptor, port, ec, DialFailure, Client, Reply}));
    EXPECT_TRUE(DialFailure.Succeeded());
    EXPECT_EQ(DialFailure.Code, Preview::Fault::Code::Success);
    EXPECT_TRUE(Reply.starts_with("HTTP/1.1 400"));
}

TEST(Http11Connect, TunnelBidirectional)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Tcp::endpoint(Tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    Preview::Fault::Failure DialFailure;
    SharedTransmission Client;
    int status = 0;
    std::string echo_back;
    RunCoroutine(ioc, RunConnectTunnel(
        ConnectTunnelScenario{acceptor, port, ec, DialFailure, Client, status, echo_back}));
    EXPECT_TRUE(DialFailure.Succeeded());
    EXPECT_EQ(DialFailure.Code, Preview::Fault::Code::Success);
    EXPECT_EQ(status, 200);
    EXPECT_EQ(echo_back, "tunnel-echo");
}

TEST(Http11Connect, ServerPreservesCoalescedTunnelPayload)
{
    Net::io_context ioc;
    auto [clientEnd, serverEnd] = Preview::MakeMemoryPair(ioc.get_executor());
    Preview::SharedTransmission Client =
        std::make_shared<Preview::MemoryStream>(std::move(clientEnd));
    auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(serverEnd));
    Preview::Http11::ServerConn Server(ServerTransport);
    const std::string Payload = "first-tunnel-bytes";
    const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                             "Host: example.com:443\r\n"
                             "\r\n" +
                             Payload;
    std::string Received;
    RunCoroutine(ioc, RunServerPayloadScenario(
        ServerPayloadScenario{Client, Server, Wire, Received}));
    EXPECT_EQ(Received, Payload);
}

TEST(Http11Connect, ClientPreservesCoalescedResponsePayload)
{
    Net::io_context ioc;
    auto [clientEnd, serverEnd] = Preview::MakeMemoryPair(ioc.get_executor());
    Preview::SharedTransmission Client =
        std::make_shared<Preview::MemoryStream>(std::move(clientEnd));
    auto Server = std::make_shared<Preview::MemoryStream>(std::move(serverEnd));
    const std::string Payload = "response-tunnel-bytes";
    const std::string Wire = "HTTP/1.1 200 Connection Established\r\n\r\n" + Payload;
    int Status = 0;
    std::string Received;
    RunCoroutine(ioc, RunClientPayloadScenario(
        ClientPayloadScenario{Client, Server, Wire, Status, Received}));
    EXPECT_EQ(Status, 200);
    EXPECT_EQ(Received, Payload);
}
