/**
 * @file HttpForwardBasicTest.cpp
 * @brief HTTP 正向代理基本请求与响应生命周期测试。
 */
#include "ForwardSupport.hpp"
TEST(HttpForwardIngress, ForwardsAuthenticatedAbsoluteFormAndCoalescedBody)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "POST /upload?q=1 HTTP/1.1\r\nHost: " + OriginHost +
        "\r\nX-Ingress: absolute\r\nContent-Length: 7\r\n\r\npayload";
    Origin.Start(Expected, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\norigin-ok");

    std::uint16_t TcpPort = FindFreePort();
    std::uint16_t OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "POST http://" + OriginHost +
        "/upload?q=1 HTTP/1.1\r\nHost: ignored.example\r\n"
        "Proxy-Authorization: " +
        std::string(ProxyAuthorization) + "\r\nX-Ingress: absolute\r\nContent-Length: 7\r\n\r\npayload";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto& Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 200 OK"), std::string::npos);
    EXPECT_TRUE(Response.ends_with("origin-ok"));
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, ForwardsAuthenticatedOriginForm)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "GET /origin?q=1 HTTP/1.1\r\nHost: " + OriginHost + "\r\nX-Ingress: origin\r\n\r\n";
    Origin.Start(Expected, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET /origin?q=1 HTTP/1.1\r\nHost: " + OriginHost +
        "\r\nProxy-Authorization: " + std::string(ProxyAuthorization) + "\r\nX-Ingress: origin\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto& Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 204 No Content"), std::string::npos);
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, CompletesContentLengthResponseBeforeKeepAliveOriginCloses)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "GET /length HTTP/1.1\r\nHost: " + OriginHost + "\r\n\r\n";
    const auto OriginResponse =
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\norigin-ok";
    Origin.Start(Expected, OriginResponse, OriginCloseMode::KeepOpen);

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://" + OriginHost +
        "/length HTTP/1.1\r\nHost: ignored.example\r\n"
        "Proxy-Authorization: " +
        std::string(ProxyAuthorization) + "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForResponse(IoTimeout));
    EXPECT_FALSE(Origin.WaitForComplete(std::chrono::milliseconds(100)));

    const auto Observation = ReadUntilClose(Client, IoTimeout);
    const auto& Response = Observation.Bytes;
    EXPECT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 200 OK"), std::string::npos);
    EXPECT_TRUE(Response.ends_with("origin-ok"));
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    OperationsDrainObservation Drain;
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort(), IoTimeout, &Drain))
        << Drain.Description();

    CloseSocket(Client);
    Origin.Stop();
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, CompletesHeadResponseBeforeKeepAliveOriginCloses)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "HEAD /head HTTP/1.1\r\nHost: " + OriginHost + "\r\n\r\n";
    const std::string OriginResponse =
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\norigin-ok";
    const auto HeaderEnd = OriginResponse.find("\r\n\r\n") + 4U;
    const auto ExpectedResponse = OriginResponse.substr(0, HeaderEnd);
    Origin.Start(Expected, OriginResponse, OriginCloseMode::KeepOpen);

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "HEAD http://" + OriginHost +
        "/head HTTP/1.1\r\nHost: ignored.example\r\n"
        "Proxy-Authorization: " +
        std::string(ProxyAuthorization) + "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForResponse(IoTimeout));
    EXPECT_FALSE(Origin.WaitForComplete(std::chrono::milliseconds(100)));

    const auto Observation = ReadUntilClose(Client, IoTimeout);
    EXPECT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_EQ(Observation.Bytes, ExpectedResponse);
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    OperationsDrainObservation Drain;
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort(), IoTimeout, &Drain))
        << Drain.Description();

    CloseSocket(Client);
    Origin.Stop();
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, CompletesInformationalChunkedResponseBeforeKeepAliveOriginCloses)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "GET /chunked HTTP/1.1\r\nHost: " + OriginHost + "\r\n\r\n";
    const std::string OriginResponse = "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
                                       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                       "Connection: keep-alive\r\n\r\n4\r\nWiki\r\n5;ext=value\r\npedia\r\n"
                                       "0\r\nX-Trailer: done\r\n\r\n";
    Origin.Start(Expected, OriginResponse, OriginCloseMode::KeepOpen);

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://" + OriginHost +
        "/chunked HTTP/1.1\r\nHost: ignored.example\r\n"
        "Proxy-Authorization: " +
        std::string(ProxyAuthorization) + "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForResponse(IoTimeout));
    EXPECT_FALSE(Origin.WaitForComplete(std::chrono::milliseconds(100)));

    const auto Observation = ReadUntilClose(Client, IoTimeout);
    EXPECT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_EQ(Observation.Bytes, OriginResponse);
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    OperationsDrainObservation Drain;
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort(), IoTimeout, &Drain))
        << Drain.Description();

    CloseSocket(Client);
    Origin.Stop();
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, RelaysHttpUpgradeResponseAndTunnelBytes)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "GET /upgrade HTTP/1.1\r\nHost: " + OriginHost +
        "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    const std::string OriginResponse = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                                       "Upgrade: websocket\r\n\r\norigin-upgrade";
    constexpr std::string_view ClientUpgradePayload = "client-upgrade-payload";
    Origin.ExpectAfterResponse(std::string(ClientUpgradePayload));
    Origin.Start(Expected, OriginResponse);

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://" + OriginHost +
        "/upgrade HTTP/1.1\r\nHost: ignored.example\r\n"
        "Proxy-Authorization: " +
        std::string(ProxyAuthorization) + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));
    ASSERT_TRUE(Origin.WaitForResponse(IoTimeout));
    ASSERT_TRUE(WriteAll(Client, ClientUpgradePayload));

    const auto Observation = ReadUntilClose(Client, IoTimeout);
    EXPECT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_EQ(Observation.Bytes, OriginResponse);
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(Origin.Extra().empty());
    EXPECT_EQ(Origin.PostResponseCaptured(), ClientUpgradePayload);

    // 101 后是双向 tunnel；源站方向 EOF 不代表客户端已经发送写端 FIN。
    CloseSocket(Client);
    OperationsDrainObservation Drain;
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort(), IoTimeout, &Drain))
        << Drain.Description();
    Origin.Stop();
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}
