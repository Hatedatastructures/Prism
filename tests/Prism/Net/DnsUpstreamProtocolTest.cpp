/**
 * @file DnsUpstreamProtocolTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "DnsUpstreamTestSupport.hpp"

TEST(DnsUpstream, TestTimeoutOnSilentServer)
{
Net::io_context IoContext;
    auto SilentServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    SilentServer->Start();

    Server ServerConfig = SilentServer->MakeConfig();
    ServerConfig.TimeoutMs = 300;
    Upstream UpstreamOwner(IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("silent.com", QType::A);
                SilentServer->Close();
                co_await SilentServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, TestAllServersFail)
{
Net::io_context IoContext;
    auto FirstServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::EmptyAnswer);
    auto SecondServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    FirstServer->Start();
    SecondServer->Start();

    Server SecondServerConfig = SecondServer->MakeConfig();
    SecondServerConfig.TimeoutMs = 200;
    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {FirstServer->MakeConfig(), SecondServerConfig},
                                .QueryMode = Prism::Network::Dns::Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("none.com", QType::A);
                FirstServer->Close();
                SecondServer->Close();
                co_await FirstServer->Drain();
                co_await SecondServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, TestNxDomainReturnsSuccessEmpty)
{
    // NXDOMAIN 是"成功+空"：无错误码、空 IP（由上层负缓存），而非错误
Net::io_context IoContext;
    auto DnsServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::NxDomain);
    DnsServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(), UpstreamOptions{.Servers = {DnsServer->MakeConfig()}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("nx.example.com", QType::A);
                DnsServer->Close();
                co_await DnsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
    EXPECT_EQ(Result.Response.Rcode, 3u);
}

TEST(DnsUpstream, TestFallbackNxDomainStopsAtFirst)
{
    // 1.3 修复验证：首个上游回 NXDOMAIN 即终态，不再重试第二个上游
Net::io_context IoContext;
    auto NxDomainServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::NxDomain);
    auto GoodServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    NxDomainServer->Start();
    GoodServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {NxDomainServer->MakeConfig(), GoodServer->MakeConfig()},
                                .QueryMode = Prism::Network::Dns::Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("nx.example.com", QType::A);
                NxDomainServer->Close();
                GoodServer->Close();
                co_await NxDomainServer->Drain();
                co_await GoodServer->Drain();
            });

    // 应答来源是首个（NXDOMAIN）服务器而非被"跳过"到第二个
    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
    EXPECT_EQ(Result.ServerAddr, NxDomainServer->Addr());
}

TEST(DnsUpstream, TestDotHandshakeAndFrameRead)
{
    // DoT 路径覆盖（此前零覆盖）：TLS 握手 HandshakeTls + 帧读取 ReadTcpFrame。
    // responder 解析长度帧并返回 QR=1、ID/question 匹配的合法 NODATA 应答；
    // 保留原来的无错误与空 IP 断言，同时覆盖 DoT 的成功校验路径。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, MakeDotDnsAnswerResponder());
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Tls;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("dot.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, TestDohHandshakeAndHttpRead)
{
    // DoH 路径覆盖（此前零覆盖）：TLS 握手 + HTTP 响应解析
    // （状态码校验、Content-Length 头区解析、\r\n\r\n 扫描、报文体收满）。
    // responder 将 HTTP POST 中的 query 转为 QR=1、ID/question 匹配的合法 NODATA answer。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, MakeDohDnsAnswerResponder("HTTP/1.1 200 OK"));
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Https;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.HttpPath = "/dns-query";

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("doh.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

