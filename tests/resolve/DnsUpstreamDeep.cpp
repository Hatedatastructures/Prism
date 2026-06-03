/**
 * @file DnsUpstreamDeep.cpp
 * @brief DNS upstream 匿名命名空间深度测试
 * @details 通过 #include 源文件访问 upstream.cpp 中匿名命名空间的
 *          transport_result、transport_context、query_context、
 *          is_timeout、udp_transport::close、tcp_transport::close、
 *          tls_transport::close、https_transport::close、
 *          以及 resolve() 空服务器路径和 query_via 的错误分类逻辑。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#include <gtest/gtest.h>

#define private public
#include <prism/resolve/dns/upstream.hpp>
#include "../../src/prism/resolve/dns/upstream.cpp"
#undef private

namespace
{
    namespace dns = psm::resolve::dns;
    namespace net = boost::asio;

    // ─── is_timeout ──────────────────────────────────

    TEST(DnsUpstreamDeep, IsTimeoutTrue)
    {
        auto ec = net::error::make_error_code(net::error::operation_aborted);
        EXPECT_TRUE(psm::resolve::dns::is_timeout(ec)) << "is_timeout: operation_aborted -> true";
    }

    TEST(DnsUpstreamDeep, IsTimeoutFalse)
    {
        auto ec = boost::system::errc::make_error_code(boost::system::errc::timed_out);
        EXPECT_TRUE(!psm::resolve::dns::is_timeout(ec)) << "is_timeout: timed_out -> false";
    }

    TEST(DnsUpstreamDeep, IsTimeoutSuccess)
    {
        boost::system::error_code ec;
        EXPECT_TRUE(!psm::resolve::dns::is_timeout(ec)) << "is_timeout: success -> false";
    }

    // ─── transport_context 构造 ──────────────────────

    TEST(DnsUpstreamDeep, TransportContextConstruction)
    {
        net::io_context ioc;
        psm::resolve::dns::transport_context ctx(ioc, 5000);
        EXPECT_TRUE(ctx.timeout_ms == 5000) << "transport_context: timeout_ms=5000";
    }

    // ─── transport_result 默认构造 ────────────────────

    TEST(DnsUpstreamDeep, TransportResultDefault)
    {
        psm::resolve::dns::transport_result tr;
        EXPECT_TRUE(!tr.response.has_value()) << "transport_result: no response by default";
        EXPECT_TRUE(tr.result.error == psm::fault::code::success) << "transport_result: default error=success";
    }

    // ─── query_context 构造 ───────────────────────────

    TEST(DnsUpstreamDeep, QueryContextConstruction)
    {
        auto mr = psm::memory::current_resource();
        dns::dns_remote server(mr);
        server.address = "8.8.8.8";
        server.port = 53;
        auto query = dns::message::make_query("example.com", dns::qtype::a, mr);

        psm::resolve::dns::query_context qctx{server, query, 4000, mr};
        EXPECT_TRUE(qctx.default_timeout == 4000) << "query_context: timeout=4000";
        EXPECT_TRUE(qctx.server.address == "8.8.8.8") << "query_context: server address";
    }

    // ─── udp_transport close（无 socket） ──────────────

    TEST(DnsUpstreamDeep, UdpTransportCloseNull)
    {
        psm::resolve::dns::udp_transport t;
        t.sock = nullptr;
        // 不应崩溃
        t.close();
        EXPECT_TRUE(true) << "udp_transport: close with null sock -> no crash";
    }

    TEST(DnsUpstreamDeep, UdpTransportCloseOpen)
    {
        net::io_context ioc;
        psm::resolve::dns::udp_transport t;
        t.sock = std::make_shared<net::ip::udp::socket>(ioc);
        t.sock->open(net::ip::udp::v4());
        EXPECT_TRUE(t.sock->is_open()) << "udp_transport: socket open before close";
        t.close();
        EXPECT_TRUE(!t.sock->is_open()) << "udp_transport: socket closed after close";
    }

    // ─── tcp_transport close ──────────────────────────

    TEST(DnsUpstreamDeep, TcpTransportCloseNull)
    {
        psm::resolve::dns::tcp_transport t;
        t.sock = nullptr;
        t.close();
        EXPECT_TRUE(true) << "tcp_transport: close with null sock -> no crash";
    }

    TEST(DnsUpstreamDeep, TcpTransportCloseOpen)
    {
        net::io_context ioc;
        psm::resolve::dns::tcp_transport t;
        t.sock = std::make_shared<net::ip::tcp::socket>(ioc);
        t.sock->open(net::ip::tcp::v4());
        EXPECT_TRUE(t.sock->is_open()) << "tcp_transport: socket open before close";
        t.close();
        EXPECT_TRUE(!t.sock->is_open()) << "tcp_transport: socket closed after close";
    }

    // ─── tls_transport close ──────────────────────────

    TEST(DnsUpstreamDeep, TlsTransportCloseNull)
    {
        psm::resolve::dns::tls_transport t;
        t.ssl_sock = nullptr;
        t.close();
        EXPECT_TRUE(true) << "tls_transport: close with null ssl_sock -> no crash";
    }

    // ─── https_transport close ────────────────────────

    TEST(DnsUpstreamDeep, HttpsTransportCloseNull)
    {
        psm::resolve::dns::https_transport t;
        t.ssl_sock = nullptr;
        t.close();
        EXPECT_TRUE(true) << "https_transport: close with null ssl_sock -> no crash";
    }

    // ─── resolve() 空服务器路径 ────────────────────────

    TEST(DnsUpstreamDeep, ResolveEmptyServers)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        // 不设置任何服务器

        std::exception_ptr ep;
        dns::query_result result(psm::memory::current_resource());

        auto coro = [&]() -> net::awaitable<void>
        {
            result = co_await ups.resolve("example.com", dns::qtype::a);
        };

        net::co_spawn(ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << "resolve empty servers exception: " << e.what();
            }
        }

        EXPECT_TRUE(result.error == psm::fault::code::dns_failed) << "resolve: empty servers -> dns_failed";
        EXPECT_TRUE(result.ips.empty()) << "resolve: empty servers -> no IPs";
    }

    // ─── resolve() 畸形服务器地址 ──────────────────────

    TEST(DnsUpstreamDeep, ResolveMalformedServerAddress)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());
        dns::dns_remote srv(psm::memory::current_resource());
        srv.address = "not-a-valid-address-xyz";
        srv.port = 53;
        srv.protocol = dns::dns_protocol::udp;
        servers.push_back(srv);
        ups.set_servers(servers);
        ups.set_mode(dns::resolve_mode::fallback);

        std::exception_ptr ep;
        dns::query_result result(psm::memory::current_resource());

        auto coro = [&]() -> net::awaitable<void>
        {
            result = co_await ups.resolve("example.com", dns::qtype::a);
        };

        net::co_spawn(ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << "resolve malformed exception: " << e.what();
            }
        }

        EXPECT_TRUE(psm::fault::failed(result.error)) << "resolve: malformed address -> failed";
    }

    // ─── resolve() fallback 模式单服务器失败 ──────────

    TEST(DnsUpstreamDeep, ResolveFallbackSingleServerFail)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());
        dns::dns_remote srv(psm::memory::current_resource());
        srv.address = "0.0.0.0";
        srv.port = 1;
        srv.protocol = dns::dns_protocol::udp;
        // 极短超时确保快速失败
        srv.timeout_ms = 1;
        servers.push_back(srv);
        ups.set_servers(servers);
        ups.set_mode(dns::resolve_mode::fallback);
        ups.set_timeout(1);

        std::exception_ptr ep;
        dns::query_result result(psm::memory::current_resource());

        auto coro = [&]() -> net::awaitable<void>
        {
            result = co_await ups.resolve("example.com", dns::qtype::a);
        };

        net::co_spawn(ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << "resolve fallback fail exception: " << e.what();
            }
        }

        EXPECT_TRUE(psm::fault::failed(result.error)) << "resolve: fallback single fail -> failed";
    }

    // ─── dial_target 构造 ─────────────────────────────

    TEST(DnsUpstreamDeep, DialTargetConstruction)
    {
        net::io_context ioc;
        auto ep = net::ip::tcp::endpoint(net::ip::make_address_v4("8.8.8.8"), 53);
        psm::resolve::dns::dial_target dt{ioc, ep};
        EXPECT_TRUE(dt.endpoint == ep) << "dial_target: endpoint matches";
    }

    // ─── tls_material 默认构造 ────────────────────────

    TEST(DnsUpstreamDeep, TlsMaterialDefault)
    {
        psm::resolve::dns::tls_material tm;
        EXPECT_TRUE(!tm.sock) << "tls_material: null sock by default";
        EXPECT_TRUE(!tm.ssl_ctx) << "tls_material: null ssl_ctx by default";
    }

    // ─── frame_context 构造 ───────────────────────────

    TEST(DnsUpstreamDeep, FrameContextConstruction)
    {
        auto mr = psm::memory::current_resource();
        boost::system::error_code ec;
        psm::resolve::dns::frame_context fctx{mr, ec};
        EXPECT_TRUE(!ec) << "frame_context: no error initially";
    }

    // ─── https_transport 字段默认值 ────────────────────

    TEST(DnsUpstreamDeep, HttpsTransportDefaults)
    {
        psm::resolve::dns::https_transport t;
        EXPECT_TRUE(!t.ssl_sock) << "https_transport: null ssl_sock";
        EXPECT_TRUE(!t.ssl_ctx) << "https_transport: null ssl_ctx";
        EXPECT_TRUE(t.http_path.empty()) << "https_transport: empty http_path";
        EXPECT_TRUE(t.host_header.empty()) << "https_transport: empty host_header";
        EXPECT_TRUE(!t.handshake_ok) << "https_transport: handshake_ok=false";
    }

    // ─── query_result 默认值 ──────────────────────────

    TEST(DnsUpstreamDeep, QueryResultDefaults)
    {
        auto mr = psm::memory::current_resource();
        dns::query_result qr(mr);
        EXPECT_TRUE(qr.error == psm::fault::code::success) << "query_result: default error=success";
        EXPECT_TRUE(qr.ips.empty()) << "query_result: default ips empty";
        EXPECT_TRUE(qr.rtt_ms == 0) << "query_result: default rtt_ms=0";
        EXPECT_TRUE(qr.server_addr.empty()) << "query_result: default server_addr empty";
    }

} // namespace
