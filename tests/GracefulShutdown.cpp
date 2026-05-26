/**
 * @file GracefulShutdown.cpp
 * @brief 优雅关闭幂等性测试
 * @details 验证 listener::stop()、worker::stop()、session::close()
 * 的幂等性——多次调用不应崩溃或抛异常。
 */

#include <prism/config.hpp>
#include <prism/context/context.hpp>
#include <prism/account/directory.hpp>
#include <prism/instance/front/listener.hpp>
#include <prism/instance/front/balancer.hpp>
#include <prism/instance/worker/worker.hpp>
#include <prism/instance/session/session.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

#ifdef _WIN32
#include <windows.h>
#endif

// ============================================================
// 测试用例
// ============================================================

/**
 * @brief 测试 listener::stop() 幂等性
 * @details 构造 listener 对象后连续调用两次 stop()，
 * 验证第二次调用不崩溃、不抛异常。
 */
void TestListenerStopIdempotent(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestListenerStopIdempotent ===");

    try
    {
        // 构造 balancer（空绑定，仅用于构造 listener）
        psm::memory::vector<psm::instance::front::balancer::worker_binding> bindings(
            psm::memory::current_resource());
        psm::instance::front::balancer bal(std::move(bindings));

        // 构造配置，使用 127.0.0.1:0 避免端口冲突
        psm::config cfg;
        cfg.instance.addressable.host = "127.0.0.1";
        cfg.instance.addressable.port = 0;

        psm::instance::front::listener lst(cfg, bal);

        // 第一次 stop：正常关闭
        lst.stop();
        runner.LogPass("listener::stop() first call succeeded");

        // 第二次 stop：应幂等，不崩溃
        lst.stop();
        runner.LogPass("listener::stop() second call succeeded (idempotent)");
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("TestListenerStopIdempotent: {}", e.what()));
    }
}

/**
 * @brief 测试 worker::stop() 幂等性
 * @details 构造 worker 对象后连续调用两次 stop()，
 * 验证第二次调用不崩溃、不抛异常。
 */
void TestWorkerStopIdempotent(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestWorkerStopIdempotent ===");

    try
    {
        psm::config cfg;
        cfg.instance.addressable.host = "127.0.0.1";
        cfg.instance.addressable.port = 0;

        auto account_store = std::make_shared<psm::account::directory>(
            psm::memory::system::global_pool());

        psm::instance::worker::worker wrk(cfg, std::move(account_store));

        // 第一次 stop：正常关闭
        wrk.stop();
        runner.LogPass("worker::stop() first call succeeded");

        // 第二次 stop：应幂等，不崩溃
        wrk.stop();
        runner.LogPass("worker::stop() second call succeeded (idempotent)");
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("TestWorkerStopIdempotent: {}", e.what()));
    }
}

/**
 * @brief 测试 session::close() 幂等性
 * @details 创建 session 对象后连续调用两次 close()，
 * 验证第二次调用不崩溃、不抛异常。session 的 close()
 * 内部通过状态机保证幂等。
 */
void TestSessionCloseIdempotent(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestSessionCloseIdempotent ===");

    try
    {
        net::io_context ioc;

        // 创建连接池和路由器（空 DNS 配置）
        psm::resolve::dns::config dns_cfg;
        auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
        auto router = std::make_unique<psm::connect::router>(
            psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

        // 创建 SSL 上下文
        auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        ssl_ctx->set_verify_mode(ssl::verify_none);

        // 构造 server 上下文
        psm::config cfg;
        auto account_store = std::make_shared<psm::account::directory>(
            psm::memory::system::global_pool());

        psm::context::server server_ctx{
            std::atomic<std::shared_ptr<const psm::config>>{
                std::make_shared<const psm::config>(cfg)},
            ssl_ctx,
            account_store};

        // 构造 worker 上下文
        auto mr = psm::memory::system::local_pool();
        psm::context::worker worker_ctx{ioc, *router, mr};

        // 创建一对已连接的 socket，模拟入站传输
        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        const auto ep = acceptor.local_endpoint();
        tcp::socket client_socket(ioc);
        client_socket.connect(ep);
        tcp::socket server_socket = acceptor.accept();

        // 包装为 reliable 传输层
        auto inbound = psm::transport::make_reliable(std::move(server_socket));

        // 创建 session
        psm::instance::session::session_params params{
            server_ctx, worker_ctx, std::move(inbound)};
        auto sess = psm::instance::session::make_session(std::move(params));

        // 第一次 close：正常关闭
        sess->close();
        runner.LogPass("session::close() first call succeeded");

        // 第二次 close：应幂等，不崩溃
        sess->close();
        runner.LogPass("session::close() second call succeeded (idempotent)");

        // 清理客户端 socket
        boost::system::error_code ec;
        client_socket.close(ec);
        acceptor.close(ec);
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("TestSessionCloseIdempotent: {}", e.what()));
    }
}

// ============================================================
// main
// ============================================================

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行所有优雅关闭幂等性测试。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    psm::testing::TestRunner runner("GracefulShutdown");
    runner.LogInfo("Starting GracefulShutdown tests...");

    TestListenerStopIdempotent(runner);
    TestWorkerStopIdempotent(runner);
    TestSessionCloseIdempotent(runner);

    return runner.Summary();
}
