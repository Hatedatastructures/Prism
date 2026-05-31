/**
 * @file LaunchPure.cpp
 * @brief Worker 启动模块纯函数单元测试
 * @details 测试 prime 和 migrate_executor 同步函数。
 *          使用 socket pair 而非 acceptor，避免阻塞在 accept()。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/instance/worker/launch.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @brief prime 设置 TCP_NODELAY 和缓冲区大小不崩溃
     */
    void TestPrimeSocketNoCrash(TestRunner &runner)
    {
        net::io_context ioc;
        // 使用 connect 自连模式创建 socket pair
        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        psm::instance::worker::launch::prime(server, 8192);
        runner.Check(true, "prime: no crash on valid socket");

        // 再次调用也不崩溃
        psm::instance::worker::launch::prime(server, 4096);
        runner.Check(true, "prime: repeated call no crash");

        server.close();
        client.close();
        acceptor.close();
    }

    /**
     * @brief prime 对已关闭 socket 不崩溃（内部忽略错误）
     */
    void TestPrimeSocketClosedNoCrash(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket socket(ioc);
        // socket 未打开，prime 应该内部忽略所有 set_option 错误
        psm::instance::worker::launch::prime(socket, 8192);
        runner.Check(true, "prime: closed socket no crash");
    }

    /**
     * @brief migrate_executor 成功迁移 socket 到新 io_context
     */
    void TestMigrateExecutorSuccess(TestRunner &runner)
    {
        net::io_context ioc1;
        net::io_context ioc2;

        tcp::acceptor acceptor(ioc1, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc1);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        auto migrated = psm::instance::worker::launch::migrate_executor(server, ioc2);
        runner.Check(migrated.has_value(), "migrate: success");
        runner.Check(migrated->is_open(), "migrate: socket open");
        runner.Check(!server.is_open(), "migrate: original socket released");

        migrated->close();
        client.close();
        acceptor.close();
    }

    /**
     * @brief migrate_executor 迁移到同一 io_context
     */
    void TestMigrateSameContext(TestRunner &runner)
    {
        net::io_context ioc;

        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        auto migrated = psm::instance::worker::launch::migrate_executor(server, ioc);
        runner.Check(migrated.has_value(), "migrate same ioc: success");
        runner.Check(migrated->is_open(), "migrate same ioc: socket open");

        migrated->close();
        client.close();
        acceptor.close();
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("LaunchPure");

    TestPrimeSocketNoCrash(runner);
    TestPrimeSocketClosedNoCrash(runner);
    TestMigrateExecutorSuccess(runner);
    TestMigrateSameContext(runner);

    return runner.Summary();
}
