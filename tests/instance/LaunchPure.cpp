/**
 * @file LaunchPure.cpp
 * @brief Worker 启动模块纯函数单元测试
 * @details 测试 prime 和 migrate_executor 同步函数。
 *          使用 socket pair 而非 acceptor，避免阻塞在 accept()。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/instance/worker/launch.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @brief prime 设置 TCP_NODELAY 和缓冲区大小不崩溃
     */
    TEST(LaunchPure, PrimeSocketNoCrash)
    {
        net::io_context ioc;
        // 使用 connect 自连模式创建 socket pair
        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        psm::instance::worker::launch::prime(server, 8192);
        EXPECT_TRUE(server.is_open()) << "prime: socket still open after prime";

        // 再次调用也不崩溃
        psm::instance::worker::launch::prime(server, 4096);
        EXPECT_TRUE(server.is_open()) << "prime: socket still open after second prime";

        server.close();
        client.close();
        acceptor.close();
    }

    /**
     * @brief prime 对已关闭 socket 不崩溃（内部忽略错误）
     */
    TEST(LaunchPure, PrimeSocketClosedNoCrash)
    {
        net::io_context ioc;
        tcp::socket socket(ioc);
        // socket 未打开，prime 应该内部忽略所有 set_option 错误
        psm::instance::worker::launch::prime(socket, 8192);
        // prime 成功返回即验证了内部错误被安全忽略
        EXPECT_TRUE(socket.is_open() == false) << "prime: closed socket remains closed after prime";
    }

    /**
     * @brief migrate_executor 成功迁移 socket 到新 io_context
     */
    TEST(LaunchPure, MigrateExecutorSuccess)
    {
        net::io_context ioc1;
        net::io_context ioc2;

        tcp::acceptor acceptor(ioc1, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc1);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        auto migrated = psm::instance::worker::launch::migrate_executor(server, ioc2);
        ASSERT_TRUE(migrated.has_value()) << "migrate: success";
        EXPECT_TRUE(migrated->is_open()) << "migrate: socket open";
        EXPECT_TRUE(!server.is_open()) << "migrate: original socket released";

        migrated->close();
        client.close();
        acceptor.close();
    }

    /**
     * @brief migrate_executor 迁移到同一 io_context
     */
    TEST(LaunchPure, MigrateSameContext)
    {
        net::io_context ioc;

        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ioc);
        client.connect(ep);
        tcp::socket server = acceptor.accept();

        auto migrated = psm::instance::worker::launch::migrate_executor(server, ioc);
        ASSERT_TRUE(migrated.has_value()) << "migrate same ioc: success";
        EXPECT_TRUE(migrated->is_open()) << "migrate same ioc: socket open";

        migrated->close();
        client.close();
        acceptor.close();
    }
} // namespace
