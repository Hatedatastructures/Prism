/**
 * @file LaunchDeep.cpp
 * @brief instance/worker/launch 深度纯函数测试
 * @details 通过 #include 源文件访问 launch.cpp 中所有同步函数，
 *          覆盖 prime、migrate_executor。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include "../../src/prism/instance/worker/launch.cpp"

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    namespace launch = psm::instance::worker::launch;

    // ─── prime() 测试 ──────────────────────────

    TEST(LaunchDeep, PrimeBasicSocket)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        sock.open(tcp::v4());

        launch::prime(sock, 8192);

        boost::system::error_code ec;
        tcp::no_delay no_delay_opt;
        sock.get_option(no_delay_opt, ec);
        EXPECT_TRUE(!ec) << "prime: no_delay option set without error";
        EXPECT_TRUE(no_delay_opt.value()) << "prime: no_delay is true";

        net::socket_base::receive_buffer_size rcv_opt;
        sock.get_option(rcv_opt, ec);
        EXPECT_TRUE(!ec) << "prime: receive_buffer_size set without error";

        net::socket_base::send_buffer_size snd_opt;
        sock.get_option(snd_opt, ec);
        EXPECT_TRUE(!ec) << "prime: send_buffer_size set without error";

        sock.close();
    }

    TEST(LaunchDeep, PrimeSmallBuffer)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        sock.open(tcp::v4());

        launch::prime(sock, 1024);

        boost::system::error_code ec;
        net::socket_base::receive_buffer_size rcv_opt;
        sock.get_option(rcv_opt, ec);
        EXPECT_TRUE(!ec) << "prime: small buffer set without error";

        sock.close();
    }

    TEST(LaunchDeep, PrimeLargeBuffer)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        sock.open(tcp::v4());

        launch::prime(sock, 1024 * 1024);

        boost::system::error_code ec;
        net::socket_base::receive_buffer_size rcv_opt;
        sock.get_option(rcv_opt, ec);
        EXPECT_TRUE(!ec) << "prime: large buffer set without error";

        sock.close();
    }

    TEST(LaunchDeep, PrimeOnConnectedSocket)
    {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        auto port = acceptor.local_endpoint().port();

        tcp::socket client(ioc);
        client.open(tcp::v4());
        client.bind(tcp::endpoint(tcp::v4(), 0));
        client.connect(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), port));

        tcp::socket server(ioc);
        acceptor.accept(server);

        launch::prime(client, 65536);

        boost::system::error_code ec;
        tcp::no_delay no_delay_opt;
        client.get_option(no_delay_opt, ec);
        EXPECT_TRUE(!ec) << "prime: connected socket no_delay set without error";
        EXPECT_TRUE(no_delay_opt.value()) << "prime: connected socket no_delay is true";

        client.close();
        server.close();
        acceptor.close();
    }

    // ─── migrate_executor() 测试 ───────────────

    TEST(LaunchDeep, MigrateExecutorBasic)
    {
        net::io_context ioc1;
        net::io_context ioc2;

        tcp::acceptor acceptor(ioc1, tcp::endpoint(tcp::v4(), 0));
        auto port = acceptor.local_endpoint().port();

        tcp::socket client(ioc1);
        client.open(tcp::v4());
        client.bind(tcp::endpoint(tcp::v4(), 0));
        client.connect(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), port));

        tcp::socket server(ioc1);
        acceptor.accept(server);

        EXPECT_TRUE(client.is_open()) << "migrate: client is open before migration";

        auto result = launch::migrate_executor(client, ioc2);
        EXPECT_TRUE(result.has_value()) << "migrate: returned valid socket";
        EXPECT_TRUE(result->is_open()) << "migrate: migrated socket is open";
        EXPECT_TRUE(!client.is_open()) << "migrate: original socket is empty after release";

        // 验证迁移后的 socket 仍然可以工作
        const char data[] = "hello";
        boost::system::error_code write_ec;
        net::write(server, net::buffer(data), write_ec);
        EXPECT_TRUE(!write_ec) << "migrate: write to server after migration succeeded";

        result->close();
        server.close();
        acceptor.close();
    }

    TEST(LaunchDeep, MigrateExecutorIPv6)
    {
        net::io_context ioc1;
        net::io_context ioc2;

        tcp::acceptor acceptor(ioc1, tcp::endpoint(tcp::v6(), 0));
        auto port = acceptor.local_endpoint().port();

        tcp::socket client(ioc1);
        client.open(tcp::v6());
        client.bind(tcp::endpoint(tcp::v6(), 0));
        client.connect(tcp::endpoint(net::ip::make_address_v6("::1"), port));

        tcp::socket server(ioc1);
        acceptor.accept(server);

        auto result = launch::migrate_executor(client, ioc2);
        EXPECT_TRUE(result.has_value()) << "migrate_ipv6: returned valid socket";
        EXPECT_TRUE(result->is_open()) << "migrate_ipv6: migrated socket is open";

        result->close();
        server.close();
        acceptor.close();
    }

    TEST(LaunchDeep, MigrateExecutorClosedSocket)
    {
        net::io_context ioc1;
        net::io_context ioc2;

        tcp::socket sock(ioc1);
        // socket 未打开，release 会返回无效句柄
        auto result = launch::migrate_executor(sock, ioc2);
        // 关闭的 socket release 返回的 handle 可能在 assign 时失败
        // 行为取决于平台，但不应崩溃
        EXPECT_TRUE(!sock.is_open()) << "migrate: closed socket stays closed";
    }

} // namespace
