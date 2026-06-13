/**
 * @file HealthDeep.cpp
 * @brief connect/pool/health 深度纯函数测试
 * @details 通过 #include 源文件访问 health.cpp 中所有同步函数，
 *          覆盖 health() 和 healthy_fast() 的所有分支。
 *          使用真实 io_context + tcp::socket 测试各种 socket 状态。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include "../../src/prism/net/connect/pool/health.cpp"

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    // ─── health() 测试 ─────────────────────────

    TEST(HealthDeep, HealthClosedSocket)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        // socket 未 open -> is_open() == false
        auto state = psm::connect::health(sock);
        EXPECT_TRUE(state == psm::connect::socket_state::invalid)
            << "health: closed socket -> invalid";
    }

    TEST(HealthDeep, HealthOpenSocketNoConnection)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        sock.open(tcp::v4());
        // socket 已 open 但未连接 -> getsockopt 可能有 error 或 available 会失败
        auto state = psm::connect::health(sock);
        // 未连接的 socket 在 Win32 上行为不固定：
        // getsockopt 可能成功，available 返回 0，peek 返回 0 → fin
        // 或者 getsockopt 失败 → error / invalid
        EXPECT_TRUE(state == psm::connect::socket_state::error
                    || state == psm::connect::socket_state::invalid
                    || state == psm::connect::socket_state::fin)
            << "health: open unconnected socket -> state=" + std::to_string(static_cast<int>(state));
        sock.close();
    }

    TEST(HealthDeep, HealthConnectedSocketPair)
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

        // 刚连接的 socket 应该是 healthy
        auto state = psm::connect::health(client);
        EXPECT_TRUE(state == psm::connect::socket_state::healthy)
            << "health: connected socket -> healthy";
        client.close();
        server.close();
        acceptor.close();
    }

    TEST(HealthDeep, HealthSocketWithPendingData)
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

        // 发送数据到 client
        std::string data = "hello";
        net::write(server, net::buffer(data));

        // 给 io_context 机会处理
        ioc.run_one();
        ioc.restart();

        auto state = psm::connect::health(client);
        EXPECT_TRUE(state == psm::connect::socket_state::has_data)
            << "health: socket with pending data -> has_data";

        client.close();
        server.close();
        acceptor.close();
    }

    TEST(HealthDeep, HealthClosedAfterConnect)
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

        // 关闭 server 端 -> client 端应检测到 FIN
        server.close();
        // 给 io_context 机会处理
        ioc.run_one();
        ioc.restart();

        auto state = psm::connect::health(client);
        EXPECT_TRUE(state == psm::connect::socket_state::fin ||
                         state == psm::connect::socket_state::has_data)
            << "health: after peer close -> fin or has_data";

        client.close();
        acceptor.close();
    }

    // ─── healthy_fast() 测试 ────────────────────

    TEST(HealthDeep, HealthyFastClosedSocket)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        auto result = psm::connect::healthy_fast(sock);
        EXPECT_TRUE(!result) << "healthy_fast: closed socket -> false";
    }

    TEST(HealthDeep, HealthyFastOpenUnconnected)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);
        sock.open(tcp::v4());
        auto result = psm::connect::healthy_fast(sock);
        EXPECT_TRUE(!result) << "healthy_fast: open unconnected socket -> false";
        sock.close();
    }

    TEST(HealthDeep, HealthyFastConnectedSocket)
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

        auto result = psm::connect::healthy_fast(client);
        EXPECT_TRUE(result) << "healthy_fast: connected socket -> true";

        client.close();
        server.close();
        acceptor.close();
    }

    TEST(HealthDeep, HealthyFastWithPendingData)
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

        // 发送数据
        std::string data = "test";
        net::write(server, net::buffer(data));
        ioc.run_one();
        ioc.restart();

        // 有待读数据 -> healthy_fast 应返回 false（脏数据不适合复用）
        auto result = psm::connect::healthy_fast(client);
        EXPECT_TRUE(!result) << "healthy_fast: socket with pending data -> false";

        client.close();
        server.close();
        acceptor.close();
    }

    TEST(HealthDeep, HealthyFastAfterPeerClose)
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

        // 关闭 server 端 -> client 应检测到 FIN
        server.close();
        ioc.run_one();
        ioc.restart();

        auto result = psm::connect::healthy_fast(client);
        EXPECT_TRUE(!result) << "healthy_fast: after peer close -> false";

        client.close();
        acceptor.close();
    }

    TEST(HealthDeep, HealthyFastNonBlockingSocket)
    {
        // 测试已经是 non-blocking 模式的 socket
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        auto port = acceptor.local_endpoint().port();

        tcp::socket client(ioc);
        client.open(tcp::v4());
        client.bind(tcp::endpoint(tcp::v4(), 0));
        client.connect(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), port));

        tcp::socket server(ioc);
        acceptor.accept(server);

        // 手动设为 non_blocking
        client.non_blocking(true);

        auto result = psm::connect::healthy_fast(client);
        EXPECT_TRUE(result) << "healthy_fast: non-blocking connected socket -> true";

        client.close();
        server.close();
        acceptor.close();
    }

} // namespace
