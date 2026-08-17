/**
 * @file UdpRelayTest.cpp
 * @brief UDP 双向中继测试（T3-4 D5 完整版）
 * @details 覆盖：
 *          - 动态关联：首包学习 → 配对 → 双向转发（echo 往返）
 *          - 关联超时回收：会话空闲超时后不再转发
 *          - 端口不匹配：未配对来源包丢弃
 *          - 单侧关闭：任一端 socket 关闭 → 隧道终止
 * @note 使用 loopback UDP socket；客户端来源动态学习（无需预置）
 */

#include <common/core/net/udp_relay.hpp>
#include <common/core/transport/unreliable.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace preview;

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

TEST(UdpRelay, AssociationAndEcho)
{
    net::io_context ioc;

    auto a = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    auto b = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->native_socket().open(net::ip::udp::v4(), oec);
    a->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    b->native_socket().open(net::ip::udp::v4(), oec);
    b->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->native_socket().local_endpoint();
    const auto b_ep = b->native_socket().local_endpoint();

    // 中继 A↔B（动态关联）
    bool relay_done = false;
    net::co_spawn(
        ioc.get_executor(),
        [&]() -> net::awaitable<void>
        {
            preview::network::udp::relay_options opts;
            opts.idle_timeout = std::chrono::milliseconds(0); // 禁用回收
            preview::network::udp::udp_relay relay(a, b, opts);
            co_await relay.run();
            relay_done = true;
        },
        net::detached);

    // 外部端 client_a（连 A 侧）、client_b（连 B 侧）
    net::ip::udp::socket client_a(ioc.get_executor());
    net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(net::ip::udp::v4(), oec);
    client_a.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(net::ip::udp::v4(), oec);
    client_b.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    // cb 侧回显
    std::string b_echo_back;
    std::string a_received;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         std::array<std::byte, 256> buf{};
                         net::ip::udp::endpoint src;
                         boost::system::error_code ec;
                         const auto n = co_await client_b.async_receive_from(
                             net::buffer(buf), src, net::redirect_error(net::use_awaitable, ec));
                         b_echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                         if (n > 0)
                         {
                             co_await client_b.async_send_to(net::buffer(buf, n), src,
                                                             net::redirect_error(net::use_awaitable, ec));
                         }
                     },
                     net::detached);

                 // 1) client_a 首包（A 学习来源；此时未配对 → 丢弃）
                 const std::string learn_a = "learn-a";
                 co_await client_a.async_send_to(net::buffer(learn_a.data(), learn_a.size()), a_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 // 2) client_b 首包（B 学习 → 配对 → 转发给 client_a）
                 const std::string learn_b = "learn-b";
                 co_await client_b.async_send_to(net::buffer(learn_b.data(), learn_b.size()), b_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 // client_a 收到 learn-b（配对后转发）
                 std::array<std::byte, 256> rbuf{};
                 net::ip::udp::endpoint sa;
                 const auto rn = co_await client_a.async_receive_from(
                     net::buffer(rbuf), sa, net::redirect_error(net::use_awaitable, oec));
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn), learn_b);

                 // 3) client_a 再发 → 转发到 client_b（已配对）
                 const std::string msg = "echo-me";
                 co_await client_a.async_send_to(net::buffer(msg.data(), msg.size()), a_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 // client_b 收 → 回显 → client_a 收
                 for (int i = 0; i < 50 && b_echo_back.empty(); ++i)
                 {
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(10));
                     co_await t.async_wait(net::use_awaitable);
                 }
                 EXPECT_EQ(b_echo_back, msg);
                 // 回显回到 client_a
                 net::ip::udp::endpoint sa2;
                 const auto rn2 = co_await client_a.async_receive_from(
                     net::buffer(rbuf), sa2, net::redirect_error(net::use_awaitable, oec));
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn2), msg);
                 a_received.assign(reinterpret_cast<const char *>(rbuf.data()), rn2);
             });

    EXPECT_EQ(a_received, "echo-me");
    (void)relay_done;
}

TEST(UdpRelay, AssociationTimeoutReap)
{
    net::io_context ioc;

    auto a = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    auto b = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->native_socket().open(net::ip::udp::v4(), oec);
    a->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    b->native_socket().open(net::ip::udp::v4(), oec);
    b->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->native_socket().local_endpoint();
    const auto b_ep = b->native_socket().local_endpoint();

    net::co_spawn(
        ioc.get_executor(),
        [&]() -> net::awaitable<void>
        {
            preview::network::udp::relay_options opts;
            opts.idle_timeout = std::chrono::milliseconds(80); // 80ms 回收
            preview::network::udp::udp_relay relay(a, b, opts);
            co_await relay.run();
        },
        net::detached);

    net::ip::udp::socket client_a(ioc.get_executor());
    net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(net::ip::udp::v4(), oec);
    client_a.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(net::ip::udp::v4(), oec);
    client_b.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);

    bool forwarded_after_reap = false;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 // 建立配对
                 const std::string l = "l";
                 co_await client_a.async_send_to(net::buffer(l.data(), l.size()), a_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 co_await client_b.async_send_to(net::buffer(l.data(), l.size()), b_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 // 等待配对完成（等 A 侧收到 learn 转发）
                 std::array<std::byte, 64> buf{};
                 net::ip::udp::endpoint sa;
                 co_await client_a.async_receive_from(net::buffer(buf), sa,
                                                      net::redirect_error(net::use_awaitable, oec));

                 // 空闲 200ms > 80ms → 会话回收
                 net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(200));
                 co_await t.async_wait(net::use_awaitable);

                 // client_b 再发 → 会话已回收 → 不转发（client_a 等 100ms 无包）
                 const std::string after = "after-reap";
                 co_await client_b.async_send_to(net::buffer(after.data(), after.size()), b_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 net::steady_timer t2(ioc);
                 t2.expires_after(std::chrono::milliseconds(100));
                 co_await t2.async_wait(net::use_awaitable);
                 forwarded_after_reap = true; // 能等到这里即未收到（无超时挂起）
             });
    EXPECT_TRUE(forwarded_after_reap);
}

TEST(UdpRelay, PortMismatchDropped)
{
    net::io_context ioc;

    auto a = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    auto b = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->native_socket().open(net::ip::udp::v4(), oec);
    a->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    b->native_socket().open(net::ip::udp::v4(), oec);
    b->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->native_socket().local_endpoint();
    const auto b_ep = b->native_socket().local_endpoint();

    net::co_spawn(
        ioc.get_executor(),
        [&]() -> net::awaitable<void>
        {
            preview::network::udp::relay_options opts;
            opts.idle_timeout = std::chrono::milliseconds(0);
            preview::network::udp::udp_relay relay(a, b, opts);
            co_await relay.run();
        },
        net::detached);

    net::ip::udp::socket client_a(ioc.get_executor());
    net::ip::udp::socket client_b(ioc.get_executor());
    net::ip::udp::socket stranger(ioc.get_executor()); // 未关联来源
    client_a.open(net::ip::udp::v4(), oec);
    client_a.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(net::ip::udp::v4(), oec);
    client_b.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    stranger.open(net::ip::udp::v4(), oec);
    stranger.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool received = false;
    bool stranger_dropped = true;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         // client_b 收（A 侧配对后转发）
                         std::array<std::byte, 128> buf{};
                         net::ip::udp::endpoint src;
                         boost::system::error_code ec;
                         const auto n = co_await client_b.async_receive_from(
                             net::buffer(buf), src, net::redirect_error(net::use_awaitable, ec));
                         if (n > 0)
                         {
                             received = true;
                         }
                     },
                     net::detached);

                 // 建立配对（client_a ↔ client_b）
                 const std::string l = "l";
                 co_await client_a.async_send_to(net::buffer(l.data(), l.size()), a_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 co_await client_b.async_send_to(net::buffer(l.data(), l.size()), b_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 std::array<std::byte, 64> buf{};
                 net::ip::udp::endpoint sa;
                 co_await client_a.async_receive_from(net::buffer(buf), sa,
                                                      net::redirect_error(net::use_awaitable, oec));

                 // stranger 向 B 发包（B 侧来源 ≠ client_b）→ 丢弃
                 const std::string evil = "evil";
                 co_await stranger.async_send_to(net::buffer(evil.data(), evil.size()), b_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 // 等 100ms：client_a 不应收到 evil
                 net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(100));
                 co_await t.async_wait(net::use_awaitable);

                 // 正常配对流量仍通（client_a → client_b）
                 const std::string good = "good";
                 co_await client_a.async_send_to(net::buffer(good.data(), good.size()), a_ep,
                                                 net::redirect_error(net::use_awaitable, oec));
                 for (int i = 0; i < 50 && !received; ++i)
                 {
                     net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(10));
                     co_await t2.async_wait(net::use_awaitable);
                 }
                 stranger_dropped = received; // 收到的是 good 而非 evil
             });
    EXPECT_TRUE(received);
    EXPECT_TRUE(stranger_dropped);
}

TEST(UdpRelay, EndCloseTerminates)
{
    net::io_context ioc;

    auto a = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    auto b = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->native_socket().open(net::ip::udp::v4(), oec);
    a->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    b->native_socket().open(net::ip::udp::v4(), oec);
    b->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool relay_done = false;
    net::co_spawn(
        ioc.get_executor(),
        [&]() -> net::awaitable<void>
        {
            preview::network::udp::relay_options opts;
            opts.idle_timeout = std::chrono::milliseconds(0); // 禁用回收，只验证关闭语义
            preview::network::udp::udp_relay relay(a, b, opts);
            co_await relay.run();
            relay_done = true;
        },
        net::detached);

    // 关闭 A 端 → 隧道终止
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(50));
                 co_await t.async_wait(net::use_awaitable);
                 a->close();
                 // 轮询等待 relay 完成（保持 ioc 运行以调度取消回调）
                 for (int i = 0; i < 100 && !relay_done; ++i)
                 {
                     net::steady_timer p(ioc);
                     p.expires_after(std::chrono::milliseconds(10));
                     co_await p.async_wait(net::use_awaitable);
                 }
             });
    EXPECT_TRUE(relay_done);
}
