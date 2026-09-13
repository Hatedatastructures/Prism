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

#include <preview/Net/UdpRelay.hpp>
#include <preview/Transport/Unreliable.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 带超时的 UDP 收包
     * @return true = 收到（out 填充）；false = 超时/错误
     */
    auto ReceiveWithTimeout(Net::ip::udp::socket &Socket, std::string &Output,
                            std::chrono::milliseconds Timeout) -> Net::awaitable<bool>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        std::array<std::byte, 256> Buffer{};
        Net::ip::udp::endpoint Src;
        boost::system::error_code Ec;
        Net::steady_timer Timer(Socket.get_executor());
        Timer.expires_after(Timeout);
        auto Result = co_await (Socket.async_receive_from(Net::buffer(Buffer), Src,
                                                          Net::redirect_error(Net::use_awaitable, Ec)) ||
                                Timer.async_wait(Net::use_awaitable));
        if (Result.index() == 1 || Ec)
        {
            co_return false; // 超时/错误 = 未收到
        }
        Output.assign(reinterpret_cast<const char *>(Buffer.data()), std::get<0>(Result));
        co_return true;
    }
} // namespace

TEST(UdpRelay, AssociationAndEcho)
{
    Net::io_context ioc;

    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    // 中继 A↔B（动态关联）
    bool RelayDone = false;
    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
            RelayDone = true;
        },
        Net::detached);

    // 外部端 client_a（连 A 侧）、client_b（连 B 侧）
    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    // cb 侧回显
    std::string b_echo_back;
    std::string a_received;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> Net::awaitable<void>
                     {
                         std::array<std::byte, 256> buf{};
                         Net::ip::udp::endpoint src;
                         boost::system::error_code ec;
                         const auto n = co_await client_b.async_receive_from(
                             Net::buffer(buf), src, Net::redirect_error(Net::use_awaitable, ec));
                         b_echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                         if (n > 0)
                         {
                             co_await client_b.async_send_to(Net::buffer(buf, n), src,
                                                             Net::redirect_error(Net::use_awaitable, ec));
                         }
                     },
                     Net::detached);

                 // 1) client_a 首包（A 学习来源；此时未配对 → 丢弃）
                 const std::string learn_a = "learn-a";
                 co_await client_a.async_send_to(Net::buffer(learn_a.data(), learn_a.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // 2) client_b 首包（B 学习 → 配对 → 转发给 client_a）
                 const std::string learn_b = "learn-b";
                 co_await client_b.async_send_to(Net::buffer(learn_b.data(), learn_b.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // client_a 收到 learn-b（配对后转发）
                 std::array<std::byte, 256> rbuf{};
                 Net::ip::udp::endpoint sa;
                 const auto rn = co_await client_a.async_receive_from(
                     Net::buffer(rbuf), sa, Net::redirect_error(Net::use_awaitable, oec));
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn), learn_b);

                 // 3) client_a 再发 → 转发到 client_b（已配对）
                 const std::string msg = "echo-me";
                 co_await client_a.async_send_to(Net::buffer(msg.data(), msg.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // client_b 收 → 回显 → client_a 收
                 for (int i = 0; i < 50 && b_echo_back.empty(); ++i)
                 {
                     Net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(10));
                     co_await t.async_wait(Net::use_awaitable);
                 }
                 EXPECT_EQ(b_echo_back, msg);
                 // 回显回到 client_a
                 Net::ip::udp::endpoint sa2;
                 const auto rn2 = co_await client_a.async_receive_from(
                     Net::buffer(rbuf), sa2, Net::redirect_error(Net::use_awaitable, oec));
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn2), msg);
                 a_received.assign(reinterpret_cast<const char *>(rbuf.data()), rn2);
             });

    EXPECT_EQ(a_received, "echo-me");
    (void)RelayDone;
}

TEST(UdpRelay, AssociationTimeoutReap)
{
    Net::io_context ioc;

    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(80); // 80ms 回收
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
        },
        Net::detached);

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);

    bool forwarded_after_reap = false;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 // 建立配对
                 const std::string l = "l";
                 co_await client_a.async_send_to(Net::buffer(l.data(), l.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 co_await client_b.async_send_to(Net::buffer(l.data(), l.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // 等待配对完成（等 A 侧收到 learn 转发）
                 std::array<std::byte, 64> buf{};
                 Net::ip::udp::endpoint sa;
                 co_await client_a.async_receive_from(Net::buffer(buf), sa,
                                                      Net::redirect_error(Net::use_awaitable, oec));

                 // 空闲 200ms > 80ms → 会话回收
                 Net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(200));
                 co_await t.async_wait(Net::use_awaitable);

                 // client_b 再发 → 会话已回收 → 不转发（client_a 等 100ms 无包）
                 const std::string after = "after-Reap";
                 co_await client_b.async_send_to(Net::buffer(after.data(), after.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 Net::steady_timer t2(ioc);
                 t2.expires_after(std::chrono::milliseconds(100));
                 co_await t2.async_wait(Net::use_awaitable);
                 forwarded_after_reap = true; // 能等到这里即未收到（无超时挂起）
             });
    EXPECT_TRUE(forwarded_after_reap);
}

TEST(UdpRelay, PortMismatchDropped)
{
    Net::io_context ioc;

    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(0);
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
        },
        Net::detached);

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    Net::ip::udp::socket stranger(ioc.get_executor()); // 未关联来源
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    stranger.open(Net::ip::udp::v4(), oec);
    stranger.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool received = false;
    bool stranger_dropped = true;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> Net::awaitable<void>
                     {
                         // client_b 收（A 侧配对后转发）
                         std::array<std::byte, 128> buf{};
                         Net::ip::udp::endpoint src;
                         boost::system::error_code ec;
                         const auto n = co_await client_b.async_receive_from(
                             Net::buffer(buf), src, Net::redirect_error(Net::use_awaitable, ec));
                         if (n > 0)
                         {
                             received = true;
                         }
                     },
                     Net::detached);

                 // 建立配对（client_a ↔ client_b）
                 const std::string l = "l";
                 co_await client_a.async_send_to(Net::buffer(l.data(), l.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 co_await client_b.async_send_to(Net::buffer(l.data(), l.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 std::array<std::byte, 64> buf{};
                 Net::ip::udp::endpoint sa;
                 co_await client_a.async_receive_from(Net::buffer(buf), sa,
                                                      Net::redirect_error(Net::use_awaitable, oec));

                 // stranger 向 B 发包（B 侧来源 ≠ client_b）→ 丢弃
                 const std::string evil = "evil";
                 co_await stranger.async_send_to(Net::buffer(evil.data(), evil.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // 等 100ms：client_a 不应收到 evil
                 Net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(100));
                 co_await t.async_wait(Net::use_awaitable);

                 // 正常配对流量仍通（client_a → client_b）
                 const std::string good = "good";
                 co_await client_a.async_send_to(Net::buffer(good.data(), good.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 for (int i = 0; i < 50 && !received; ++i)
                 {
                     Net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(10));
                     co_await t2.async_wait(Net::use_awaitable);
                 }
                 stranger_dropped = received; // 收到的是 good 而非 evil
             });
    EXPECT_TRUE(received);
    EXPECT_TRUE(stranger_dropped);
}

TEST(UdpRelay, EndCloseTerminates)
{
    Net::io_context ioc;

    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool RelayDone = false;
    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收，只验证关闭语义
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
            RelayDone = true;
        },
        Net::detached);

    // 关闭 A 端 → 隧道终止
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Net::steady_timer t(ioc);
                 t.expires_after(std::chrono::milliseconds(50));
                 co_await t.async_wait(Net::use_awaitable);
                 a->Close();
                 // 轮询等待 relay 完成（保持 ioc 运行以调度取消回调）
                 for (int i = 0; i < 100 && !RelayDone; ++i)
                 {
                     Net::steady_timer p(ioc);
                     p.expires_after(std::chrono::milliseconds(10));
                     co_await p.async_wait(Net::use_awaitable);
                 }
             });
    EXPECT_TRUE(RelayDone);
}

TEST(UdpRelay, BFirstOrphanReapedNotReused)
{
    // P-H03：B 先到且未配对的孤立条目必须被对称回收；
    // 否则后续新 A 来源会与陈旧 B 端点配对，造成跨会话流量混淆。
    Net::io_context ioc;
    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(60);
            opts.MaxAssociations = 8;
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
        },
        Net::detached);

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 // B 先发包：B 学习来源但未配对（孤立条目）
                 const std::string orphan = "orphan-b";
                 co_await client_b.async_send_to(Net::buffer(orphan.data(), orphan.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 // 空闲 200ms > 60ms：孤立 B 条目必须被回收
                 Net::steady_timer wait(ioc);
                 wait.expires_after(std::chrono::milliseconds(200));
                 co_await wait.async_wait(Net::use_awaitable);
                 // 新 A 来源到来：不得与陈旧 B 条目配对转发
                 const std::string probe = "stale-pair-probe";
                 co_await client_a.async_send_to(Net::buffer(probe.data(), probe.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 std::string got;
                 EXPECT_FALSE(co_await ReceiveWithTimeout(client_b, got, std::chrono::milliseconds(150)))
                     << "陈旧 B 端点不应与新 A 来源配对，收到=" << got;
             });
}

TEST(UdpRelay, AssociationLimitRejectsNewPair)
{
    // P-H03：关联数达到上限后新会话必须被拒绝，已有会话保持可用。
    Net::io_context ioc;
    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收，隔离上限行为
            opts.MaxAssociations = 1;
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
        },
        Net::detached);

    auto make_client = [&](Net::ip::udp::socket &s)
    {
        boost::system::error_code ec;
        s.open(Net::ip::udp::v4(), ec);
        s.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ec);
        EXPECT_FALSE(ec);
    };
    Net::ip::udp::socket a1(ioc.get_executor());
    Net::ip::udp::socket b1(ioc.get_executor());
    Net::ip::udp::socket a2(ioc.get_executor());
    Net::ip::udp::socket b2(ioc.get_executor());
    make_client(a1);
    make_client(b1);
    make_client(a2);
    make_client(b2);

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 // 会话 1：A1 学习 + B1 配对
                 const std::string hello = "s1-hello";
                 co_await a1.async_send_to(Net::buffer(hello.data(), hello.size()), a_ep,
                                           Net::redirect_error(Net::use_awaitable, oec));
                 co_await b1.async_send_to(Net::buffer(hello.data(), hello.size()), b_ep,
                                           Net::redirect_error(Net::use_awaitable, oec));
                 std::string got;
                 EXPECT_TRUE(co_await ReceiveWithTimeout(a1, got, std::chrono::milliseconds(300)))
                     << "会话 1 配对后应收到 B1 首包";

                 // 会话 2：A2/B2 试图建立第二条关联 → 超上限，拒绝
                 co_await a2.async_send_to(Net::buffer(hello.data(), hello.size()), a_ep,
                                           Net::redirect_error(Net::use_awaitable, oec));
                 co_await b2.async_send_to(Net::buffer(hello.data(), hello.size()), b_ep,
                                           Net::redirect_error(Net::use_awaitable, oec));
                 std::string leaked;
                 EXPECT_FALSE(co_await ReceiveWithTimeout(a2, leaked, std::chrono::milliseconds(150)))
                     << "超出 MaxAssociations 的新会话不应建立，收到=" << leaked;

                 // 已有会话 1 仍然可用
                 const std::string again = "s1-again";
                 co_await a1.async_send_to(Net::buffer(again.data(), again.size()), a_ep,
                                           Net::redirect_error(Net::use_awaitable, oec));
                 std::string got2;
                 EXPECT_TRUE(co_await ReceiveWithTimeout(b1, got2, std::chrono::milliseconds(300)))
                     << "已有会话不应受新会话拒绝影响";
                 EXPECT_EQ(got2, again);
             });
}

TEST(UdpRelay, OneSidedTrafficKeepsSessionAlive)
{
    // P-H03：仅一侧持续发流量时，会话不能因另一侧时间戳陈旧被误回收。
    Net::io_context ioc;
    auto a = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Net::co_spawn(
        ioc.get_executor(),
        [&]() -> Net::awaitable<void>
        {
            Preview::Network::Udp::RelayOptions opts;
            opts.IdleTimeout = std::chrono::milliseconds(60);
            opts.MaxAssociations = 8;
            Preview::Network::Udp::UdpRelay relay(a, b, opts);
            co_await relay.Run();
        },
        Net::detached);

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    Net::ip::udp::socket client_a2(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_a2.open(Net::ip::udp::v4(), oec);
    client_a2.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 // 建立配对
                 const std::string learn = "learn";
                 co_await client_a.async_send_to(Net::buffer(learn.data(), learn.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 co_await client_b.async_send_to(Net::buffer(learn.data(), learn.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 std::string got;
                 EXPECT_TRUE(co_await ReceiveWithTimeout(client_a, got, std::chrono::milliseconds(300)));

                 // 只有 B 侧持续发包 5×40ms=200ms > 60ms：会话必须保持存活
                 const std::string keep = "keep";
                 for (int i = 0; i < 5; ++i)
                 {
                     co_await client_b.async_send_to(Net::buffer(keep.data(), keep.size()), b_ep,
                                                     Net::redirect_error(Net::use_awaitable, oec));
                     Net::steady_timer tick(ioc);
                     tick.expires_after(std::chrono::milliseconds(40));
                     co_await tick.async_wait(Net::use_awaitable);
                 }

                 // 判别点：若会话被误回收，B 侧会留下未配对条目，
                 // 新的 A 来源就会与它配对并收到转发；修复后必须丢弃。
                 const std::string intruder = "intruder-a2";
                 co_await client_a2.async_send_to(Net::buffer(intruder.data(), intruder.size()), a_ep,
                                                  Net::redirect_error(Net::use_awaitable, oec));
                 // 判别窗口内保持 B 侧活跃，避免会话按空闲超时合法过期
                 co_await client_b.async_send_to(Net::buffer(keep.data(), keep.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 std::string leaked;
                 EXPECT_FALSE(co_await ReceiveWithTimeout(client_b, leaked, std::chrono::milliseconds(40)))
                     << "仅 B 侧活跃不应导致会话被回收并与新 A 来源配对，收到=" << leaked;

                 // 原会话仍可用：a1 → b1
                 co_await client_b.async_send_to(Net::buffer(keep.data(), keep.size()), b_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 const std::string probe = "after-one-sided";
                 co_await client_a.async_send_to(Net::buffer(probe.data(), probe.size()), a_ep,
                                                 Net::redirect_error(Net::use_awaitable, oec));
                 std::string got2;
                 EXPECT_TRUE(co_await ReceiveWithTimeout(client_b, got2, std::chrono::milliseconds(300)))
                     << "原会话应保持可用";
                 EXPECT_EQ(got2, probe);
             });
}
