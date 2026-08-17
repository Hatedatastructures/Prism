/**
 * @file NetworkingStressTest.cpp
 * @brief 网络层压力测试（T5-10 D7，smoke 版）
 * @details 覆盖：
 *          - TCP 连接风暴：并发 50 连接 × 10 轮，全部 echo 成功
 *          - UDP relay 长跑：1000 包双向往返
 *          - stress helper：gate 汇合 / leak_tracker 泄漏探测
 * @note smoke 参数（短时）；完整长跑在 CI/手动扩展轮次
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>

#include <common/core/net/dialer/dialer.hpp>
#include <common/core/net/udp_relay.hpp>
#include <common/core/transport/reliable.hpp>
#include <common/core/transport/unreliable.hpp>
#include <common/stress/stress_helper.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    /// 长跑缩放因子：NGX_STRESS_DURATION=秒 → 轮次放大（默认 1 = smoke）
    auto stress_scale() -> int
    {
        const auto *env = std::getenv("NGX_STRESS_DURATION");
        if (!env)
        {
            return 1;
        }
        const auto sec = std::atoi(env);
        if (sec <= 0)
        {
            return 1;
        }
        return (std::max)(1, sec / 5); // 每 5 秒扩 1 倍
    }

    /// TCP echo 服务器
    auto tcp_echo_server(tcp::socket sock) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        boost::system::error_code ec;
        while (true)
        {
            const auto n = co_await sock.async_read_some(net::buffer(buf),
                                                         net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            co_await sock.async_write_some(net::buffer(buf, n),
                                           net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
        }
    }

    TEST(NetworkStress, TcpConnectionStorm)
    {
        constexpr int conns_per_round = 50;
        const auto rounds = 10 * stress_scale();
        const auto total = conns_per_round * rounds;

        net::io_context ioc;
        std::exception_ptr ep;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
                const auto port = acceptor.local_endpoint().port();

                net::co_spawn(
                    ioc.get_executor(),
                    [&]() -> net::awaitable<void>
                    {
                        while (true)
                        {
                            boost::system::error_code ec;
                            auto sock = co_await acceptor.async_accept(
                                net::redirect_error(net::use_awaitable, ec));
                            if (ec)
                            {
                                co_return;
                            }
                            net::co_spawn(ioc.get_executor(), tcp_echo_server(std::move(sock)),
                                          net::detached);
                        }
                    },
                    net::detached);

                // 风暴：并发连接 × 多轮
                std::atomic<int> ok{0};
                preview::stress::gate g(ioc.get_executor(), total);
                for (int round = 0; round < rounds; ++round)
                {
                    for (int i = 0; i < conns_per_round; ++i)
                    {
                        net::co_spawn(
                            ioc.get_executor(),
                            [&, i]() -> net::awaitable<void>
                            {
                                std::error_code ec;
                                preview::network::dialer::dialer d(ioc.get_executor());
                                auto conn = co_await d.connect("127.0.0.1", port, ec);
                                if (ec || !conn)
                                {
                                    g.arrive();
                                    co_return;
                                }
                                const std::string msg = "storm-" + std::to_string(i);
                                co_await conn->async_write_some(
                                    std::span<const std::byte>(
                                        reinterpret_cast<const std::byte *>(msg.data()), msg.size()),
                                    ec);
                                std::array<std::byte, 64> buf{};
                                const auto n = co_await conn->async_read_some(buf, ec);
                                if (!ec && std::string_view(reinterpret_cast<const char *>(buf.data()),
                                                            n) == msg)
                                {
                                    ++ok;
                                }
                                conn->close();
                                g.arrive();
                            },
                            net::detached);
                    }
                }
                co_await g.wait();
                EXPECT_EQ(ok, total);
                acceptor.close();
            },
            [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(NetworkStress, UdpRelayLongRun)
    {
        const auto packets = 1000 * stress_scale();
        net::io_context ioc;

        auto a = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
        auto b = std::make_shared<preview::transport::unreliable>(ioc.get_executor());
        boost::system::error_code oec;
        a->native_socket().open(net::ip::udp::v4(), oec);
        a->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        b->native_socket().open(net::ip::udp::v4(), oec);
        b->native_socket().bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                preview::network::udp::relay_options opts;
                opts.idle_timeout = std::chrono::milliseconds(5000);
                preview::network::udp::udp_relay relay(a, b, opts);
                co_await relay.run();
            },
            net::detached);

        // 端 A/B 客户端（echo 型）
        net::ip::udp::socket ca(ioc.get_executor());
        net::ip::udp::socket cb(ioc.get_executor());
        ca.open(net::ip::udp::v4(), oec);
        ca.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        cb.open(net::ip::udp::v4(), oec);
        cb.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        const auto ca_ep = ca.local_endpoint();
        const auto cb_ep = cb.local_endpoint();
        const auto a_ep = a->native_socket().local_endpoint();
        const auto b_ep = b->native_socket().local_endpoint();

        std::exception_ptr ep;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                // 建立动态关联（ca/cb 各发首包配对）
                const std::string learn = "l";
                co_await ca.async_send_to(net::buffer(learn.data(), learn.size()), a_ep,
                                          net::redirect_error(net::use_awaitable, oec));
                co_await cb.async_send_to(net::buffer(learn.data(), learn.size()), b_ep,
                                          net::redirect_error(net::use_awaitable, oec));
                // 等配对后的学习包转发到 ca
                {
                    std::array<std::byte, 8> buf{};
                    net::ip::udp::endpoint src;
                    co_await ca.async_receive_from(net::buffer(buf), src,
                                                   net::redirect_error(net::use_awaitable, oec));
                }

                // cb 侧回显（收 B 中继数据 → 回发）
                net::co_spawn(
                    ioc.get_executor(),
                    [&]() -> net::awaitable<void>
                    {
                        for (int i = 0; i < packets; ++i)
                        {
                            std::array<std::byte, 64> buf{};
                            net::ip::udp::endpoint src;
                            boost::system::error_code ec;
                            const auto n = co_await cb.async_receive_from(
                                net::buffer(buf), src, net::redirect_error(net::use_awaitable, ec));
                            if (n > 0)
                            {
                                co_await cb.async_send_to(net::buffer(buf, n), src,
                                                          net::redirect_error(net::use_awaitable, ec));
                            }
                        }
                    },
                    net::detached);

                // ca 侧：发 1000 包 → 等回显
                int received = 0;
                for (int i = 0; i < packets; ++i)
                {
                    const std::string msg = "udp-" + std::to_string(i);
                    co_await ca.async_send_to(net::buffer(msg.data(), msg.size()), a_ep,
                                              net::redirect_error(net::use_awaitable, oec));
                    std::array<std::byte, 64> buf{};
                    net::ip::udp::endpoint src;
                    const auto n = co_await ca.async_receive_from(
                        net::buffer(buf), src, net::redirect_error(net::use_awaitable, oec));
                    if (n == msg.size() &&
                        std::string_view(reinterpret_cast<const char *>(buf.data()), n) == msg)
                    {
                        ++received;
                    }
                }
                EXPECT_EQ(received, packets);
            },
            [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(NetworkStress, LeakTrackerDetectsRelease)
    {
        auto obj = std::make_shared<int>(42);
        preview::stress::leak_tracker tracker;
        tracker.track(obj);
        EXPECT_EQ(tracker.total(), 1);
        EXPECT_FALSE(tracker.all_released());
        obj.reset();
        EXPECT_TRUE(tracker.all_released());
    }

    TEST(NetworkStress, GateSynchronizes)
    {
        net::io_context ioc;
        preview::stress::gate g(ioc.get_executor(), 3);
        std::atomic<int> arrived{0};

        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          for (int i = 0; i < 3; ++i)
                          {
                              ++arrived;
                              g.arrive();
                          }
                          co_await g.wait();
                          EXPECT_EQ(arrived, 3);
                      },
                      [&](std::exception_ptr e)
                      {
                          if (e)
                          {
                              std::rethrow_exception(e);
                          }
                          ioc.stop();
                      });
        ioc.run();
    }

} // namespace
