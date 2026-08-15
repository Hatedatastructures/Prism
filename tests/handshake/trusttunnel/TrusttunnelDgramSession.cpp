/**
 * @file TrusttunnelDgramSession.cpp
 * @brief TrustTunnel dgram 包连接双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect_packet / 服务端 accept_packet（CONNECT 认证握手）→ 数据报往返
 * 2. 错误分支：io_error（对端关闭）/ unexpected_eof（读 EOF）
 * 3. 装饰器链方法：executor / transport_type / next_layer / stream / release / close / cancel
 * @note 使用 make_memory_pair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/stealth/trusttunnel/trusttunnel.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(TrusttunnelDgramSession, SendReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept_packet 完成 CONNECT 认证 → dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trusttunnel::server_config cfg;
                         cfg.username = "admin";
                         cfg.password = "secret";
                         auto [err, target, dg] =
                             co_await trusttunnel::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                                 cfg);
                         if (err != error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "accept_packet failed";
                             co_return;
                         }
                         EXPECT_EQ(target, "example.com");
                         EXPECT_EQ(dg->transport_type(), psmtest::transmission::type::udp);
                         std::string host;
                         std::uint16_t port = 0;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->async_receive_from(host, port, payload);
                         EXPECT_EQ(rerr, error::none);
                         EXPECT_EQ(host, "dns.google");
                         EXPECT_EQ(port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "dgram hello");
                         // 回发
                         const auto serr = co_await dg->async_send_to(host, port, payload);
                         EXPECT_EQ(serr, error::none);
                         // 透传读写（passthrough）
                         std::array<std::byte, 8> raw{};
                         std::error_code ec;
                         const auto w = co_await dg->async_write_some(
                             std::span<const std::byte>(raw.data(), 4), ec);
                         EXPECT_EQ(w, 4u);
                         const auto r = co_await dg->async_read_some(raw, ec);
                         EXPECT_GT(r, 0u); // 客户端透传写的数据
                         EXPECT_TRUE(dg->stream());
                         EXPECT_NE(dg->next_layer(), nullptr);
                         EXPECT_NE(dg->lowest_layer<memory_stream>(), nullptr);
                         const trusttunnel::dgram *const_dg = dg.get();
                         EXPECT_NE(const_dg->next_layer(), nullptr);
                         // 底层 conn 的 const 装饰器导航
                         auto inner = dg->stream();
                         const auto *const_conn = dynamic_cast<const trusttunnel::conn *>(inner.get());
                         EXPECT_NE(const_conn, nullptr);
                         if (const_conn)
                         {
                             EXPECT_NE(const_conn->next_layer(), nullptr);
                         }
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     trusttunnel::client_config cfg;
                     cfg.username = "admin";
                     cfg.password = "secret";
                     auto [herr, dg] = co_await trusttunnel::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), cfg, "example.com", 443);
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     EXPECT_TRUE(dg->executor());
                     const std::string p = "dgram hello";
                     const auto serr = co_await dg->async_send_to(
                         "dns.google", 53,
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, error::none);
                     // 读取回发帧（1B hostlen + host + 2B port + payload）
                     std::string host;
                     std::uint16_t port = 0;
                     std::vector<std::uint8_t> back;
                     const auto rerr = co_await dg->async_receive_from(host, port, back);
                     EXPECT_EQ(rerr, error::none);
                     EXPECT_EQ(host, "dns.google");
                     EXPECT_EQ(port, 53u);
                     EXPECT_EQ(std::string(back.begin(), back.end()), "dgram hello");
                     // 透传写（服务端透传读的数据）
                     const std::array<std::byte, 8> raw{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(raw.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                     dg->close();
                     dg->cancel();
                     auto released = dg->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(dg->next_layer(), nullptr);
                 });
    }

    TEST(TrusttunnelDgramSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：凭据不匹配 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trusttunnel::server_config cfg;
                         cfg.username = "admin";
                         cfg.password = "secret";
                         auto [err, target, dg] =
                             co_await trusttunnel::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                                 cfg);
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(dg);
                         (void)target;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     trusttunnel::client_config cfg;
                     cfg.username = "admin";
                     cfg.password = "wrong";
                     auto [herr, dg] = co_await trusttunnel::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), cfg, "example.com", 443);
                     EXPECT_EQ(herr, error::none); // 客户端只发送 CONNECT，不感知认证结果
                     if (dg)
                     {
                         dg->close();
                     }
                 });
    }

    TEST(TrusttunnelDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<trusttunnel::dgram>(
                         std::make_shared<memory_stream>(std::move(a)));
                     b.close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->async_send_to(
                         "example.com", 80,
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                 });
    }

    TEST(TrusttunnelDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<trusttunnel::dgram>(
                         std::make_shared<memory_stream>(std::move(b)));
                     a.close(); // 对端关闭 → 读 EOF → unexpected_eof
                     std::string host;
                     std::uint16_t port = 0;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(host, port, payload);
                     EXPECT_EQ(err, error::unexpected_eof);
                     dg->close();
                 });
    }

} // namespace
