/**
 * @file Socks5DgramSession.cpp
 * @brief SOCKS5 dgram 包连接双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect_packet / 服务端 accept_packet（UDP_ASSOCIATE 握手）→ 数据报往返
 * 2. 地址解析：IPv4 / 域名 / IPv6
 * 3. 错误分支：bad_message（RSV/FRAG 非法、ATYP 非法）/ io_error / unexpected_eof
 * 4. 装饰器链方法：executor / transport_type / next_layer / stream / release
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
#include <common/proxy/socks5/socks5.hpp>
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

    /// 构造 socks5 目标地址
    auto make_addr(socks5::address_type type, std::string host, std::uint16_t port)
        -> socks5::address
    {
        socks5::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    TEST(Socks5DgramSession, SendReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept_packet 完成 UDP_ASSOCIATE 握手 → dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         socks5::server_config cfg;
                         cfg.enable_udp = true;
                         auto [err, req, dg] =
                             co_await socks5::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                            cfg);
                         if (err != error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "accept_packet failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, socks5::command::udp_associate);
                         EXPECT_EQ(dg->transport_type(), psmtest::transmission::type::udp);
                         // 接收两个包（域名 + IPv4）
                         for (int i = 0; i < 2; ++i)
                         {
                             socks5::address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await dg->async_receive_from(src, payload);
                             EXPECT_EQ(rerr, error::none);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.type, socks5::address_type::domain);
                                 EXPECT_EQ(src.host, "example.com");
                                 EXPECT_EQ(src.port, 53u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "dns query");
                             }
                             else
                             {
                                 EXPECT_EQ(src.type, socks5::address_type::ipv4);
                                 EXPECT_EQ(src.host, "8.8.8.8");
                                 EXPECT_EQ(src.port, 443u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "second pkt");
                             }
                         }
                         EXPECT_TRUE(dg->stream());
                         EXPECT_NE(dg->next_layer(), nullptr);
                         EXPECT_NE(dg->lowest_layer<memory_stream>(), nullptr);
                         const socks5::dgram<> *const_dg = dg.get();
                         EXPECT_NE(const_dg->next_layer(), nullptr);
                         EXPECT_TRUE(dg->executor());
                         // 透传读（客户端透传写的数据）
                         std::array<std::byte, 8> raw{};
                         std::error_code ec;
                         const auto r = co_await dg->async_read_some(raw, ec);
                         EXPECT_EQ(r, 4u);
                         dg->close();
                         dg->cancel();
                         auto released = dg->release();
                         EXPECT_TRUE(released);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await socks5::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), socks5::client_config{},
                         make_addr(socks5::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p1 = "dns query";
                     auto serr = co_await dg->async_send_to(
                         make_addr(socks5::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, error::none);
                     const std::string p2 = "second pkt";
                     serr = co_await dg->async_send_to(
                         make_addr(socks5::address_type::ipv4, "8.8.8.8", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, error::none);
                     // 透传写（服务端读端无消费，仅覆盖 passthrough）
                     const std::array<std::byte, 4> raw{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(raw.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                 });
    }

    TEST(Socks5DgramSession, Ipv6Receive)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：IPv6 地址解析
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         socks5::server_config cfg;
                         cfg.enable_udp = true;
                         auto [err, req, dg] =
                             co_await socks5::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                            cfg);
                         if (err != error::none || !dg)
                         {
                             co_return;
                         }
                         socks5::address src;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(rerr, error::none);
                         EXPECT_EQ(src.type, socks5::address_type::ipv6);
                         EXPECT_EQ(src.host, std::string(16, '\x21'));
                         EXPECT_EQ(src.port, 8080u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "v6 pkt");
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await socks5::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), socks5::client_config{},
                         make_addr(socks5::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "v6 pkt";
                     const auto serr = co_await dg->async_send_to(
                         make_addr(socks5::address_type::ipv6, std::string(16, '\x21'), 8080),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, error::none);
                 });
    }

    TEST(Socks5DgramSession, BadRsvRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：RSV/FRAG 非零 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<socks5::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         socks5::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_message);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 3> wire{0x00, 0x00, 0x01}; // FRAG 非零
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Socks5DgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：ATYP 非法 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<socks5::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         socks5::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_message);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 4> wire{0x00, 0x00, 0x00, 0x99}; // ATYP 非法
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Socks5DgramSession, HeaderWithoutPayload)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址头完整但无载荷 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<socks5::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         socks5::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::unexpected_eof);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // [RSV 3B][ATYP=1][IPv4 4B][Port 2B] 无载荷，随后关闭
                     const std::array<std::uint8_t, 10> wire{0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Socks5DgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<socks5::dgram<>>(std::make_shared<memory_stream>(std::move(b)));
                     a.close(); // 对端关闭 → 读 EOF → io_error
                     socks5::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                     dg->cancel();
                     EXPECT_NE(dg->next_layer(), nullptr);
                     auto released = dg->release();
                     EXPECT_TRUE(released);
                 });
    }

    TEST(Socks5DgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<socks5::dgram<>>(std::make_shared<memory_stream>(std::move(a)));
                     b.close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->async_send_to(
                         make_addr(socks5::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                 });
    }

} // namespace
