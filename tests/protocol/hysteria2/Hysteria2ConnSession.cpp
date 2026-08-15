/**
 * @file Hysteria2ConnSession.cpp
 * @brief Hysteria2 conn/dgram 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept 握手 + TCP 数据双向回显
 * 2. conn UDP 数据面（async_send_datagram / async_receive_datagram）
 * 3. 错误分支：bad_auth / bad_magic / not_open / unexpected_eof / bad_message
 * 4. 装饰器链方法：executor / close / cancel / next_layer / release / lowest_layer
 * 5. dgram 包连接：发送接收、地址解析、错误分支
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
#include <common/proxy/hysteria2/hysteria2.hpp>
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

    /// 构造 hysteria2 目标地址
    auto make_addr(hysteria2::address_type type, std::string host, std::uint16_t port)
        -> hysteria2::address
    {
        hysteria2::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    TEST(Hysteria2ConnSession, ClientServerEchoRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const std::string payload = "hysteria2 echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 读取数据回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"pw123456"});
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(req.type, hysteria2::message::kind::tcp);
                         EXPECT_EQ(req.dst.host, "example.com");
                         EXPECT_EQ(req.dst.port, 443u);
                         EXPECT_EQ(conn->parsed().dst.host, "example.com");
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：connect 握手 → 发送数据 → 读取回显
                     auto [herr, cli] =
                         co_await hysteria2::connect(std::make_shared<memory_stream>(std::move(a)),
                                                     hysteria2::client_config{"pw123456"},
                                                     make_addr(hysteria2::address_type::domain,
                                                               "example.com", 443));
                     EXPECT_EQ(herr, error::none);
                     if (!cli) { co_return; }
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 1024> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->close();
                 });
    }

    TEST(Hysteria2ConnSession, Ipv6TargetHandshake)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"pw"});
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(req.dst.type, hysteria2::address_type::ipv6);
                         EXPECT_EQ(req.dst.port, 8080u);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::string ipv6(16, '\x11');
                     auto [herr, cli] = co_await hysteria2::connect(
                         std::make_shared<memory_stream>(std::move(a)), hysteria2::client_config{"pw"},
                         make_addr(hysteria2::address_type::ipv6, ipv6, 8080));
                     EXPECT_EQ(herr, error::none);
                     if (!cli) { co_return; }
                     cli->close();
                 });
    }

    TEST(Hysteria2ConnSession, UdpDatagramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"pw"});
                         if (err != error::none || !conn)
                         {
                             co_return;
                         }
                         // 接收两个数据报（验证 session/packet id 递增）
                         for (int i = 0; i < 2; ++i)
                         {
                             hysteria2::address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await conn->async_receive_datagram(src, payload);
                             EXPECT_EQ(rerr, error::none);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.type, hysteria2::address_type::ipv4);
                                 EXPECT_EQ(src.host, "93.184.216.34");
                                 EXPECT_EQ(src.port, 443u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "hello udp");
                             }
                             else
                             {
                                 EXPECT_EQ(src.type, hysteria2::address_type::domain);
                                 EXPECT_EQ(src.host, "example.com");
                                 EXPECT_EQ(src.port, 53u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "second");
                             }
                         }
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await hysteria2::connect(std::make_shared<memory_stream>(std::move(a)),
                                                     hysteria2::client_config{"pw"},
                                                     make_addr(hysteria2::address_type::ipv4,
                                                               "93.184.216.34", 443));
                     EXPECT_EQ(herr, error::none);
                     if (!cli) { co_return; }
                     const std::string p1 = "hello udp";
                     auto serr = co_await cli->async_send_datagram(
                         make_addr(hysteria2::address_type::ipv4, "93.184.216.34", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, error::none);
                     const std::string p2 = "second";
                     serr = co_await cli->async_send_datagram(
                         make_addr(hysteria2::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, error::none);
                     cli->close();
                 });
    }

    TEST(Hysteria2ConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：期望密码 expect-pw，客户端使用 wrong-pw
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"expect-pw"});
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await hysteria2::connect(std::make_shared<memory_stream>(std::move(a)),
                                                     hysteria2::client_config{"wrong-pw"},
                                                     make_addr(hysteria2::address_type::domain,
                                                               "example.com", 443));
                     EXPECT_EQ(herr, error::none); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(Hysteria2ConnSession, BadMagicRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：首字节非 0x01 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<hysteria2::conn<>>(
                             std::make_shared<memory_stream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->read_handshake();
                         EXPECT_EQ(err, error::bad_magic);
                         (void)msg;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 2> wire{0x02, 0x00}; // 非 HEADERS 帧类型
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Hysteria2ConnSession, TruncatedTargetFrame)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：认证帧合法，但 TCP 目标帧只有 Kind 无后续 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<hysteria2::conn<>>(
                             std::make_shared<memory_stream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->read_handshake();
                         EXPECT_EQ(err, error::unexpected_eof);
                         (void)msg;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto auth = hysteria2::make_auth_request("pw");
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(as_u8_span(auth)), ec);
                     const std::array<std::uint8_t, 1> kind{0x01}; // 只有 Kind，无地址体
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(kind)), ec);
                     a.close();
                 });
    }

    TEST(Hysteria2ConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：读写与数据报均应返回 not_open
                     auto c = std::make_shared<hysteria2::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));

                     const std::string p = "x";
                     const auto e1 = co_await c->async_send_datagram(
                         make_addr(hysteria2::address_type::ipv4, "1.1.1.1", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(e1, error::not_open);
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto e2 = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(e2, error::not_open);
                     c->close();
                     c->cancel();
                     EXPECT_TRUE(c->executor());
                     EXPECT_NE(c->next_layer(), nullptr);
                     const hysteria2::conn<> *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     EXPECT_NE(c->lowest_layer<memory_stream>(), nullptr);
                     auto released = c->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->next_layer(), nullptr);
                     b.close();
                 });
    }

    TEST(Hysteria2ConnSession, ConnectToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.close(); // 对端已全关 → 写返回 broken_pipe → io_error
                     auto [err, cli] = co_await hysteria2::connect(
                         std::make_shared<memory_stream>(std::move(a)), hysteria2::client_config{"pw"},
                         make_addr(hysteria2::address_type::ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, error::io_error);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Hysteria2ConnSession, ReceiveTcpFrameAsDatagram)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：握手中收到 TCP 帧后，再收到 TCP 帧（非 UDP）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<hysteria2::conn<>>(
                             std::make_shared<memory_stream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->read_handshake();
                         if (err != error::none) { co_return; }
                         EXPECT_EQ(msg.type, hysteria2::message::kind::tcp);
                         hysteria2::address src;
                         std::vector<std::uint8_t> out;
                         const auto rerr = co_await c->async_receive_datagram(src, out);
                         EXPECT_EQ(rerr, error::bad_message);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：认证帧 + TCP 目标帧（握手）+ TCP 数据帧（错误路径）
                     const auto auth = hysteria2::make_auth_request("pw");
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     const auto tcp_frame = hysteria2::build_tcp(target, {});
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(as_u8_span(auth)), ec);
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(tcp_frame)), ec);
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(tcp_frame)), ec);
                     a.close();
                 });
    }

    /// 构造 dgram 接收侧兼容帧（ATYP 内嵌于 packet_id 末字节，对齐 dgram 解析布局）
    auto build_recv_wire(std::uint8_t atyp, const std::vector<std::uint8_t> &addr,
                         std::uint16_t port, const std::string &payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> wire{0x02, 0, 0, 0, 0, 0, 0, 0, atyp}; // kind + session(4) + packet(3) + ATYP
        wire.insert(wire.end(), addr.begin(), addr.end());
        wire.push_back(static_cast<std::uint8_t>(port >> 8));
        wire.push_back(static_cast<std::uint8_t>(port & 0xFF));
        wire.insert(wire.end(), payload.begin(), payload.end());
        return wire;
    }

    TEST(Hysteria2DgramSession, ReceiveSideParsing)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：逐帧解析三种地址类型（IPv4 / 域名 / IPv6）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<hysteria2::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         EXPECT_EQ(dg->transport_type(), psmtest::transmission::type::udp);
                         EXPECT_TRUE(dg->stream());
                         EXPECT_NE(dg->next_layer(), nullptr);
                         EXPECT_NE(dg->lowest_layer<memory_stream>(), nullptr);
                         EXPECT_TRUE(dg->executor());

                         hysteria2::address src;
                         std::vector<std::uint8_t> payload;
                         // IPv4
                         auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::none);
                         EXPECT_EQ(src.type, hysteria2::address_type::ipv4);
                         EXPECT_EQ(src.host, "93.184.216.34");
                         EXPECT_EQ(src.port, 443u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "one");
                         // 域名
                         err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::none);
                         EXPECT_EQ(src.type, hysteria2::address_type::domain);
                         EXPECT_EQ(src.host, "example.com");
                         EXPECT_EQ(src.port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "two");
                         // IPv6
                         err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::none);
                         EXPECT_EQ(src.type, hysteria2::address_type::ipv6);
                         EXPECT_EQ(src.host, std::string(16, '\x22'));
                         EXPECT_EQ(src.port, 8080u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "three");
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：发送三种兼容帧
                     std::error_code ec;
                     auto w1 = build_recv_wire(0x01, {93, 184, 216, 34}, 443, "one");
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(w1)), ec);
                     auto w2 = build_recv_wire(0x02, {11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
                                               53, "two");
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(w2)), ec);
                     auto w3 = build_recv_wire(0x03, std::vector<std::uint8_t>(16, 0x22), 8080, "three");
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(w3)), ec);
                     a.close();
                 });
    }

    TEST(Hysteria2DgramSession, SendSideRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto a_stream = std::make_shared<memory_stream>(std::move(a));
        auto b_stream = std::make_shared<memory_stream>(std::move(b));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<hysteria2::dgram<>>(b_stream);
                         // 透传读取客户端 build_udp 帧并解析验证
                         std::array<std::uint8_t, 512> wire{};
                         std::error_code ec;
                         const auto n = co_await dg->async_read_some(
                             as_bytes(std::span<std::uint8_t>(wire)), ec);                         EXPECT_GT(n, 0u);
                         hysteria2::message msg;
                         std::size_t consumed = 0;
                         const auto perr = hysteria2::parse(
                             std::span<const std::uint8_t>(wire).first(n), msg, consumed);
                         EXPECT_EQ(perr, error::none);
                         EXPECT_EQ(msg.type, hysteria2::message::kind::udp);
                         EXPECT_EQ(msg.session_id, 0u);
                         EXPECT_EQ(msg.packet_id, 1u);
                         EXPECT_EQ(msg.dst.type, hysteria2::address_type::ipv4);
                         EXPECT_EQ(msg.dst.host, "93.184.216.34");
                         EXPECT_EQ(msg.dst.port, 443u);
                         EXPECT_EQ(msg.payload, "dgram hello");
                         // 透传写入（passthrough）
                         std::error_code w_ec;
                         const auto w = co_await dg->async_write_some(
                             as_bytes(std::span<const std::uint8_t>(wire).first(n)), w_ec);
                         EXPECT_EQ(w, n);
                         dg->close();
                         dg->cancel();
                         EXPECT_NE(dg->next_layer(), nullptr);
                         const hysteria2::dgram<> *const_dg = dg.get();
                         EXPECT_NE(const_dg->next_layer(), nullptr);
                         auto released = dg->release();
                         EXPECT_TRUE(released);
                         EXPECT_EQ(dg->next_layer(), nullptr);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto dg = std::make_shared<hysteria2::dgram<>>(a_stream);
                     EXPECT_TRUE(dg->executor());
                     const std::string p = "dgram hello";
                     const auto err = co_await dg->async_send_to(
                         make_addr(hysteria2::address_type::ipv4, "93.184.216.34", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::none);
                 });
    }

    TEST(Hysteria2DgramSession, BadKindRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：head[0] 非 UDP kind（0x02）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<hysteria2::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         hysteria2::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_message);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 9> wire{0x01, 0, 0, 0, 0, 0, 0, 0, 0}; // TCP kind
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Hysteria2DgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：ATYP 非法（0x99）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<hysteria2::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         hysteria2::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_message);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // UDP kind + session/packet id(8) + 非法 ATYP
                     std::vector<std::uint8_t> wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(Hysteria2DgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<hysteria2::dgram<>>(
                         std::make_shared<memory_stream>(std::move(b)));
                     a.close(); // 对端关闭 → 读返回 0 → unexpected_eof
                     hysteria2::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::unexpected_eof);
                     dg->close();
                 });
    }

} // namespace
