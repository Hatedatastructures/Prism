/**
 * @file VlessConnSession.cpp
 * @brief VLESS conn/dgram 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept 握手（域名 + 预读缓冲路径）+ 双向回显
 * 2. UDP 数据面：connect_packet / accept_packet + dgram 收发往返
 * 3. 错误分支：bad_magic / bad_message / bad_auth / not_supported / io_error
 * 4. 装饰器链方法：executor / close / cancel / next_layer / release
 * @note 使用 make_memory_pair 建立内存传输对，同一进程内双向互操作。
 */

#include <system_error>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/vless/vless.hpp>
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

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto test_uuid() -> std::array<std::uint8_t, vless::uuid_len>
    {
        std::array<std::uint8_t, vless::uuid_len> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x10 + i);
        }
        return uuid;
    }

    /// 构造 vless 目标地址
    auto make_addr(vless::address_type type, std::string host, std::uint16_t port) -> vless::address
    {
        vless::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    /// 原始客户端：构造请求头字节
    auto build_raw_request(const std::array<std::uint8_t, vless::uuid_len> &uuid, vless::command cmd,
                           const vless::address &target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> wire;
        wire.push_back(vless::protocol_version);
        wire.insert(wire.end(), uuid.begin(), uuid.end());
        wire.push_back(0x00); // addnl len
        wire.push_back(static_cast<std::uint8_t>(cmd));
        wire.push_back(static_cast<std::uint8_t>(target.port >> 8));
        wire.push_back(static_cast<std::uint8_t>(target.port & 0xFF));
        wire.push_back(static_cast<std::uint8_t>(target.type));
        switch (target.type)
        {
        case vless::address_type::ipv4: {
            std::size_t a = 0;
            std::uint32_t oct = 0;
            for (const char ch : target.host)
            {
                if (ch == '.')
                {
                    wire.push_back(static_cast<std::uint8_t>(oct));
                    oct = 0;
                    ++a;
                }
                else
                {
                    oct = oct * 10 + static_cast<std::uint32_t>(ch - '0');
                }
            }
            wire.push_back(static_cast<std::uint8_t>(oct));
            break;
        }
        case vless::address_type::ipv6:
            wire.insert(wire.end(), target.host.begin(), target.host.end());
            break;
        case vless::address_type::domain:
        default:
            wire.push_back(static_cast<std::uint8_t>(target.host.size()));
            wire.insert(wire.end(), target.host.begin(), target.host.end());
            break;
        }
        return wire;
    }

    TEST(VlessConnSession, ConnectAcceptEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const std::string payload = "vless echo payload";
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 预读缓冲读取 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, vless::command::tcp);
                         EXPECT_EQ(req.target.host, "example.com");
                         EXPECT_EQ(req.target.port, 443u);
                         EXPECT_EQ(conn->parsed().target.host, "example.com");
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

                     // 原始客户端：请求头 + 载荷一次写入（触发服务端预读缓冲）
                     auto wire = build_raw_request(uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     // 读取 2 字节响应 [Version][Addons Len]
                     std::array<std::uint8_t, 2> resp{};
                     std::size_t got = 0;
                     while (got < resp.size())
                     {
                         const auto n = co_await a.async_read_some(
                             as_bytes(std::span<std::uint8_t>(resp).subspan(got)), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         got += n;
                     }
                     EXPECT_EQ(got, 2u);
                     EXPECT_EQ(resp[0], vless::protocol_version);
                     // 读取回显
                     std::array<std::byte, 1024> echo{};
                     got = 0;
                     while (got < payload.size())
                     {
                         const auto n = co_await a.async_read_some(
                             std::span<std::byte>(echo.data() + got, echo.size() - got), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         got += n;
                     }
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(echo.data()), got), payload);
                     a.close();
                 });
    }

    TEST(VlessConnSession, FactoryConnectAcceptIpv4)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, vless::command::tcp);
                         EXPECT_EQ(req.target.type, vless::address_type::ipv4);
                         EXPECT_EQ(req.target.host, "1.2.3.4");
                         EXPECT_EQ(req.target.port, 80u);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vless::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await vless::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vless::address_type::ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, error::none);
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(VlessConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept_packet（udp 命令）→ dgram 收包
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, dg] =
                             co_await vless::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                           cfg);
                         if (err != error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "accept_packet failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, vless::command::udp);
                         EXPECT_EQ(dg->transport_type(), psmtest::transmission::type::udp);
                         vless::address src;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(rerr, error::none);
                         EXPECT_EQ(src.type, vless::address_type::domain);
                         EXPECT_EQ(src.host, "example.com");
                         EXPECT_EQ(src.port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "dns query");
                         EXPECT_TRUE(dg->stream());
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vless::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await vless::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vless::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "dns query";
                     const auto serr = co_await dg->async_send_to(
                         make_addr(vless::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, error::none);
                     dg->close();
                 });
    }

    TEST(VlessConnSession, BadVersionRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：版本号非法 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_magic);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     wire[0] = 0x01; // 版本错误
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessConnSession, BadAddonsRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：addnl_len 非 0 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_message);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     wire[17] = 0x02; // addnl len = 2
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessConnSession, BadCommandRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法命令 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_message);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, static_cast<vless::command>(0x09),
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessConnSession, TcpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：enable_tcp=false → not_supported（不发送响应）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<vless::conn<>>(
                             std::make_shared<memory_stream>(std::move(b)), uuid);
                         auto [err, req] = co_await c->read_handshake(false, true, true);
                         EXPECT_EQ(err, error::not_supported);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：发送请求头后关闭（服务端不响应，客户端读 EOF → io_error）
                     auto wire = build_raw_request(uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                     std::array<std::uint8_t, 2> resp{};
                     const auto n = co_await a.async_read_some(as_bytes(std::span<std::uint8_t>(resp)), ec);
                     EXPECT_EQ(n, 0u); // 无响应，EOF
                 });
    }

    TEST(VlessConnSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_message);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     wire[21] = 0x99; // atyp 非法（offset: ver+uuid+addnl+cmd+port = 21）
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessConnSession, BadUuidRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：UUID 不匹配 → bad_auth（不发送响应，静默断开）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vless::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vless::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::array<std::uint8_t, vless::uuid_len> bad_uuid{};
                     bad_uuid.fill(0xAA);
                     auto wire = build_raw_request(bad_uuid, vless::command::tcp,
                                                   make_addr(vless::address_type::domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.close(); // 对端已全关 → 写失败 → io_error
                     vless::client_config cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await vless::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vless::address_type::ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, error::io_error);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(VlessConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto c = std::make_shared<vless::conn<>>(std::make_shared<memory_stream>(std::move(a)),
                                                            uuid);
                     EXPECT_TRUE(c->executor());
                     EXPECT_NE(c->next_layer(), nullptr);
                     EXPECT_NE(c->lowest_layer<memory_stream>(), nullptr);
                     const vless::conn<> *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     const std::string p = "passthrough";
                     std::error_code ec;
                     co_await c->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(p.data()),
                                                    p.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await b.async_read_some(buf, ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), p);
                     co_await b.async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     std::array<std::uint8_t, 4> dst{};
                     const auto ok = co_await c->read_exact(std::span<std::uint8_t>(dst));
                     EXPECT_FALSE(ok);
                     c->close();
                     c->cancel();
                     auto released = c->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->next_layer(), nullptr);
                 });
    }

    TEST(VlessDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<vless::dgram<>>(std::make_shared<memory_stream>(std::move(a)));
                     b.close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->async_send_to(
                         make_addr(vless::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                 });
    }

    TEST(VlessDgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<vless::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         vless::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_message);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 1> atyp{0x99};
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(atyp)), ec);
                     a.close();
                 });
    }

    TEST(VlessDgramSession, HeaderWithoutPayload)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址头完整但无载荷 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<vless::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         vless::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::unexpected_eof);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // [ATYP=1][IPv4 4B][Port 2B] 无载荷，随后关闭
                     const std::array<std::uint8_t, 7> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(VlessDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<vless::dgram<>>(std::make_shared<memory_stream>(std::move(b)));
                     EXPECT_TRUE(dg->executor());
                     // 透传读写（passthrough）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                     a.close(); // 对端关闭 → 读 EOF → io_error
                     const auto n = co_await dg->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     vless::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                     dg->cancel();
                     EXPECT_NE(dg->next_layer(), nullptr);
                     const vless::dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->next_layer(), nullptr);
                     auto released = dg->release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
