/**
 * @file TrojanConnSession.cpp
 * @brief Trojan conn/dgram 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept 握手（domain / ipv4 目标）+ 双向回显
 * 2. 预读缓冲消费路径（async_read_some 的 used_ > 0 分支）
 * 3. UDP 数据面：connect_packet / accept_packet + dgram 收发往返
 * 4. 错误分支：bad_auth / bad_magic / bad_message / not_supported / io_error
 * 5. 装饰器链方法：executor / close / cancel / next_layer / release
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
#include <common/proxy/trojan/trojan.hpp>
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

    /// 构造 trojan 目标地址
    auto make_addr(trojan::address_type type, std::string host, std::uint16_t port)
        -> trojan::address
    {
        trojan::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    TEST(TrojanConnSession, ConnectAcceptEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const std::string payload = "trojan echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 预读缓冲读取 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trojan::server_config cfg;
                         cfg.password = "pw123456";
                         cfg.enable_udp = true;
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, trojan::command::connect);
                         EXPECT_EQ(req.target.host, "example.com");
                         EXPECT_EQ(req.target.port, 443u);
                         EXPECT_EQ(conn->request().target.host, "example.com");
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
                     const auto cred = trojan::credential("pw123456");
                     const auto header =
                         trojan::build_request(cred, trojan::command::connect,
                                                      make_addr(trojan::address_type::domain,
                                                                "example.com", 443));
                     std::vector<std::uint8_t> wire = header;
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     // 读取回显
                     std::array<std::byte, 1024> echo{};
                     std::size_t got = 0;
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

    TEST(TrojanConnSession, FactoryConnectAcceptIpv4)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         if (err != error::none || !conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, trojan::command::connect);
                         EXPECT_EQ(req.target.type, trojan::address_type::ipv4);
                         EXPECT_EQ(req.target.host, "1.2.3.4");
                         EXPECT_EQ(req.target.port, 80u);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await trojan::connect(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw"},
                         make_addr(trojan::address_type::ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, error::none);
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(TrojanConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept_packet 完成 udp_associate 握手 → dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trojan::server_config cfg;
                         cfg.password = "pw";
                         cfg.enable_udp = true;
                         auto [err, req, dg] =
                             co_await trojan::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                            cfg);
                         if (err != error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "accept_packet failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, trojan::command::udp_associate);
                         EXPECT_EQ(dg->transport_type(), psmtest::transmission::type::udp);
                         // 接收两个包（domain + ipv4）
                         for (int i = 0; i < 2; ++i)
                         {
                             trojan::address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await dg->async_receive_from(src, payload);
                             EXPECT_EQ(rerr, error::none);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.type, trojan::address_type::domain);
                                 EXPECT_EQ(src.host, "example.com");
                                 EXPECT_EQ(src.port, 53u);
                             }
                             else
                             {
                                 EXPECT_EQ(src.type, trojan::address_type::ipv4);
                                 EXPECT_EQ(src.host, "8.8.8.8");
                                 EXPECT_EQ(src.port, 443u);
                             }
                             EXPECT_EQ(std::string(payload.begin(), payload.end()),
                                       i == 0 ? "dns query" : "second pkt");
                         }
                         EXPECT_TRUE(dg->stream());
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await trojan::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw"},
                         make_addr(trojan::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p1 = "dns query";
                     auto serr = co_await dg->async_send_to(
                         make_addr(trojan::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, error::none);
                     const std::string p2 = "second pkt";
                     serr = co_await dg->async_send_to(
                         make_addr(trojan::address_type::ipv4, "8.8.8.8", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, error::none);
                     dg->close();
                 });
    }

    TEST(TrojanConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"expect-pw"});
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await trojan::connect(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"wrong-pw"},
                         make_addr(trojan::address_type::domain, "example.com", 443));
                     EXPECT_EQ(herr, error::none); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(TrojanConnSession, BadMagicCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：凭据正确但 CRLF 分隔符错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         EXPECT_EQ(err, error::bad_magic);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = trojan::credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.push_back('\r');
                     wire.push_back('X'); // 应为 \n
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanConnSession, BadCommandRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法命令 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         EXPECT_EQ(err, error::bad_message);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = trojan::credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x99, 0x01, 1, 1, 0, 0, 0, 0, '\r', '\n'});
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanConnSession, TcpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trojan::server_config cfg;
                         cfg.password = "pw";
                         cfg.enable_tcp = false;
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::not_supported);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await trojan::connect(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw"},
                         make_addr(trojan::address_type::domain, "example.com", 443));
                     EXPECT_EQ(herr, error::none);
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(TrojanConnSession, UdpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         trojan::server_config cfg;
                         cfg.password = "pw";
                         cfg.enable_udp = false;
                         auto [err, req, dg] =
                             co_await trojan::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                            cfg);
                         EXPECT_EQ(err, error::not_supported);
                         EXPECT_FALSE(dg);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await trojan::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw"},
                         make_addr(trojan::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none); // 客户端只发送 udp_associate 头
                     if (dg)
                     {
                         dg->close();
                     }
                 });
    }

    TEST(TrojanConnSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         EXPECT_EQ(err, error::bad_message);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = trojan::credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x01, 0x99}); // cmd=connect, ATYP 非法
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanConnSession, BadTailCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址体后的尾部 CRLF 错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         EXPECT_EQ(err, error::bad_magic);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = trojan::credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x01, 0x01, 1, 2, 3, 4});
                     wire.push_back(0x00);
                     wire.push_back(0x50);
                     wire.push_back('\r');
                     wire.push_back('X'); // 尾部 CRLF 错误
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanConnSession, TruncatedHeaderEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：头部截断 → io_error
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                     trojan::server_config{"pw"});
                         EXPECT_EQ(err, error::io_error);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = trojan::credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.push_back('\r'); // 缺少后续字节
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.close(); // 对端已全关 → 写失败 → io_error
                     auto [err, cli] = co_await trojan::connect(
                         std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw"},
                         make_addr(trojan::address_type::ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, error::io_error);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(TrojanConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto c = std::make_shared<trojan::conn<>>(std::make_shared<memory_stream>(std::move(a)),
                                                             "pw");
                     EXPECT_TRUE(c->executor());
                     EXPECT_NE(c->next_layer(), nullptr);
                     EXPECT_NE(c->lowest_layer<memory_stream>(), nullptr);
                     const trojan::conn<> *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     // 透传读写 + async_read / async_write 组合
                     const std::string p = "passthrough";
                     std::error_code ec;
                     const auto w = co_await c->async_write(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(p.data()),
                                                    p.size()),
                         ec);
                     EXPECT_EQ(w, p.size());
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

    TEST(TrojanDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<trojan::dgram<>>(std::make_shared<memory_stream>(std::move(a)));
                     b.close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->async_send_to(
                         make_addr(trojan::address_type::domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                 });
    }

    TEST(TrojanDgramSession, BadCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：LEN 头后 CRLF 错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<trojan::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         trojan::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::bad_magic);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::vector<std::uint8_t> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     wire.push_back(0x00);
                     wire.push_back(0x04);
                     wire.push_back('X');
                     wire.push_back('\n'); // CRLF 错误
                     wire.insert(wire.end(), {'a', 'b', 'c', 'd'});
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanDgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<trojan::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         trojan::address src;
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

    TEST(TrojanDgramSession, LenExceedsRemaining)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：帧头声称 len=500，实际载荷不足 → io_error
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<trojan::dgram<>>(
                             std::make_shared<memory_stream>(std::move(b)));
                         trojan::address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->async_receive_from(src, payload);
                         EXPECT_EQ(err, error::io_error);
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::vector<std::uint8_t> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     wire.push_back(0x01);
                     wire.push_back(0xF4); // len = 500
                     wire.push_back('\r');
                     wire.push_back('\n');
                     wire.insert(wire.end(), {'a', 'b', 'c'}); // 仅 3 字节
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     a.close();
                 });
    }

    TEST(TrojanDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<trojan::dgram<>>(std::make_shared<memory_stream>(std::move(b)));
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
                     trojan::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::io_error);
                     dg->close();
                     dg->cancel();
                     EXPECT_NE(dg->next_layer(), nullptr);
                     const trojan::dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->next_layer(), nullptr);
                     auto released = dg->release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
