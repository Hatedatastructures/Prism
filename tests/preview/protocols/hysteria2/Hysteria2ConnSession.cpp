/**
 * @file Hysteria2ConnSession.cpp
 * @brief Hysteria2 Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手 + TCP 数据双向回显
 * 2. Conn UDP 数据面（AsyncSendDatagram / AsyncReceiveDatagram）
 * 3. 错误分支：bad_auth / bad_magic / not_open / unexpected_eof / bad_message
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release / lowest_layer
 * 5. Dgram 包连接：发送接收、地址解析、错误分支
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
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
    auto make_addr(Hysteria2::AddressType Type, std::string host, std::uint16_t port)
        -> Hysteria2::Address
    {
        Hysteria2::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    TEST(Hysteria2ConnSession, ClientServerEchoRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "hysteria2 echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 读取数据回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                        Hysteria2::ServerConfig{"pw123456"});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Type, Hysteria2::Message::Kind::Tcp);
                         EXPECT_EQ(req.dst.Host, "example.com");
                         EXPECT_EQ(req.dst.Port, 443u);
                         EXPECT_EQ(Conn->Parsed().dst.Host, "example.com");
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：Connect 握手 → 发送数据 → 读取回显
                     auto [herr, cli] =
                         co_await Hysteria2::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                     Hysteria2::ClientConfig{"pw123456"},
                                                     make_addr(Hysteria2::AddressType::Domain,
                                                               "example.com", 443));
                     EXPECT_EQ(herr, Error::None);
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
                     cli->Close();
                 });
    }

    TEST(Hysteria2ConnSession, Ipv6TargetHandshake)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                        Hysteria2::ServerConfig{"pw"});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.dst.Type, Hysteria2::AddressType::Ipv6);
                         EXPECT_EQ(req.dst.Port, 8080u);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::string ipv6(16, '\x11');
                     auto [herr, cli] = co_await Hysteria2::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Hysteria2::ClientConfig{"pw"},
                         make_addr(Hysteria2::AddressType::Ipv6, ipv6, 8080));
                     EXPECT_EQ(herr, Error::None);
                     if (!cli) { co_return; }
                     cli->Close();
                 });
    }

    TEST(Hysteria2ConnSession, UdpDatagramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                        Hysteria2::ServerConfig{"pw"});
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         // 接收两个数据报（验证 Session/packet Id 递增）
                         for (int i = 0; i < 2; ++i)
                         {
                             Hysteria2::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await Conn->AsyncReceiveDatagram(src, payload);
                             EXPECT_EQ(rerr, Error::None);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.Type, Hysteria2::AddressType::Ipv4);
                                 EXPECT_EQ(src.Host, "93.184.216.34");
                                 EXPECT_EQ(src.Port, 443u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "hello udp");
                             }
                             else
                             {
                                 EXPECT_EQ(src.Type, Hysteria2::AddressType::Domain);
                                 EXPECT_EQ(src.Host, "example.com");
                                 EXPECT_EQ(src.Port, 53u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "second");
                             }
                         }
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await Hysteria2::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                     Hysteria2::ClientConfig{"pw"},
                                                     make_addr(Hysteria2::AddressType::Ipv4,
                                                               "93.184.216.34", 443));
                     EXPECT_EQ(herr, Error::None);
                     if (!cli) { co_return; }
                     const std::string p1 = "hello udp";
                     auto serr = co_await cli->AsyncSendDatagram(
                         make_addr(Hysteria2::AddressType::Ipv4, "93.184.216.34", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, Error::None);
                     const std::string p2 = "second";
                     serr = co_await cli->AsyncSendDatagram(
                         make_addr(Hysteria2::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, Error::None);
                     cli->Close();
                 });
    }

    TEST(Hysteria2ConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：期望密码 Expect-pw，客户端使用 wrong-pw
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                        Hysteria2::ServerConfig{"Expect-pw"});
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await Hysteria2::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                     Hysteria2::ClientConfig{"wrong-pw"},
                                                     make_addr(Hysteria2::AddressType::Domain,
                                                               "example.com", 443));
                     EXPECT_EQ(herr, Error::None); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(Hysteria2ConnSession, BadMagicRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：首字节非 0x01 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<Hysteria2::Conn<>>(
                             std::make_shared<MemoryStream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->ReadHandshake();
                         EXPECT_EQ(err, Error::BadMagic);
                         (void)msg;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 2> wire{0x02, 0x00}; // 非 HEADERS 帧类型
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Hysteria2ConnSession, TruncatedTargetFrame)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：认证帧合法，但 TCP 目标帧只有 Kind 无后续 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<Hysteria2::Conn<>>(
                             std::make_shared<MemoryStream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->ReadHandshake();
                         EXPECT_EQ(err, Error::UnexpectedEof);
                         (void)msg;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto Auth = Hysteria2::MakeAuthRequest("pw");
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(AsU8Span(Auth)), ec);
                     const std::array<std::uint8_t, 1> Kind{0x01}; // 只有 Kind，无地址体
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(Kind)), ec);
                     a.Close();
                 });
    }

    TEST(Hysteria2ConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：读写与数据报均应返回 not_open
                     auto c = std::make_shared<Hysteria2::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));

                     const std::string p = "x";
                     const auto e1 = co_await c->AsyncSendDatagram(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.1.1.1", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(e1, Error::NotOpen);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto e2 = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(e2, Error::NotOpen);
                     c->Close();
                     c->Cancel();
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     const Hysteria2::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                     b.Close();
                 });
    }

    TEST(Hysteria2ConnSession, ConnectToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.Close(); // 对端已全关 → 写返回 broken_pipe → io_error
                     auto [err, cli] = co_await Hysteria2::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Hysteria2::ClientConfig{"pw"},
                         make_addr(Hysteria2::AddressType::Ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Hysteria2ConnSession, ReceiveTcpFrameAsDatagram)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：握手中收到 TCP 帧后，再收到 TCP 帧（非 UDP）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<Hysteria2::Conn<>>(
                             std::make_shared<MemoryStream>(std::move(b)), "pw");
                         auto [err, msg] = co_await c->ReadHandshake();
                         if (err != Error::None) { co_return; }
                         EXPECT_EQ(msg.Type, Hysteria2::Message::Kind::Tcp);
                         Hysteria2::Address src;
                         std::vector<std::uint8_t> out;
                         const auto rerr = co_await c->AsyncReceiveDatagram(src, out);
                         EXPECT_EQ(rerr, Error::BadMessage);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：认证帧 + TCP 目标帧（握手）+ TCP 数据帧（错误路径）
                     const auto Auth = Hysteria2::MakeAuthRequest("pw");
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     const auto tcp_frame = Hysteria2::BuildTcp(Target, {});
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(AsU8Span(Auth)), ec);
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(tcp_frame)), ec);
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(tcp_frame)), ec);
                     a.Close();
                 });
    }

    /// 构造 Dgram 接收侧兼容帧（9B 头后 ATYP 独立成段，对齐 Dgram 解析布局）
    auto build_recv_wire(std::uint8_t atyp, const std::vector<std::uint8_t> &addr,
                         std::uint16_t port, const std::string &payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> wire(9, 0); // Kind + Session(4) + PacketId(4)
        wire[0] = 0x02;
        wire.push_back(atyp);
        wire.insert(wire.end(), addr.begin(), addr.end());
        wire.push_back(static_cast<std::uint8_t>(port >> 8));
        wire.push_back(static_cast<std::uint8_t>(port & 0xFF));
        wire.insert(wire.end(), payload.begin(), payload.end());
        return wire;
    }

    TEST(Hysteria2DgramSession, ReceiveSideParsing)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：逐帧解析三种地址类型（IPv4 / 域名 / IPv6）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Hysteria2::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::Udp);
                         EXPECT_TRUE(dg->Stream());
                         EXPECT_NE(dg->NextLayer(), nullptr);
                         EXPECT_NE(dg->lowest_layer<MemoryStream>(), nullptr);
                         EXPECT_TRUE(dg->Executor());

                         Hysteria2::Address src;
                         std::vector<std::uint8_t> payload;
                         // IPv4
                         auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::None);
                         EXPECT_EQ(src.Type, Hysteria2::AddressType::Ipv4);
                         EXPECT_EQ(src.Host, "93.184.216.34");
                         EXPECT_EQ(src.Port, 443u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "one");
                         // 域名
                         err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::None);
                         EXPECT_EQ(src.Type, Hysteria2::AddressType::Domain);
                         EXPECT_EQ(src.Host, "example.com");
                         EXPECT_EQ(src.Port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "two");
                         // IPv6
                         err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::None);
                         EXPECT_EQ(src.Type, Hysteria2::AddressType::Ipv6);
                         EXPECT_EQ(src.Host, std::string(16, '\x22'));
                         EXPECT_EQ(src.Port, 8080u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "three");
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：发送三种兼容帧
                     std::error_code ec;
                     auto w1 = build_recv_wire(0x01, {93, 184, 216, 34}, 443, "one");
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(w1)), ec);
                     auto w2 = build_recv_wire(0x02, {11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
                                               53, "two");
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(w2)), ec);
                     auto w3 = build_recv_wire(0x03, std::vector<std::uint8_t>(16, 0x22), 8080, "three");
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(w3)), ec);
                     a.Close();
                 });
    }

    TEST(Hysteria2DgramSession, SendSideRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto a_stream = std::make_shared<MemoryStream>(std::move(a));
        auto b_stream = std::make_shared<MemoryStream>(std::move(b));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Hysteria2::Dgram<>>(b_stream);
                         // 透传读取客户端 BuildUdp 帧并解析验证
                         std::array<std::uint8_t, 512> wire{};
                         std::error_code ec;
                         const auto n = co_await dg->async_read_some(
                             AsBytes(std::span<std::uint8_t>(wire)), ec);                         EXPECT_GT(n, 0u);
                         Hysteria2::Message msg;
                         std::size_t consumed = 0;
                         const auto perr = Hysteria2::Parse(
                             std::span<const std::uint8_t>(wire).first(n), msg, consumed);
                         EXPECT_EQ(perr, Error::None);
                         EXPECT_EQ(msg.Type, Hysteria2::Message::Kind::Udp);
                         EXPECT_EQ(msg.SessionId, 0u);
                         EXPECT_EQ(msg.PacketId, 1u);
                         EXPECT_EQ(msg.dst.Type, Hysteria2::AddressType::Ipv4);
                         EXPECT_EQ(msg.dst.Host, "93.184.216.34");
                         EXPECT_EQ(msg.dst.Port, 443u);
                         EXPECT_EQ(msg.payload, "Dgram hello");
                         // 透传写入（passthrough）
                         std::error_code w_ec;
                         const auto w = co_await dg->async_write_some(
                             AsBytes(std::span<const std::uint8_t>(wire).first(n)), w_ec);
                         EXPECT_EQ(w, n);
                         dg->Close();
                         dg->Cancel();
                         EXPECT_NE(dg->NextLayer(), nullptr);
                         const Hysteria2::Dgram<> *const_dg = dg.get();
                         EXPECT_NE(const_dg->NextLayer(), nullptr);
                         auto released = dg->Release();
                         EXPECT_TRUE(released);
                         EXPECT_EQ(dg->NextLayer(), nullptr);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto dg = std::make_shared<Hysteria2::Dgram<>>(a_stream);
                     EXPECT_TRUE(dg->Executor());
                     const std::string p = "Dgram hello";
                     const auto err = co_await dg->AsyncSendTo(
                         make_addr(Hysteria2::AddressType::Ipv4, "93.184.216.34", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::None);
                 });
    }

    TEST(Hysteria2DgramSession, BadKindRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：head[0] 非 UDP Kind（0x02）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Hysteria2::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Hysteria2::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::BadMessage);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 9> wire{0x01, 0, 0, 0, 0, 0, 0, 0, 0}; // TCP Kind
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Hysteria2DgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：ATYP 非法（0x99）→ bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Hysteria2::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Hysteria2::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::BadMessage);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // UDP Kind + Session/packet Id(8) + 非法 ATYP
                     std::vector<std::uint8_t> wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Hysteria2DgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(
                         std::make_shared<MemoryStream>(std::move(b)));
                     a.Close(); // 对端关闭 → 读返回 0 → unexpected_eof
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                     dg->Close();
                 });
    }

} // namespace
