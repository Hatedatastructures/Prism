/**
 * @file VlessConnSession.cpp
 * @brief VLESS Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（域名 + 预读缓冲路径）+ 双向回显
 * 2. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 3. 错误分支：bad_magic / bad_message / bad_auth / not_supported / io_error
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
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

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Vless/Vless.hpp>
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

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto test_uuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x10 + i);
        }
        return uuid;
    }

    /// 构造 vless 目标地址
    auto make_addr(Vless::AddressType Type, std::string host, std::uint16_t port) -> Vless::Address
    {
        Vless::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    /// 原始客户端：构造请求头字节
    auto build_raw_request(const std::array<std::uint8_t, Vless::UuidLen> &uuid, Vless::Command cmd,
                           const Vless::Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> wire;
        wire.push_back(Vless::ProtocolVersion);
        wire.insert(wire.end(), uuid.begin(), uuid.end());
        wire.push_back(0x00); // addnl len
        wire.push_back(static_cast<std::uint8_t>(cmd));
        wire.push_back(static_cast<std::uint8_t>(Target.Port >> 8));
        wire.push_back(static_cast<std::uint8_t>(Target.Port & 0xFF));
        wire.push_back(static_cast<std::uint8_t>(Target.Type));
        switch (Target.Type)
        {
        case Vless::AddressType::Ipv4: {
            std::size_t a = 0;
            std::uint32_t oct = 0;
            for (const char ch : Target.Host)
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
        case Vless::AddressType::Ipv6:
            wire.insert(wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        case Vless::AddressType::Domain:
        default:
            wire.push_back(static_cast<std::uint8_t>(Target.Host.size()));
            wire.insert(wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        }
        return wire;
    }

    TEST(VlessConnSession, ConnectAcceptEcho)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "vless echo payload";
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 预读缓冲读取 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Vless::Command::Tcp);
                         EXPECT_EQ(req.Target.Host, "example.com");
                         EXPECT_EQ(req.Target.Port, 443u);
                         EXPECT_EQ(Conn->Parsed().Target.Host, "example.com");
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

                     // 原始客户端：请求头 + 载荷一次写入（触发服务端预读缓冲）
                     auto wire = build_raw_request(uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     // 读取 2 字节响应 [Version][Addons Len]
                     std::array<std::uint8_t, 2> resp{};
                     std::size_t got = 0;
                     while (got < resp.size())
                     {
                         const auto n = co_await a.async_read_some(
                             AsBytes(std::span<std::uint8_t>(resp).subspan(got)), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         got += n;
                     }
                     EXPECT_EQ(got, 2u);
                     EXPECT_EQ(resp[0], Vless::ProtocolVersion);
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
                     a.Close();
                 });
    }

    TEST(VlessConnSession, FactoryConnectAcceptIpv4)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Vless::Command::Tcp);
                         EXPECT_EQ(req.Target.Type, Vless::AddressType::Ipv4);
                         EXPECT_EQ(req.Target.Host, "1.2.3.4");
                         EXPECT_EQ(req.Target.Port, 80u);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vless::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await Vless::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vless::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::None);
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(VlessConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AcceptPacket（udp 命令）→ Dgram 收包
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, dg] =
                             co_await Vless::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                           cfg);
                         if (err != Error::None || !dg)
                         {
                             EXPECT_TRUE(false) << "AcceptPacket Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Vless::Command::Udp);
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::Udp);
                         Vless::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(rerr, Error::None);
                         EXPECT_EQ(src.Type, Vless::AddressType::Domain);
                         EXPECT_EQ(src.Host, "example.com");
                         EXPECT_EQ(src.Port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "dns query");
                         EXPECT_TRUE(dg->Stream());
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vless::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await Vless::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vless::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::None);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "dns query";
                     const auto serr = co_await dg->AsyncSendTo(
                         make_addr(Vless::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, Error::None);
                     dg->Close();
                 });
    }

    TEST(VlessConnSession, BadVersionRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：版本号非法 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadMagic);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     wire[0] = 0x01; // 版本错误
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessConnSession, BadAddonsRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AddnlLen 非 0 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     wire[17] = 0x02; // addnl len = 2
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessConnSession, BadCommandRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法命令 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, static_cast<Vless::Command>(0x09),
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessConnSession, TcpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：EnableTcp=false → not_supported（不发送响应）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto c = std::make_shared<Vless::Conn<>>(
                             std::make_shared<MemoryStream>(std::move(b)), uuid);
                         auto [err, req] = co_await c->ReadHandshake(false, true, true);
                         EXPECT_EQ(err, Error::NotSupported);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：发送请求头后关闭（服务端不响应，客户端读 EOF → io_error）
                     auto wire = build_raw_request(uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                     std::array<std::uint8_t, 2> resp{};
                     const auto n = co_await a.async_read_some(AsBytes(std::span<std::uint8_t>(resp)), ec);
                     EXPECT_EQ(n, 0u); // 无响应，EOF
                 });
    }

    TEST(VlessConnSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto wire = build_raw_request(uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     wire[21] = 0x99; // atyp 非法（offset: ver+uuid+addnl+cmd+port = 21）
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessConnSession, BadUuidRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：UUID 不匹配 → bad_auth（不发送响应，静默断开）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vless::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vless::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::array<std::uint8_t, Vless::UuidLen> bad_uuid{};
                     bad_uuid.fill(0xAA);
                     auto wire = build_raw_request(bad_uuid, Vless::Command::Tcp,
                                                   make_addr(Vless::AddressType::Domain, "example.com",
                                                             443));
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.Close(); // 对端已全关 → 写失败 → io_error
                     Vless::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await Vless::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vless::AddressType::Ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(VlessConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto c = std::make_shared<Vless::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                            uuid);
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     const Vless::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
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
                     const auto Ok = co_await c->ReadExact(std::span<std::uint8_t>(dst));
                     EXPECT_FALSE(Ok);
                     c->Close();
                     c->Cancel();
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                 });
    }

    TEST(VlessDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Vless::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(
                         make_addr(Vless::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::IoError);
                     dg->Close();
                 });
    }

    TEST(VlessDgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Vless::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Vless::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::BadMessage);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 1> atyp{0x99};
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(atyp)), ec);
                     a.Close();
                 });
    }

    TEST(VlessDgramSession, HeaderWithoutPayload)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址头完整但无载荷 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Vless::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Vless::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::UnexpectedEof);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // [ATYP=1][IPv4 4B][Port 2B] 无载荷，随后关闭
                     const std::array<std::uint8_t, 7> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(VlessDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Vless::Dgram<>>(std::make_shared<MemoryStream>(std::move(b)));
                     EXPECT_TRUE(dg->Executor());
                     // 透传读写（passthrough）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                     a.Close(); // 对端关闭 → 读 EOF → io_error
                     const auto n = co_await dg->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     Vless::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::IoError);
                     dg->Close();
                     dg->Cancel();
                     EXPECT_NE(dg->NextLayer(), nullptr);
                     const Vless::Dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->NextLayer(), nullptr);
                     auto released = dg->Release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
