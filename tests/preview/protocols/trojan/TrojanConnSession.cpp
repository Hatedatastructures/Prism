/**
 * @file TrojanConnSession.cpp
 * @brief Trojan Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（domain / ipv4 目标）+ 双向回显
 * 2. 预读缓冲消费路径（async_read_some 的 Used_ > 0 分支）
 * 3. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 4. 错误分支：bad_auth / bad_magic / bad_message / not_supported / io_error
 * 5. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
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

    /// 构造 trojan 目标地址
    auto make_addr(Trojan::AddressType Type, std::string host, std::uint16_t port)
        -> Trojan::Address
    {
        Trojan::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    TEST(TrojanConnSession, ConnectAcceptEcho)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "trojan echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 预读缓冲读取 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trojan::ServerConfig cfg;
                         cfg.password = "pw123456";
                         cfg.EnableUdp = true;
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Trojan::Command::Connect);
                         EXPECT_EQ(req.Target.Host, "example.com");
                         EXPECT_EQ(req.Target.Port, 443u);
                         EXPECT_EQ(Conn->Request().Target.Host, "example.com");
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
                     const auto cred = Trojan::Credential("pw123456");
                     const auto Header =
                         Trojan::BuildRequest(cred, Trojan::Command::Connect,
                                                      make_addr(Trojan::AddressType::Domain,
                                                                "example.com", 443));
                     std::vector<std::uint8_t> wire = Header;
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, FactoryConnectAcceptIpv4)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Trojan::Command::Connect);
                         EXPECT_EQ(req.Target.Type, Trojan::AddressType::Ipv4);
                         EXPECT_EQ(req.Target.Host, "1.2.3.4");
                         EXPECT_EQ(req.Target.Port, 80u);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Trojan::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"pw"},
                         make_addr(Trojan::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::None);
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(TrojanConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AcceptPacket 完成 udp_associate 握手 → Dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trojan::ServerConfig cfg;
                         cfg.password = "pw";
                         cfg.EnableUdp = true;
                         auto [err, req, dg] =
                             co_await Trojan::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                            cfg);
                         if (err != Error::None || !dg)
                         {
                             EXPECT_TRUE(false) << "AcceptPacket Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Trojan::Command::UdpAssociate);
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::Udp);
                         // 接收两个包（domain + ipv4）
                         for (int i = 0; i < 2; ++i)
                         {
                             Trojan::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await dg->AsyncReceiveFrom(src, payload);
                             EXPECT_EQ(rerr, Error::None);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.Type, Trojan::AddressType::Domain);
                                 EXPECT_EQ(src.Host, "example.com");
                                 EXPECT_EQ(src.Port, 53u);
                             }
                             else
                             {
                                 EXPECT_EQ(src.Type, Trojan::AddressType::Ipv4);
                                 EXPECT_EQ(src.Host, "8.8.8.8");
                                 EXPECT_EQ(src.Port, 443u);
                             }
                             EXPECT_EQ(std::string(payload.begin(), payload.end()),
                                       i == 0 ? "dns query" : "second pkt");
                         }
                         EXPECT_TRUE(dg->Stream());
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await Trojan::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"pw"},
                         make_addr(Trojan::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::None);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p1 = "dns query";
                     auto serr = co_await dg->AsyncSendTo(
                         make_addr(Trojan::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, Error::None);
                     const std::string p2 = "second pkt";
                     serr = co_await dg->AsyncSendTo(
                         make_addr(Trojan::AddressType::Ipv4, "8.8.8.8", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, Error::None);
                     dg->Close();
                 });
    }

    TEST(TrojanConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"Expect-pw"});
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Trojan::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"wrong-pw"},
                         make_addr(Trojan::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::None); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(TrojanConnSession, BadMagicCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：凭据正确但 CRLF 分隔符错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         EXPECT_EQ(err, Error::BadMagic);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = Trojan::Credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.push_back('\r');
                     wire.push_back('X'); // 应为 \n
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, BadCommandRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法命令 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = Trojan::Credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x99, 0x01, 1, 1, 0, 0, 0, 0, '\r', '\n'});
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, TcpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trojan::ServerConfig cfg;
                         cfg.password = "pw";
                         cfg.EnableTcp = false;
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Trojan::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"pw"},
                         make_addr(Trojan::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::None);
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(TrojanConnSession, UdpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trojan::ServerConfig cfg;
                         cfg.password = "pw";
                         cfg.EnableUdp = false;
                         auto [err, req, dg] =
                             co_await Trojan::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                            cfg);
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(dg);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await Trojan::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"pw"},
                         make_addr(Trojan::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::None); // 客户端只发送 udp_associate 头
                     if (dg)
                     {
                         dg->Close();
                     }
                 });
    }

    TEST(TrojanConnSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = Trojan::Credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x01, 0x99}); // cmd=Connect, ATYP 非法
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, BadTailCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址体后的尾部 CRLF 错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         EXPECT_EQ(err, Error::BadMagic);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = Trojan::Credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.insert(wire.end(), {'\r', '\n', 0x01, 0x01, 1, 2, 3, 4});
                     wire.push_back(0x00);
                     wire.push_back(0x50);
                     wire.push_back('\r');
                     wire.push_back('X'); // 尾部 CRLF 错误
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, TruncatedHeaderEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：头部截断 → io_error
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Trojan::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Trojan::ServerConfig{"pw"});
                         EXPECT_EQ(err, Error::IoError);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto cred = Trojan::Credential("pw");
                     std::vector<std::uint8_t> wire(cred.begin(), cred.end());
                     wire.push_back('\r'); // 缺少后续字节
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.Close(); // 对端已全关 → 写失败 → io_error
                     auto [err, cli] = co_await Trojan::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Trojan::ClientConfig{"pw"},
                         make_addr(Trojan::AddressType::Ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(TrojanConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto c = std::make_shared<Trojan::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                             "pw");
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     const Trojan::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     // 透传读写 + AsyncRead / AsyncWrite 组合
                     const std::string p = "passthrough";
                     std::error_code ec;
                     const auto w = co_await c->AsyncWrite(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(p.data()),
                                                    p.size()),
                         ec);
                     EXPECT_EQ(w, p.size());
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

    TEST(TrojanDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Trojan::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(
                         make_addr(Trojan::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::IoError);
                     dg->Close();
                 });
    }

    TEST(TrojanDgramSession, BadCrlfRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：LEN 头后 CRLF 错误 → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Trojan::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Trojan::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::BadMagic);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::vector<std::uint8_t> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     wire.push_back(0x00);
                     wire.push_back(0x04);
                     wire.push_back('X');
                     wire.push_back('\n'); // CRLF 错误
                     wire.insert(wire.end(), {'a', 'b', 'c', 'd'});
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanDgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Trojan::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Trojan::Address src;
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

    TEST(TrojanDgramSession, LenExceedsRemaining)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：帧头声称 len=500，实际载荷不足 → io_error
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Trojan::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Trojan::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::IoError);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::vector<std::uint8_t> wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     wire.push_back(0x01);
                     wire.push_back(0xF4); // len = 500
                     wire.push_back('\r');
                     wire.push_back('\n');
                     wire.insert(wire.end(), {'a', 'b', 'c'}); // 仅 3 字节
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(TrojanDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Trojan::Dgram<>>(std::make_shared<MemoryStream>(std::move(b)));
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
                     Trojan::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::IoError);
                     dg->Close();
                     dg->Cancel();
                     EXPECT_NE(dg->NextLayer(), nullptr);
                     const Trojan::Dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->NextLayer(), nullptr);
                     auto released = dg->Release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
