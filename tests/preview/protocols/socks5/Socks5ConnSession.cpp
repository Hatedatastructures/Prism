/**
 * @file Socks5ConnSession.cpp
 * @brief SOCKS5 Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（无认证 + RFC 1929 用户认证）
 * 2. 预读缓冲消费路径（async_read_some 的 Used_ > 0 分支）
 * 3. 错误分支：version_mismatch / not_supported / bad_auth / bad_message
 * 4. 命令开关：EnableTcp / EnableUdp 关闭时的拒绝路径
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
#include <preview/Protocols/Socks5/Socks5.hpp>
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

    /// 构造 socks5 目标地址
    auto make_addr(Socks5::AddressType Type, std::string host, std::uint16_t port)
        -> Socks5::Address
    {
        Socks5::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    TEST(Socks5ConnSession, NoAuthHandshakeEcho)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "socks5 echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 预读缓冲读取（握手尾与载荷同批到达）→ 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Socks5::ServerConfig{});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Socks5::Command::Connect);
                         EXPECT_EQ(req.Target.Host, "example.com");
                         EXPECT_EQ(req.Target.Port, 443u);
                         EXPECT_EQ(Conn->Parsed().Target.Host, "example.com");
                         // 预读缓冲路径：握手超读的载荷直接由缓冲返回
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

                     // 原始客户端：Greeting + 请求 + 载荷一次写入（触发服务端预读）
                     std::vector<std::uint8_t> wire{0x05, 0x01, 0x00}; // Greeting
                     const std::string host = "example.com";
                     wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(host.size())});
                     wire.insert(wire.end(), host.begin(), host.end());
                     wire.push_back(0x01);
                     wire.push_back(0xBB); // port 443
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     // 读取方法选择 + 成功响应（4 + ipv4 Bind 4 + port 2）
                     std::array<std::uint8_t, 12> resp{};
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
                     EXPECT_EQ(got, 12u);
                     EXPECT_EQ(resp[0], Socks5::Version);
                     EXPECT_EQ(resp[1], 0x00); // no_auth 选中
                     EXPECT_EQ(resp[3], 0x00); // success
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

    TEST(Socks5ConnSession, FactoryConnectAcceptEcho)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Socks5::ServerConfig{});
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(req.Target.Host, "1.2.3.4");
                         std::array<std::byte, 256> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         if (ec || n == 0)
                         {
                             co_return;
                         }
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     // BindEndpoint 已由成功响应填充（0.0.0.0:0）
                     EXPECT_EQ(cli->BindEndpoint().Host, "0.0.0.0");
                     const std::string p = "factory echo";
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(p.data()),
                                                    p.size()),
                         ec);
                     std::array<std::byte, 256> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), p);
                     cli->Close();
                 });
    }

    TEST(Socks5ConnSession, UserPassAuthHandshake)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableAuth = true;
                         cfg.username = "alice";
                         cfg.password = "Secret";
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Socks5::Command::Connect);
                         EXPECT_EQ(req.Target.Type, Socks5::AddressType::Ipv4);
                         EXPECT_EQ(req.Target.Host, "1.2.3.4");
                         EXPECT_EQ(req.Target.Port, 80u);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Socks5::ClientConfig cfg;
                     cfg.EnableAuth = true;
                     cfg.username = "alice";
                     cfg.password = "Secret";
                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Socks5::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::None);
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(Socks5ConnSession, UserPassWrongPassword)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableAuth = true;
                         cfg.username = "alice";
                         cfg.password = "Secret";
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Socks5::ClientConfig cfg;
                     cfg.EnableAuth = true;
                     cfg.username = "alice";
                     cfg.password = "wrong";
                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::BadAuth);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, UserPassMalformedVersion)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：userpass 子协商版本号非法 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableAuth = true;
                         cfg.username = "alice";
                         cfg.password = "Secret";
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：Greeting 含 user_pass 方法
                     std::error_code ec;
                     const std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x02};
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ec);
                     // 读取方法选择
                     std::array<std::uint8_t, 2> sel{};
                     const auto n = co_await a.async_read_some(AsBytes(std::span<std::uint8_t>(sel)), ec);
                     EXPECT_EQ(n, 2u);
                     EXPECT_EQ(sel[1], 0x02);
                     // 发送非法版本的 userpass 子协商
                     const std::array<std::uint8_t, 3> bad{0x02, 0x01, 0x61}; // 版本 0x02
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(bad)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5ConnSession, VersionMismatchRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(err, Error::VersionMismatch);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 3> bad_greeting{0x04, 0x01, 0x00}; // 版本错误
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(bad_greeting)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5ConnSession, NoAcceptableMethod)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：要求 user_pass，客户端仅提供 no_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableAuth = true;
                         cfg.username = "alice";
                         cfg.password = "Secret";
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::NotSupported);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, ClientRejectsUnexpectedMethod)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：Greeting 后选择 gssapi（客户端未提供且未开认证）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x00};
                         std::error_code ec;
                         co_await b.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ec);
                         std::array<std::uint8_t, 2> sel{0x05, 0x01}; // gssapi
                         co_await b.async_write_some(AsBytes(std::span<const std::uint8_t>(sel)), ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::NotSupported);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, TcpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableTcp = false;
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：收到 command_not_supported 响应 → bad_auth
                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::BadAuth);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, UdpDisabledRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableUdp = false;
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Socks5::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443),
                         Socks5::Command::UdpAssociate});
                     EXPECT_EQ(herr, Error::BadAuth);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, BadCommandRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：非法命令 → not_supported + general_failure 响应
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(err, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：Greeting + 请求（cmd=0x09 非法）
                     std::error_code ec;
                     const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ec);
                     const std::array<std::uint8_t, 10> req{0x05, 0x09, 0x00, 0x03, 0x0B, 'e', 'x',
                                                            'a',  'm',  'p'};
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(req)), ec);
                     // 读取方法选择（避免服务端响应写失败）
                     std::array<std::uint8_t, 2> sel{};
                     co_await a.async_read_some(AsBytes(std::span<std::uint8_t>(sel)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5ConnSession, BadAtypRejected)
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
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(err, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::error_code ec;
                     const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ec);
                     const std::array<std::uint8_t, 6> req{0x05, 0x01, 0x00, 0x99, 0x00, 0x50}; // ATYP 非法
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(req)), ec);
                     // 读取方法选择（避免服务端响应写失败）
                     std::array<std::uint8_t, 2> sel{};
                     co_await a.async_read_some(AsBytes(std::span<std::uint8_t>(sel)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5ConnSession, ClientIoErrorOnClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.Close(); // 对端已全关 → Greeting 发送失败 → io_error
                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, ClientGreetingEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：读完 Greeting 后直接关闭 → 客户端读方法选择 EOF → io_error
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 4> Greeting{};
                         std::error_code ec;
                         const auto n = co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(Greeting)),
                                                                   ec);
                         EXPECT_GT(n, 0u);
                         b.Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(Socks5ConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto c = std::make_shared<Socks5::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     // 透传读写（未握手状态原样透传）
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
                     // ReadExact 公开接口（供包连接复用）
                     std::array<std::uint8_t, 4> dst{};
                     co_await b.async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     const auto Ok = co_await c->ReadExact(std::span<std::uint8_t>(dst));
                     EXPECT_FALSE(Ok);
                     c->Close();
                     c->Cancel();
                     const Socks5::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                 });
    }

} // namespace

    // ── 深度接口：IsValid / Underlying ──

    TEST(Socks5ConnDeep, ValidAfterHandshake)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), Socks5::ServerConfig{});
                if (err == Error::None && Conn)
                {
                    EXPECT_TRUE(Conn->IsValid());
                    EXPECT_TRUE(Conn->Underlying() != nullptr);
                    Conn->Close();
                }
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            std::string host = "example.com";
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03, static_cast<std::uint8_t>(host.size())});
            wire.insert(wire.end(), host.begin(), host.end());
            wire.push_back(0x01);
            wire.push_back(0xBB);
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            std::array<std::uint8_t, 12> resp{};
            co_await a.async_read_some(AsBytes(std::span<std::uint8_t>(resp)), ec);
        });
    }
