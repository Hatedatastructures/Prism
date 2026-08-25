/**
 * @file TrusttunnelDgramSession.cpp
 * @brief TrustTunnel Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 ConnectPacket / 服务端 AcceptPacket（CONNECT 认证握手）→ 数据报往返
 * 2. 错误分支：io_error（对端关闭）/ unexpected_eof（读 EOF）
 * 3. 装饰器链方法：Executor / TransportType / NextLayer / Stream / Release / Close / Cancel
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
#include <common/Protocols/Trusttunnel/Trusttunnel.hpp>
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

    TEST(TrusttunnelDgramSession, SendReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AcceptPacket 完成 CONNECT 认证 → Dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trusttunnel::ServerConfig cfg;
                         cfg.username = "admin";
                         cfg.password = "Secret";
                         auto [err, Target, dg] =
                             co_await Trusttunnel::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                                 cfg);
                         if (err != Error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "AcceptPacket Failed";
                             co_return;
                         }
                         EXPECT_EQ(Target, "example.com");
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::udp);
                         std::string host;
                         std::uint16_t port = 0;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->AsyncReceiveFrom(host, port, payload);
                         EXPECT_EQ(rerr, Error::none);
                         EXPECT_EQ(host, "dns.google");
                         EXPECT_EQ(port, 53u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "Dgram hello");
                         // 回发
                         const auto serr = co_await dg->AsyncSendTo(host, port, payload);
                         EXPECT_EQ(serr, Error::none);
                         // 透传读写（passthrough）
                         std::array<std::byte, 8> raw{};
                         std::error_code ec;
                         const auto w = co_await dg->AsyncWriteSome(
                             std::span<const std::byte>(raw.data(), 4), ec);
                         EXPECT_EQ(w, 4u);
                         const auto r = co_await dg->AsyncReadSome(raw, ec);
                         EXPECT_GT(r, 0u); // 客户端透传写的数据
                         EXPECT_TRUE(dg->Stream());
                         EXPECT_NE(dg->NextLayer(), nullptr);
                         EXPECT_NE(dg->LowestLayer<MemoryStream>(), nullptr);
                         const Trusttunnel::Dgram *const_dg = dg.get();
                         EXPECT_NE(const_dg->NextLayer(), nullptr);
                         // 底层 Conn 的 const 装饰器导航
                         auto Inner = dg->Stream();
                         const auto *const_conn = dynamic_cast<const Trusttunnel::Conn<> *>(Inner.get());
                         EXPECT_NE(const_conn, nullptr);
                         if (const_conn)
                         {
                             EXPECT_NE(const_conn->NextLayer(), nullptr);
                         }
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Trusttunnel::ClientConfig cfg;
                     cfg.username = "admin";
                     cfg.password = "Secret";
                     auto [herr, dg] = co_await Trusttunnel::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg, "example.com", 443);
                     EXPECT_EQ(herr, Error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     EXPECT_TRUE(dg->Executor());
                     const std::string p = "Dgram hello";
                     const auto serr = co_await dg->AsyncSendTo(
                         "dns.google", 53,
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, Error::none);
                     // 读取回发帧（1B hostlen + host + 2B port + payload）
                     std::string host;
                     std::uint16_t port = 0;
                     std::vector<std::uint8_t> back;
                     const auto rerr = co_await dg->AsyncReceiveFrom(host, port, back);
                     EXPECT_EQ(rerr, Error::none);
                     EXPECT_EQ(host, "dns.google");
                     EXPECT_EQ(port, 53u);
                     EXPECT_EQ(std::string(back.begin(), back.end()), "Dgram hello");
                     // 透传写（服务端透传读的数据）
                     const std::array<std::byte, 8> raw{};
                     std::error_code ec;
                     const auto w = co_await dg->AsyncWriteSome(
                         std::span<const std::byte>(raw.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                     dg->Close();
                     dg->Cancel();
                     auto released = dg->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(dg->NextLayer(), nullptr);
                 });
    }

    TEST(TrusttunnelDgramSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：凭据不匹配 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Trusttunnel::ServerConfig cfg;
                         cfg.username = "admin";
                         cfg.password = "Secret";
                         auto [err, Target, dg] =
                             co_await Trusttunnel::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                                 cfg);
                         EXPECT_EQ(err, Error::bad_auth);
                         EXPECT_FALSE(dg);
                         (void)Target;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Trusttunnel::ClientConfig cfg;
                     cfg.username = "admin";
                     cfg.password = "wrong";
                     auto [herr, dg] = co_await Trusttunnel::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg, "example.com", 443);
                     EXPECT_EQ(herr, Error::none); // 客户端只发送 CONNECT，不感知认证结果
                     if (dg)
                     {
                         dg->Close();
                     }
                 });
    }

    TEST(TrusttunnelDgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Trusttunnel::Dgram>(
                         std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(
                         "example.com", 80,
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::io_error);
                     dg->Close();
                 });
    }

    TEST(TrusttunnelDgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Trusttunnel::Dgram>(
                         std::make_shared<MemoryStream>(std::move(b)));
                     a.Close(); // 对端关闭 → 读 EOF → unexpected_eof
                     std::string host;
                     std::uint16_t port = 0;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(host, port, payload);
                     EXPECT_EQ(err, Error::unexpected_eof);
                     dg->Close();
                 });
    }

} // namespace
