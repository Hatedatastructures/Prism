/**
 * @file Socks5DgramSession.cpp
 * @brief SOCKS5 Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 ConnectPacket / 服务端 AcceptPacket（UDP_ASSOCIATE 握手）→ 数据报往返
 * 2. 地址解析：IPv4 / 域名 / IPv6
 * 3. 错误分支：bad_message（RSV/FRAG 非法、ATYP 非法）/ io_error / unexpected_eof
 * 4. 装饰器链方法：Executor / TransportType / NextLayer / Stream / Release
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
#include <common/Protocols/Socks5/Socks5.hpp>
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

    TEST(Socks5DgramSession, SendReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AcceptPacket 完成 UDP_ASSOCIATE 握手 → Dgram 收包回发
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableUdp = true;
                         auto [err, req, dg] =
                             co_await Socks5::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                            cfg);
                         if (err != Error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "AcceptPacket Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, Socks5::Command::UdpAssociate);
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::udp);
                         // 接收两个包（域名 + IPv4）
                         for (int i = 0; i < 2; ++i)
                         {
                             Socks5::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto rerr = co_await dg->AsyncReceiveFrom(src, payload);
                             EXPECT_EQ(rerr, Error::none);
                             if (i == 0)
                             {
                                 EXPECT_EQ(src.Type, Socks5::AddressType::Domain);
                                 EXPECT_EQ(src.Host, "example.com");
                                 EXPECT_EQ(src.Port, 53u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "dns query");
                             }
                             else
                             {
                                 EXPECT_EQ(src.Type, Socks5::AddressType::Ipv4);
                                 EXPECT_EQ(src.Host, "8.8.8.8");
                                 EXPECT_EQ(src.Port, 443u);
                                 EXPECT_EQ(std::string(payload.begin(), payload.end()), "second pkt");
                             }
                         }
                         EXPECT_TRUE(dg->Stream());
                         EXPECT_NE(dg->NextLayer(), nullptr);
                         EXPECT_NE(dg->LowestLayer<MemoryStream>(), nullptr);
                         const Socks5::Dgram<> *const_dg = dg.get();
                         EXPECT_NE(const_dg->NextLayer(), nullptr);
                         EXPECT_TRUE(dg->Executor());
                         // 透传读（客户端透传写的数据）
                         std::array<std::byte, 8> raw{};
                         std::error_code ec;
                         const auto r = co_await dg->AsyncReadSome(raw, ec);
                         EXPECT_EQ(r, 4u);
                         dg->Close();
                         dg->Cancel();
                         auto released = dg->Release();
                         EXPECT_TRUE(released);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await Socks5::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p1 = "dns query";
                     auto serr = co_await dg->AsyncSendTo(
                         make_addr(Socks5::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p1.data()),
                                                       p1.size()));
                     EXPECT_EQ(serr, Error::none);
                     const std::string p2 = "second pkt";
                     serr = co_await dg->AsyncSendTo(
                         make_addr(Socks5::AddressType::Ipv4, "8.8.8.8", 443),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p2.data()),
                                                       p2.size()));
                     EXPECT_EQ(serr, Error::none);
                     // 透传写（服务端读端无消费，仅覆盖 passthrough）
                     const std::array<std::byte, 4> raw{};
                     std::error_code ec;
                     const auto w = co_await dg->AsyncWriteSome(
                         std::span<const std::byte>(raw.data(), 4), ec);
                     EXPECT_EQ(w, 4u);
                 });
    }

    TEST(Socks5DgramSession, Ipv6Receive)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：IPv6 地址解析
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Socks5::ServerConfig cfg;
                         cfg.EnableUdp = true;
                         auto [err, req, dg] =
                             co_await Socks5::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                            cfg);
                         if (err != Error::none || !dg)
                         {
                             co_return;
                         }
                         Socks5::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(rerr, Error::none);
                         EXPECT_EQ(src.Type, Socks5::AddressType::Ipv6);
                         EXPECT_EQ(src.Host, std::string(16, '\x21'));
                         EXPECT_EQ(src.Port, 8080u);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "v6 pkt");
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, dg] = co_await Socks5::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                         make_addr(Socks5::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "v6 pkt";
                     const auto serr = co_await dg->AsyncSendTo(
                         make_addr(Socks5::AddressType::Ipv6, std::string(16, '\x21'), 8080),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, Error::none);
                 });
    }

    TEST(Socks5DgramSession, BadRsvRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：RSV/FRAG 非零 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Socks5::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Socks5::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::bad_message);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 3> wire{0x00, 0x00, 0x01}; // FRAG 非零
                     std::error_code ec;
                     co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5DgramSession, BadAtypRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：ATYP 非法 → bad_message
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Socks5::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Socks5::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::bad_message);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::array<std::uint8_t, 4> wire{0x00, 0x00, 0x00, 0x99}; // ATYP 非法
                     std::error_code ec;
                     co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5DgramSession, HeaderWithoutPayload)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：地址头完整但无载荷 → unexpected_eof
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto dg = std::make_shared<Socks5::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(b)));
                         Socks5::Address src;
                         std::vector<std::uint8_t> payload;
                         const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                         EXPECT_EQ(err, Error::unexpected_eof);
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // [RSV 3B][ATYP=1][IPv4 4B][Port 2B] 无载荷，随后关闭
                     const std::array<std::uint8_t, 10> wire{0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     std::error_code ec;
                     co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
                     a.Close();
                 });
    }

    TEST(Socks5DgramSession, PeerClosedEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Socks5::Dgram<>>(std::make_shared<MemoryStream>(std::move(b)));
                     a.Close(); // 对端关闭 → 读 EOF → io_error
                     Socks5::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::io_error);
                     dg->Close();
                     dg->Cancel();
                     EXPECT_NE(dg->NextLayer(), nullptr);
                     auto released = dg->Release();
                     EXPECT_TRUE(released);
                 });
    }

    TEST(Socks5DgramSession, SendToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto dg = std::make_shared<Socks5::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端关闭 → 写失败 → io_error
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(
                         make_addr(Socks5::AddressType::Domain, "example.com", 53),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::io_error);
                     dg->Close();
                 });
    }

} // namespace
