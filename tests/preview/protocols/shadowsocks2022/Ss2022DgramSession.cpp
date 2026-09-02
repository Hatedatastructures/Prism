/**
 * @file Ss2022DgramSession.cpp
 * @brief SS2022 UDP 数据报会话测试（Dgram 成功路径）
 * @details 覆盖：
 *          - 客户端 → 服务端单向数据报（逐包 AEAD）
 *          - 双向回环（服务端回发）
 *          - 包内目标地址解析（src 还原）
 *          - 错误路径：无数据超时 / 绑定时钟不回
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    auto ReceiveWithDeadline(const Shadowsocks2022::SharedDgram &Dgram,
                             Shadowsocks2022::Address &Source,
                             std::vector<std::uint8_t> &Payload)
        -> net::awaitable<std::optional<Error>>
    {
        net::steady_timer Timer(Dgram->Executor());
        Timer.expires_after(std::chrono::milliseconds(250));
        using boost::asio::experimental::awaitable_operators::operator||;
        auto Result = co_await (Dgram->AsyncReceiveFrom(Source, Payload) ||
                                Timer.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            Dgram->Close();
            co_return std::nullopt;
        }
        co_return std::get<0>(std::move(Result));
    }

    TEST(Ss2022DgramSession, ClientToServerDatagram)
    {
        net::io_context ioc;

        Shadowsocks2022::ServerConfig cfg;
        const std::array<std::uint8_t, 16> Key{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        cfg.password = "pass123";
        cfg.Psk = Key;
        cfg.UsePsk = true;
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, cfg);
        ASSERT_NE(Server, nullptr);

        // 客户端：连接服务端端口（从底层 socket 取）
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        Shadowsocks2022::ClientConfig client_cfg;
        client_cfg.password = "pass123";
        client_cfg.Psk = Key;
        client_cfg.UsePsk = true;
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(Client, nullptr);

        // 目标地址（服务端收到的包内目标）
        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 12345;

        std::string received;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端收（先挂起）
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             if (err == Error::None)
                             {
                                 received.assign(reinterpret_cast<const char *>(payload.data()),
                                                 payload.size());
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "ss2022-Dgram";
                     const auto err = co_await Client->AsyncSendTo(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, Error::None);

                     // 等服务端收到
                     for (int i = 0; i < 50 && received.empty(); ++i)
                     {
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(received, "ss2022-Dgram");
    }

    TEST(Ss2022DgramSession, ClientSessionIdsAndFirstPacketId)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, 16> Key{};
        Key.fill(0x42);
        auto Client = std::make_shared<Shadowsocks2022::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(a)), Key, Shadowsocks2022::UdpRole::Client);
        auto Peer = std::make_shared<MemoryStream>(std::move(b));
        auto [c, d] = MakeMemoryPair(ioc.get_executor());
        auto Client2 = std::make_shared<Shadowsocks2022::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(c)), Key, Shadowsocks2022::UdpRole::Client);

        EXPECT_NE(Client->SessionId(), Client2->SessionId());
        Shadowsocks2022::Address Target;
        Target.Type = Shadowsocks2022::AddressType::Ipv4;
        Target.Host = "192.0.2.1";
        Target.Port = 443;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     EXPECT_EQ(co_await Client->AsyncSendTo(Target, AsU8Span(std::string_view{"first"})),
                               Error::None);
                     std::array<std::uint8_t, 2048> Wire{};
                     std::error_code Ec;
                     const auto N = co_await Peer->async_read_some(AsBytes(std::span<std::uint8_t>(Wire)), Ec);
                     EXPECT_GT(N, Shadowsocks2022::SeparateHdrLen);
                     if (N <= Shadowsocks2022::SeparateHdrLen)
                     {
                         co_return;
                     }
                     std::vector<std::uint8_t> Packet(Wire.begin(), Wire.begin() + N);
                     std::array<std::uint8_t, Shadowsocks2022::SessionIdLen> Session{};
                     std::uint64_t PacketId = 99;
                     std::uint8_t Type = 0xFF;
                     Shadowsocks2022::Address Parsed;
                     std::vector<std::uint8_t> Payload;
                     EXPECT_EQ(Shadowsocks2022::ParseUdpPacket(
                                   {Key, Packet, &Parsed, &Payload, &Session, &PacketId, nullptr, &Type, nullptr}),
                               Error::None);
                     EXPECT_EQ(Session, Client->SessionId());
                     EXPECT_EQ(PacketId, 0u);
                     EXPECT_EQ(Type, Shadowsocks2022::HeaderTypeClient);
                 });
    }

    TEST(Ss2022DgramSession, BidirectionalEcho)
    {
        net::io_context ioc;

        Shadowsocks2022::ServerConfig cfg;
        cfg.password = "echo-pass";
        const std::array<std::uint8_t, 16> Key{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                               0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
        cfg.Psk = Key;
        cfg.UsePsk = true;
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, cfg);
        ASSERT_NE(Server, nullptr);
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        Shadowsocks2022::ClientConfig client_cfg;
        client_cfg.password = "echo-pass";
        client_cfg.Psk = Key;
        client_cfg.UsePsk = true;
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(Client, nullptr);

        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 9999;

        std::string echoed;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：收 → 原样回发
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             if (err == Error::None)
                             {
                                 co_await Server->AsyncSendTo(src, payload);
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "echo-me";
                     auto err = co_await Client->AsyncSendTo(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, Error::None);

                     // 客户端收回显
                     Shadowsocks2022::Address src2;
                     std::vector<std::uint8_t> back;
                     err = co_await Client->AsyncReceiveFrom(src2, back);
                     EXPECT_EQ(err, Error::None);
                     echoed.assign(reinterpret_cast<const char *>(back.data()), back.size());
                 });
        EXPECT_EQ(echoed, "echo-me");
    }

    TEST(Ss2022DgramSession, InvalidDatagramCannotHijackPeer)
    {
        net::io_context ioc;
        const std::array<std::uint8_t, 16> Key{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                                               0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60};

        Shadowsocks2022::ServerConfig ServerConfig;
        ServerConfig.UsePsk = true;
        ServerConfig.Psk = Key;
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, ServerConfig);
        ASSERT_NE(Server, nullptr);
        const auto ServerUdp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort = ServerUdp->NativeSocket().local_endpoint().port();

        Shadowsocks2022::ClientConfig ClientConfig;
        ClientConfig.UsePsk = true;
        ClientConfig.Psk = Key;
        const auto Client = Shadowsocks2022::ConnectPacket(
            ioc.get_executor(), "127.0.0.1:" + std::to_string(ServerPort), ClientConfig);
        ASSERT_NE(Client, nullptr);

        auto Attacker = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        ASSERT_TRUE(Attacker->Connect("127.0.0.1:" + std::to_string(ServerPort)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const Shadowsocks2022::Address Target{
                         Shadowsocks2022::AddressType::Domain, "example.com", 443};
                     const auto ValidPayload = AsU8Span(std::string_view{"valid"});
                     EXPECT_EQ(co_await Client->AsyncSendTo(Target, ValidPayload), Error::None);

                     Shadowsocks2022::Address Source;
                     std::vector<std::uint8_t> Payload;
                     EXPECT_EQ(co_await Server->AsyncReceiveFrom(Source, Payload), Error::None);
                     EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "valid");

                     std::array<std::uint8_t, 16> BadKey{};
                     BadKey.fill(0xEE);
                     std::array<std::uint8_t, Shadowsocks2022::SessionIdLen> BadSession{};
                     BadSession.fill(0xD1);
                     std::vector<std::uint8_t> BadWire;
                     const auto Built = Shadowsocks2022::BuildUdpPacket(
                         {BadKey, 0, &Target, ValidPayload, BadSession}, BadWire);
                     EXPECT_TRUE(Built);
                     if (!Built)
                     {
                         co_return;
                     }
                     std::error_code WriteEc;
                     EXPECT_EQ(co_await Attacker->async_write_some(
                                   AsBytes(std::span<const std::uint8_t>(BadWire)), WriteEc),
                               BadWire.size());
                     EXPECT_FALSE(WriteEc);

                     Payload.clear();
                     const auto BadErr = co_await Server->AsyncReceiveFrom(Source, Payload);
                     EXPECT_NE(BadErr, Error::None);

                     const auto ResponseErr = co_await Server->AsyncSendTo(Source, ValidPayload);
                     EXPECT_EQ(ResponseErr, Error::None);
                     Shadowsocks2022::Address ResponseSource;
                     std::vector<std::uint8_t> Response;
                     const auto ClientErr = co_await ReceiveWithDeadline(
                         Client, ResponseSource, Response);
                     EXPECT_TRUE(ClientErr.has_value());
                     if (!ClientErr.has_value())
                     {
                         co_return;
                     }
                     EXPECT_EQ(*ClientErr, Error::None);
                     EXPECT_EQ(std::string(Response.begin(), Response.end()), "valid");
                 });
    }

    TEST(Ss2022DgramSession, BadPasswordRejected)
    {
        net::io_context ioc;

        Shadowsocks2022::ServerConfig server_cfg;
        server_cfg.password = "Server-pass";
        const std::array<std::uint8_t, 16> ServerKey{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                                     0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
        server_cfg.Psk = ServerKey;
        server_cfg.UsePsk = true;
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, server_cfg);
        ASSERT_NE(Server, nullptr);
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        // 错误密码客户端
        Shadowsocks2022::ClientConfig bad_cfg;
        bad_cfg.password = "wrong-pass";
        bad_cfg.Psk.fill(0x99);
        bad_cfg.UsePsk = true;
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port), bad_cfg);
        ASSERT_NE(Client, nullptr);

        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 7777;

        bool server_received = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             server_received = (err == Error::None);
                         },
                         net::detached);

                     const std::string msg = "bad-key";
                     co_await Client->AsyncSendTo(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));

                     // 密码不匹配 → 服务端 AEAD 解密失败 → 不产生有效包
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(100));
                     co_await t.async_wait(net::use_awaitable);
                 });
        EXPECT_FALSE(server_received);
    }

} // namespace
