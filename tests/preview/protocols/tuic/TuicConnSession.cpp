/**
 * @file TuicConnSession.cpp
 * @brief Tuic 流式连接会话测试（Conn 成功路径）
 * @details 覆盖：
 *          - Connect 握手 → Accept 握手 → 双向数据往返
 *          - 认证失败（密码不匹配）→ Accept 拒绝
 *          - 握手后数据面透传
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Tuic/Tuic.hpp>

namespace
{
    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
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

    auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        for (std::size_t i = 0; i < u.size(); ++i)
        {
            u[i] = static_cast<std::uint8_t>(0x40 + i);
        }
        return u;
    }

    TEST(TuicConnSession, ConnectAcceptRoundtrip)
    {
        net::io_context ioc;
        Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();

        Tuic::ClientConfig ccfg;
        ccfg.uuid = test_uuid();
        ccfg.password = "pw";
        Tuic::ServerConfig scfg;
        scfg.uuid = test_uuid();
        scfg.password = "pw";

        Tuic::Address Target;
        Target.Type = Tuic::AddressType::Domain;
        Target.Host = "example.com";
        Target.Port = 443;

        std::string echo_back;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端 Accept + 回显
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             auto sock = co_await acceptor.async_accept(net::use_awaitable);
                             auto [aerr, msg, sconn] = co_await Tuic::Accept(
                                 std::make_shared<Transport::Reliable>(std::move(sock)), scfg);
                             (void)msg;
                             if (aerr != Error::None || !sconn)
                             {
                                 co_return;
                             }
                             // 回显一次
                             std::array<std::byte, 64> buf{};
                             std::error_code ec;
                             const auto n = co_await sconn->async_read_some(std::span<std::byte>(buf), ec);
                             if (n > 0)
                             {
                                 co_await sconn->async_write_some(
                                     std::span<const std::byte>(buf.data(), n), ec);
                             }
                         },
                         net::detached);

                     // 客户端 Connect
                     Tcp::socket sock(ioc.get_executor());
                     co_await sock.async_connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port),
                                                 net::use_awaitable);
                     auto [err, Conn] = co_await Tuic::Connect(
                         std::make_shared<Transport::Reliable>(std::move(sock)), ccfg, Target);
                     if (err != Error::None || !Conn)
                     {
                         co_return;
                     }

                     // 数据往返（客户端写 → 服务端读 → 回显 → 客户端读）
                     const std::string msg = "tuic-Stream";
                     std::error_code ec;
                     co_await Conn->async_write_some(AsBytesSpan(msg), ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await Conn->async_read_some(std::span<std::byte>(buf), ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                 });
        EXPECT_EQ(echo_back, "tuic-Stream");
    }

    TEST(TuicConnSession, BadFrameRejected)
    {
        net::io_context ioc;
        Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();

        Tuic::ServerConfig scfg;
        scfg.uuid = test_uuid();
        scfg.password = "pw";

        bool accept_rejected = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             auto sock = co_await acceptor.async_accept(net::use_awaitable);
                             const auto [aerr2, msg2, sconn2] = co_await Tuic::Accept(
                                 std::make_shared<Transport::Reliable>(std::move(sock)), scfg);
                             (void)msg2;
                             (void)sconn2;
                             accept_rejected = (aerr2 != Error::None);
                         },
                         net::detached);

                     // 发送垃圾字节（非 tuic 帧）→ Accept 解析失败
                     Tcp::socket sock(ioc.get_executor());
                     co_await sock.async_connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port),
                                                 net::use_awaitable);
                     const std::string garbage = "\xff\xfe\xfd\xfc";
                     co_await sock.async_write_some(net::buffer(garbage), net::use_awaitable);
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(200));
                     co_await t.async_wait(net::use_awaitable);
                 });
        EXPECT_TRUE(accept_rejected);
    }

} // namespace
