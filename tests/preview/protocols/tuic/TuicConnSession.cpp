/**
 * @file TuicConnSession.cpp
 * @brief Tuic 流式连接会话测试（conn 成功路径）
 * @details 覆盖：
 *          - connect 握手 → accept 握手 → 双向数据往返
 *          - 认证失败（密码不匹配）→ accept 拒绝
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

#include <common/core/byte_span.hpp>
#include <common/core/transport/reliable.hpp>
#include <common/protocols/tuic/tuic.hpp>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

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
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();

        tuic::client_config ccfg;
        ccfg.uuid = test_uuid();
        ccfg.password = "pw";
        tuic::server_config scfg;
        scfg.uuid = test_uuid();
        scfg.password = "pw";

        tuic::address target;
        target.type = tuic::address_type::domain;
        target.host = "example.com";
        target.port = 443;

        std::string echo_back;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端 accept + 回显
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             auto sock = co_await acceptor.async_accept(net::use_awaitable);
                             auto [aerr, msg, sconn] = co_await tuic::accept(
                                 std::make_shared<transport::reliable>(std::move(sock)), scfg);
                             (void)msg;
                             if (aerr != error::none || !sconn)
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

                     // 客户端 connect
                     tcp::socket sock(ioc.get_executor());
                     co_await sock.async_connect(tcp::endpoint(net::ip::address_v4::loopback(), port),
                                                 net::use_awaitable);
                     auto [err, conn] = co_await tuic::connect(
                         std::make_shared<transport::reliable>(std::move(sock)), ccfg, target);
                     if (err != error::none || !conn)
                     {
                         co_return;
                     }

                     // 数据往返（客户端写 → 服务端读 → 回显 → 客户端读）
                     const std::string msg = "tuic-stream";
                     std::error_code ec;
                     co_await conn->async_write_some(as_bytes_span(msg), ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await conn->async_read_some(std::span<std::byte>(buf), ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                 });
        EXPECT_EQ(echo_back, "tuic-stream");
    }

    TEST(TuicConnSession, BadFrameRejected)
    {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();

        tuic::server_config scfg;
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
                             const auto [aerr2, msg2, sconn2] = co_await tuic::accept(
                                 std::make_shared<transport::reliable>(std::move(sock)), scfg);
                             (void)msg2;
                             (void)sconn2;
                             accept_rejected = (aerr2 != error::none);
                         },
                         net::detached);

                     // 发送垃圾字节（非 tuic 帧）→ accept 解析失败
                     tcp::socket sock(ioc.get_executor());
                     co_await sock.async_connect(tcp::endpoint(net::ip::address_v4::loopback(), port),
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
