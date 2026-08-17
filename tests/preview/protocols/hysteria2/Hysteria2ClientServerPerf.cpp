/**
 * @file Hysteria2ClientServerPerf.cpp
 * @brief Hysteria2 客户端/服务端封装测试（传输 + 性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/bench/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/hysteria2/hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    namespace net = boost::asio;

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

    auto make_dst() -> hysteria2::address
    {
        hysteria2::address dst{};
        dst.type = hysteria2::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    TEST(Hysteria2ClientServer, HandshakeAndTransfer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        constexpr std::size_t kTotal = 4 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"pw123456"});
                         if (err != error::none)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(req.dst.port, 443u);
                         std::array<std::byte, kBlock> buf{};
                         std::size_t got = 0;
                         while (got < kTotal)
                         {
                             std::error_code ec;
                             const auto n = co_await conn->async_read_some(buf, ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             got += n;
                         }
                         EXPECT_EQ(got, kTotal);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await hysteria2::connect(std::make_shared<memory_stream>(std::move(a)),
                                                     hysteria2::client_config{"pw123456"}, make_dst());
                     if (herr != error::none || !cli)
                     {
                         EXPECT_TRUE(false) << "connect failed";
                         co_return;
                     }
                     std::vector<std::uint8_t> payload(kBlock, 0x4D);
                     std::size_t sent = 0;
                     std::size_t yield_cnt = 0;
                     while (sent < kTotal)
                     {
                         if ((++yield_cnt % 16) == 0)
                         {
                             co_await net::post(ioc.get_executor(), net::use_awaitable);
                         }
                         const auto n = std::min(kBlock, kTotal - sent);
                         std::size_t done = 0;
                         while (done < n)
                         {
                             std::error_code ec;
                             const auto w = co_await cli->async_write_some(
                                 std::span<const std::byte>(
                                     reinterpret_cast<const std::byte *>(payload.data() + done), n - done),
                                 ec);
                             if (ec || w == 0)
                             {
                                 break;
                             }
                             done += w;
                         }
                         if (done < n)
                         {
                             break;
                         }
                         sent += n;
                     }
                     EXPECT_EQ(sent, kTotal);
                     cli->close();
                 });
    }

    TEST(Hysteria2ClientServer, UdpDatagramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{"pw123456"});
                         if (err != error::none)
                         {
                             co_return;
                         }
                         hysteria2::address src;
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await conn->async_receive_datagram(src, payload);
                         EXPECT_EQ(rerr, error::none);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "hello udp");
                         std::vector<std::uint8_t> back(payload.rbegin(), payload.rend());
                         (void)co_await conn->async_send_datagram(src, back);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await hysteria2::connect(std::make_shared<memory_stream>(std::move(a)),
                                                     hysteria2::client_config{"pw123456"}, make_dst());
                     if (herr != error::none || !cli)
                     {
                         co_return;
                     }
                     const std::string payload = "hello udp";
                     auto serr = co_await cli->async_send_datagram(
                         make_dst(),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                       payload.size()));
                     EXPECT_EQ(serr, error::none);
                     hysteria2::address src;
                     std::vector<std::uint8_t> back;
                     const auto rerr = co_await cli->async_receive_datagram(src, back);
                     EXPECT_EQ(rerr, error::none);
                     EXPECT_EQ(std::string(back.begin(), back.end()), "pdu olleh");
                     cli->close();
                 });
    }

} // namespace
