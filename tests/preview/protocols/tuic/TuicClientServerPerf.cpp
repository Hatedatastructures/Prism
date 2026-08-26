/**
 * @file TuicClientServerPerf.cpp
 * @brief Tuic 客户端/服务端封装测试（传输 + 性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/Bench/Bench.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
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

    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        u.fill(0x55);
        return u;
    }

    auto make_dst() -> Tuic::Address
    {
        Tuic::Address dst{};
        dst.Type = Tuic::AddressType::Ipv4;
        dst.Host = "93.184.216.34";
        dst.Port = 443;
        return dst;
    }

    TEST(TuicClientServer, HandshakeAndTransfer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        constexpr std::size_t kTotal = 4 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, req, Conn] =
                             co_await Tuic::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                   Tuic::ServerConfig{make_uuid(), "pw"});
                         if (err != Error::None)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.dst.Port, 443u);
                         std::array<std::byte, kBlock> buf{};
                         std::size_t got = 0;
                         while (got < kTotal)
                         {
                             std::error_code ec;
                             const auto n = co_await Conn->async_read_some(buf, ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             got += n;
                         }
                         EXPECT_EQ(got, kTotal);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] =
                         co_await Tuic::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                Tuic::ClientConfig{make_uuid(), "pw"}, make_dst());
                     if (herr != Error::None || !cli)
                     {
                         EXPECT_TRUE(false) << "Connect Failed";
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
                         std::size_t Done = 0;
                         while (Done < n)
                         {
                             std::error_code ec;
                             const auto w = co_await cli->async_write_some(
                                 std::span<const std::byte>(
                                     reinterpret_cast<const std::byte *>(payload.data() + Done), n - Done),
                                 ec);
                             if (ec || w == 0)
                             {
                                 break;
                             }
                             Done += w;
                         }
                         if (Done < n)
                         {
                             break;
                         }
                         sent += n;
                     }
                     EXPECT_EQ(sent, kTotal);
                     cli->Close();
                 });
    }

    TEST(TuicClientServer, UdpDatagramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [err, req, Conn] =
                        co_await Tuic::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                              Tuic::ServerConfig{make_uuid(), "pw"});
                    if (err != Error::None)
                    {
                        co_return;
                    }
                    Tuic::Address src;
                    std::vector<std::uint8_t> payload;
                    const auto rerr = co_await Conn->AsyncReceiveDatagram(src, payload);
                    EXPECT_EQ(rerr, Error::None);
                    EXPECT_EQ(std::string(payload.begin(), payload.end()), "hello udp");
                    std::vector<std::uint8_t> back(payload.rbegin(), payload.rend());
                    (void)co_await Conn->AsyncSendDatagram(src, back);
                    Conn->Close();
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto [herr, cli] = co_await Tuic::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                          Tuic::ClientConfig{make_uuid(), "pw"}, make_dst());
                if (herr != Error::None || !cli)
                {
                    co_return;
                }
                const std::string payload = "hello udp";
                auto serr = co_await cli->AsyncSendDatagram(
                    make_dst(), std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
                EXPECT_EQ(serr, Error::None);
                Tuic::Address src;
                std::vector<std::uint8_t> back;
                const auto rerr = co_await cli->AsyncReceiveDatagram(src, back);
                EXPECT_EQ(rerr, Error::None);
                EXPECT_EQ(std::string(back.begin(), back.end()), "pdu olleh");
                cli->Close();
            });
    }

} // namespace
