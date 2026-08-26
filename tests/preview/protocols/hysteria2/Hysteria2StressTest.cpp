/**
 * @file Hysteria2StressTest.cpp
 * @brief Hysteria2 协议会话压力测试
 * @details 生产级压力验证：
 * 1. 200 次连接循环（握手 + 回显，计数验证）
 * 2. 16 并发连接（并发正确性）
 * 3. 2MB 数据传输（64KB 分块，累积校验）
 * @note 使用 Hysteria2::Connect/Accept 自由函数 + MakeMemoryPair
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    constexpr const char *kPassword = "stress-pw";

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

    auto make_domain_addr(const std::string &host, std::uint16_t port) -> Hysteria2::Address
    {
        Hysteria2::Address addr{};
        addr.Type = Hysteria2::AddressType::Domain;
        addr.Host = host;
        addr.Port = port;
        return addr;
    }

    /// 单次会话：握手 + 回显往返
    auto one_session(net::io_context &ioc, const std::string &payload) -> bool
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        bool Ok = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept + 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, msg, Conn] =
                             co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                        Hysteria2::ServerConfig{kPassword});
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         std::array<std::byte, 4096> buf{};
                         std::error_code ec;
                         while (true)
                         {
                             const auto n = co_await Conn->async_read_some(buf, ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             co_await Conn->async_write_some(
                                 std::span<const std::byte>(buf.data(), n), ec);
                         }
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：Connect + 写入 + 读回显
                     auto Stream = std::make_shared<MemoryStream>(std::move(a));
                     auto [herr, cli] = co_await Hysteria2::Connect(
                         Stream, Hysteria2::ClientConfig{kPassword},
                         make_domain_addr("example.com", 443));
                     if (herr != Error::None || !cli)
                     {
                         co_return;
                     }
                     std::error_code wec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                         wec);
                     std::array<std::byte, 4096> echo{};
                     std::error_code rec;
                     std::size_t Total = 0;
                     while (Total < payload.size())
                     {
                         const auto n = co_await cli->async_read_some(
                             std::span<std::byte>(echo.data() + Total, echo.size() - Total), rec);
                         if (rec || n == 0)
                         {
                             break;
                         }
                         Total += n;
                     }
                     Ok = (Total == payload.size());
                     cli->Close();
                 });
        return Ok;
    }

    // ── 1. 200 次连接循环 ──

    TEST(Hysteria2Stress, ConnectLoop)
    {
        constexpr int kRounds = 200;
        const std::string payload = "hysteria2-stress";
        int ok_count = 0;
        for (int i = 0; i < kRounds; ++i)
        {
            net::io_context ioc;
            if (one_session(ioc, payload))
            {
                ++ok_count;
            }
        }
        EXPECT_EQ(ok_count, kRounds);
    }

    // ── 2. 16 并发连接 ──

    TEST(Hysteria2Stress, Concurrent16)
    {
        net::io_context ioc;
        std::atomic<int> success{0};
        const std::string payload = "concurrent-h2";
        for (int i = 0; i < 16; ++i)
        {
            auto [a, b] = MakeMemoryPair(ioc.get_executor());
            net::co_spawn(
                ioc.get_executor(),
                [b = std::move(b)]() mutable -> net::awaitable<void>
                {
                    auto [err, msg, Conn] =
                        co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                   Hysteria2::ServerConfig{kPassword});
                    if (err == Error::None && Conn)
                    {
                        std::array<std::byte, 128> buf{};
                        std::error_code ec;
                        const auto n = co_await Conn->async_read_some(buf, ec);
                        if (!ec && n > 0)
                        {
                            co_await Conn->async_write_some(
                                std::span<const std::byte>(buf.data(), n), ec);
                        }
                        Conn->Close();
                    }
                },
                net::detached);
            net::co_spawn(
                ioc.get_executor(),
                [&, a = std::move(a), payload]() mutable -> net::awaitable<void>
                {
                    auto Stream = std::make_shared<MemoryStream>(std::move(a));
                    auto [herr, cli] = co_await Hysteria2::Connect(
                        Stream, Hysteria2::ClientConfig{kPassword},
                        make_domain_addr("example.com", 443));
                    if (herr != Error::None || !cli)
                    {
                        co_return;
                    }
                    std::error_code ec;
                    co_await cli->async_write_some(
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                        ec);
                    std::array<std::byte, 128> echo{};
                    std::size_t rg = 0;
                    while (rg < payload.size())
                    {
                        const auto n = co_await cli->async_read_some(
                            std::span<std::byte>(echo.data() + rg, echo.size() - rg), ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        rg += n;
                    }
                    if (rg == payload.size())
                    {
                        success.fetch_add(1);
                    }
                    cli->Close();
                },
                net::detached);
        }
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 超时守卫：客户端失败时避免无限自旋
                     net::steady_timer t(ioc);
                     const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                     while (success.load() < 16 && std::chrono::steady_clock::now() < deadline)
                     {
                         t.expires_after(std::chrono::milliseconds(1));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(success.load(), 16);
    }

    // ── 3. 2MB 传输 ──

    TEST(Hysteria2Stress, Transfer2MB)
    {
        net::io_context ioc;
        constexpr std::size_t kTotal = 2 * 1024 * 1024;
        constexpr std::size_t kChunk = 64 * 1024;

        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::atomic<std::size_t> received{0};
        net::co_spawn(
            ioc.get_executor(),
            [b = std::move(b), &received]() mutable -> net::awaitable<void>
            {
                auto [err, msg, Conn] =
                    co_await Hysteria2::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                               Hysteria2::ServerConfig{kPassword});
                if (err != Error::None || !Conn)
                {
                    co_return;
                }
                std::array<std::byte, kChunk> buf{};
                std::error_code ec;
                std::size_t Total = 0;
                while (Total < kTotal)
                {
                    const auto n = co_await Conn->async_read_some(buf, ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Total += n;
                }
                received.store(Total);
                Conn->Close();
            },
            net::detached);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Stream = std::make_shared<MemoryStream>(std::move(a));
                     auto [herr, cli] = co_await Hysteria2::Connect(
                         Stream, Hysteria2::ClientConfig{kPassword},
                         make_domain_addr("example.com", 443));
                     if (herr != Error::None || !cli)
                     {
                         co_return;
                     }
                     std::vector<std::byte> chunk(kChunk, std::byte{0xAB});
                     std::error_code ec;
                     for (std::size_t sent = 0; sent < kTotal; sent += kChunk)
                     {
                         co_await cli->async_write_some(std::span<const std::byte>(chunk), ec);
                         if (ec)
                         {
                             break;
                         }
                     }
                     cli->Close();
                 });
        EXPECT_EQ(received.load(), kTotal);
    }

} // namespace
