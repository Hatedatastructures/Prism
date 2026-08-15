/**
 * @file Hysteria2StressTest.cpp
 * @brief Hysteria2 协议会话压力测试
 * @details 生产级压力验证：
 * 1. 200 次连接循环（握手 + 回显，计数验证）
 * 2. 16 并发连接（并发正确性）
 * 3. 2MB 数据传输（64KB 分块，累积校验）
 * @note 使用 hysteria2::connect/accept 自由函数 + make_memory_pair
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/hysteria2/hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
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

    auto make_domain_addr(const std::string &host, std::uint16_t port) -> hysteria2::address
    {
        hysteria2::address addr{};
        addr.type = hysteria2::address_type::domain;
        addr.host = host;
        addr.port = port;
        return addr;
    }

    /// 单次会话：握手 + 回显往返
    auto one_session(net::io_context &ioc, const std::string &payload) -> bool
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        bool ok = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept + 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, msg, conn] =
                             co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                        hysteria2::server_config{kPassword});
                         if (err != error::none || !conn)
                         {
                             co_return;
                         }
                         std::array<std::byte, 4096> buf{};
                         std::error_code ec;
                         while (true)
                         {
                             const auto n = co_await conn->async_read_some(buf, ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             co_await conn->async_write_some(
                                 std::span<const std::byte>(buf.data(), n), ec);
                         }
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：connect + 写入 + 读回显
                     auto stream = std::make_shared<memory_stream>(std::move(a));
                     auto [herr, cli] = co_await hysteria2::connect(
                         stream, hysteria2::client_config{kPassword},
                         make_domain_addr("example.com", 443));
                     if (herr != error::none || !cli)
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
                     std::size_t total = 0;
                     while (total < payload.size())
                     {
                         const auto n = co_await cli->async_read_some(
                             std::span<std::byte>(echo.data() + total, echo.size() - total), rec);
                         if (rec || n == 0)
                         {
                             break;
                         }
                         total += n;
                     }
                     ok = (total == payload.size());
                     cli->close();
                 });
        return ok;
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
            auto [a, b] = make_memory_pair(ioc.get_executor());
            net::co_spawn(
                ioc.get_executor(),
                [b = std::move(b)]() mutable -> net::awaitable<void>
                {
                    auto [err, msg, conn] =
                        co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                                   hysteria2::server_config{kPassword});
                    if (err == error::none && conn)
                    {
                        std::array<std::byte, 128> buf{};
                        std::error_code ec;
                        const auto n = co_await conn->async_read_some(buf, ec);
                        if (!ec && n > 0)
                        {
                            co_await conn->async_write_some(
                                std::span<const std::byte>(buf.data(), n), ec);
                        }
                        conn->close();
                    }
                },
                net::detached);
            net::co_spawn(
                ioc.get_executor(),
                [&, a = std::move(a), payload]() mutable -> net::awaitable<void>
                {
                    auto stream = std::make_shared<memory_stream>(std::move(a));
                    auto [herr, cli] = co_await hysteria2::connect(
                        stream, hysteria2::client_config{kPassword},
                        make_domain_addr("example.com", 443));
                    if (herr != error::none || !cli)
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
                    cli->close();
                },
                net::detached);
        }
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     while (success.load() < 16)
                     {
                         co_await net::post(ioc.get_executor(), net::use_awaitable);
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

        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::atomic<std::size_t> received{0};
        net::co_spawn(
            ioc.get_executor(),
            [b = std::move(b), &received]() mutable -> net::awaitable<void>
            {
                auto [err, msg, conn] =
                    co_await hysteria2::accept(std::make_shared<memory_stream>(std::move(b)),
                                               hysteria2::server_config{kPassword});
                if (err != error::none || !conn)
                {
                    co_return;
                }
                std::array<std::byte, kChunk> buf{};
                std::error_code ec;
                std::size_t total = 0;
                while (total < kTotal)
                {
                    const auto n = co_await conn->async_read_some(buf, ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    total += n;
                }
                received.store(total);
                conn->close();
            },
            net::detached);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto stream = std::make_shared<memory_stream>(std::move(a));
                     auto [herr, cli] = co_await hysteria2::connect(
                         stream, hysteria2::client_config{kPassword},
                         make_domain_addr("example.com", 443));
                     if (herr != error::none || !cli)
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
                     cli->close();
                 });
        EXPECT_EQ(received.load(), kTotal);
    }

} // namespace
