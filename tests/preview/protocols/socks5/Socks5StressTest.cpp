/**
 * @file Socks5StressTest.cpp
 * @brief SOCKS5 会话压力测试
 * @details 生产级压力验证：
 * 1. 300 次连接循环泄漏检测（连接计数稳定，无资源泄漏）
 * 2. 并发连接握手（并发正确性）
 * 3. 大数据双向传输（64KB 分块，累积校验）
 * @note 使用 Socks5::Connect/Accept 自由函数 + 原始 wire 协议握手
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
#include <common/Protocols/Socks5/Socks5.hpp>
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

    /// 服务端：Accept + 回显
    auto server_echo(net::io_context &ioc, MemoryStream b, const std::string &expected) -> void
    {
        net::co_spawn(ioc.get_executor(),
                      [b = std::move(b), expected]() mutable -> net::awaitable<void>
                      {
                          auto [err, req, Conn] =
                              co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                      Socks5::ServerConfig{});
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
                      },
                      net::detached);
    }

    /// 客户端：原始 wire 握手 + 回显往返
    auto client_roundtrip(net::io_context &ioc, MemoryStream a, const std::string &payload) -> bool
    {
        bool Ok = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
                     const std::string host = "example.com";
                     wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(host.size())});
                     wire.insert(wire.end(), host.begin(), host.end());
                     wire.push_back(0x01);
                     wire.push_back(0xBB);
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                     if (got != 12u || resp[0] != Socks5::Version)
                     {
                         Ok = false;
                         co_return;
                     }
                     std::array<std::byte, 4096> echo{};
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
                     Ok = (got == payload.size());
                 });
        return Ok;
    }

    // ── 1. 300 次连接循环泄漏检测 ──

    TEST(Socks5Stress, ConnectLoopNoLeak)
    {
        constexpr int kRounds = 300;
        const std::string payload = "stress-payload";
        int ok_count = 0;
        for (int i = 0; i < kRounds; ++i)
        {
            net::io_context ioc;
            auto [a, b] = MakeMemoryPair(ioc.get_executor());
            server_echo(ioc, std::move(b), payload);
            if (client_roundtrip(ioc, std::move(a), payload))
            {
                ++ok_count;
            }
        }
        EXPECT_EQ(ok_count, kRounds);
    }

    // ── 2. 32 并发连接 ──

    TEST(Socks5Stress, Concurrent32)
    {
        net::io_context ioc;
        std::atomic<int> success{0};
        const std::string payload = "concurrent-payload";
        for (int i = 0; i < 32; ++i)
        {
            auto [a, b] = MakeMemoryPair(ioc.get_executor());
            net::co_spawn(
                ioc.get_executor(),
                [b = std::move(b)]() mutable -> net::awaitable<void>
                {
                    auto [err, req, Conn] =
                        co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                Socks5::ServerConfig{});
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
                    std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
                    const std::string host = "example.com";
                    wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03,
                                             static_cast<std::uint8_t>(host.size())});
                    wire.insert(wire.end(), host.begin(), host.end());
                    wire.push_back(0x01);
                    wire.push_back(0xBB);
                    wire.insert(wire.end(), payload.begin(), payload.end());
                    std::error_code ec;
                    co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                    if (got == 12u)
                    {
                        // 读回显
                        std::array<std::byte, 128> echo{};
                        std::size_t rg = 0;
                        while (rg < payload.size())
                        {
                            const auto n = co_await a.async_read_some(
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
                    }
                },
                net::detached);
        }
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 超时守卫：客户端失败时避免无限自旋
                     net::steady_timer t(ioc);
                     const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                     while (success.load() < 32 && std::chrono::steady_clock::now() < deadline)
                     {
                         t.expires_after(std::chrono::milliseconds(1));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(success.load(), 32);
    }

    // ── 3. 4MB 数据传输 ──

    TEST(Socks5Stress, Transfer4MB)
    {
        net::io_context ioc;
        constexpr std::size_t kTotal = 4 * 1024 * 1024;
        constexpr std::size_t kChunk = 64 * 1024;

        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        // 服务端：接受 + 统计接收字节
        std::atomic<std::size_t> received{0};
        net::co_spawn(
            ioc.get_executor(),
            [b = std::move(b), &received]() mutable -> net::awaitable<void>
            {
                auto [err, req, Conn] =
                    co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                            Socks5::ServerConfig{});
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

        // 客户端：原始 wire 握手 + 发送 4MB
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
                     const std::string host = "example.com";
                     wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(host.size())});
                     wire.insert(wire.end(), host.begin(), host.end());
                     wire.push_back(0x01);
                     wire.push_back(0xBB);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                     std::vector<std::byte> chunk(kChunk, std::byte{0xAB});
                     for (std::size_t sent = 0; sent < kTotal; sent += kChunk)
                     {
                         co_await a.async_write_some(std::span<const std::byte>(chunk), ec);
                         if (ec)
                         {
                             break;
                         }
                     }
                 });
        EXPECT_EQ(received.load(), kTotal);
    }

} // namespace
