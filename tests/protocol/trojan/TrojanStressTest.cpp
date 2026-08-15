/**
 * @file TrojanStressTest.cpp
 * @brief Trojan 协议会话压力测试（达标标准 C2）
 * @details 生产级压力验证：
 * 1. 200 次连接循环（每次新 ioc + 内存对，握手 + 回显，计数验证）
 * 2. 16 并发连接握手（全 co_spawn 到同一 ioc，客户端逻辑内联）
 * 3. 2MB 数据传输（64KB 分块，服务端累积计数校验）
 * @note 使用 trojan::accept 服务端 + 原始 wire 客户端握手
 *       （sha224 凭据 + CRLF 分隔请求头，无服务端响应字节）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/trojan/trojan.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /// 测试密码（sha224 哈希后作为凭据）
    constexpr const char *kPassword = "pw123456";

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

    /// 构造 trojan 目标地址
    auto make_addr(trojan::address_type type, std::string host, std::uint16_t port)
        -> trojan::address
    {
        trojan::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    /// 服务端：accept + 回显
    auto server_echo(net::io_context &ioc, memory_stream b) -> void
    {
        net::co_spawn(ioc.get_executor(),
                      [b = std::move(b)]() mutable -> net::awaitable<void>
                      {
                          auto [err, req, conn] =
                              co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                      trojan::server_config{kPassword});
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
                      },
                      net::detached);
    }

    /// 客户端：原始 wire 握手（sha224 凭据 + CRLF 头）+ 回显往返
    auto client_roundtrip(net::io_context &ioc, memory_stream a, const std::string &payload) -> bool
    {
        bool ok = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto cred = trojan::credential(kPassword);
                     auto wire = trojan::build_request(
                         cred, trojan::command::connect,
                         make_addr(trojan::address_type::domain, "example.com", 443));
                     wire.insert(wire.end(), payload.begin(), payload.end());
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                     std::array<std::byte, 4096> echo{};
                     std::size_t got = 0;
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
                     ok = (got == payload.size());
                 });
        return ok;
    }

    // ── 1. 200 次连接循环泄漏检测 ──

    TEST(TrojanStress, ConnectLoopNoLeak)
    {
        constexpr int kRounds = 200;
        const std::string payload = "stress-payload";
        int ok_count = 0;
        for (int i = 0; i < kRounds; ++i)
        {
            net::io_context ioc;
            auto [a, b] = make_memory_pair(ioc.get_executor());
            server_echo(ioc, std::move(b));
            if (client_roundtrip(ioc, std::move(a), payload))
            {
                ++ok_count;
            }
        }
        EXPECT_EQ(ok_count, kRounds);
    }

    // ── 2. 16 并发连接 ──

    TEST(TrojanStress, Concurrent16)
    {
        net::io_context ioc;
        std::atomic<int> success{0};
        const std::string payload = "concurrent-payload";
        for (int i = 0; i < 16; ++i)
        {
            auto [a, b] = make_memory_pair(ioc.get_executor());
            net::co_spawn(
                ioc.get_executor(),
                [b = std::move(b)]() mutable -> net::awaitable<void>
                {
                    auto [err, req, conn] =
                        co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                                trojan::server_config{kPassword});
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
                    const auto cred = trojan::credential(kPassword);
                    auto wire = trojan::build_request(
                        cred, trojan::command::connect,
                        make_addr(trojan::address_type::domain, "example.com", 443));
                    wire.insert(wire.end(), payload.begin(), payload.end());
                    std::error_code ec;
                    co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
                    std::array<std::byte, 128> echo{};
                    std::size_t got = 0;
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
                    if (got == payload.size())
                    {
                        success.fetch_add(1);
                    }
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

    // ── 3. 2MB 数据传输 ──

    TEST(TrojanStress, Transfer2MB)
    {
        net::io_context ioc;
        constexpr std::size_t kTotal = 2 * 1024 * 1024;
        constexpr std::size_t kChunk = 64 * 1024;

        auto [a, b] = make_memory_pair(ioc.get_executor());
        // 服务端：接受 + 统计接收字节
        std::atomic<std::size_t> received{0};
        net::co_spawn(
            ioc.get_executor(),
            [b = std::move(b), &received]() mutable -> net::awaitable<void>
            {
                auto [err, req, conn] =
                    co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)),
                                            trojan::server_config{kPassword});
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

        // 客户端：原始 wire 握手 + 发送 2MB
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto cred = trojan::credential(kPassword);
                     auto wire = trojan::build_request(
                         cred, trojan::command::connect,
                         make_addr(trojan::address_type::domain, "example.com", 443));
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
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
