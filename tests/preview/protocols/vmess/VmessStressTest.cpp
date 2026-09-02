/**
 * @file VmessStressTest.cpp
 * @brief VMess 协议会话压力测试（达标标准 C2）
 * @details 生产级压力验证：
 * 1. 200 次连接循环（每次新 ioc + 内存对，AEAD 握手 + 回显，计数验证）
 * 2. 16 并发连接握手（全 co_spawn 到同一 ioc，客户端逻辑内联）
 * 3. 2MB 数据传输（64KB 分块，Conn 内部 16KB AEAD chunk 分片，服务端累积计数校验）
 * @note 使用 Vmess::Accept/Connect 工厂（AEAD 认证头握手在工厂内部完成），
 *       VMess 数据面为 chunk 加解密，分块读写由 Conn 内部完成。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>
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

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x20 + i);
        }
        return uuid;
    }

    /// 构造 vmess 目标地址
    auto make_addr(Vmess::AddressType Type, std::string host, std::uint16_t port)
        -> Vmess::Address
    {
        Vmess::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    /// 服务端：Accept（AEAD 握手）+ 回显
    auto server_echo(net::io_context &ioc, MemoryStream b) -> void
    {
        net::co_spawn(ioc.get_executor(),
                      [b = std::move(b)]() mutable -> net::awaitable<void>
                      {
                          Vmess::ServerConfig cfg;
                          cfg.uuid = test_uuid();
                          auto [err, req, Conn] =
                              co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
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

    /// 客户端：工厂 Connect（AEAD 握手）+ 回显往返
    auto client_roundtrip(net::io_context &ioc, MemoryStream a, const std::string &payload) -> bool
    {
        bool Ok = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     Vmess::ClientConfig cfg;
                     cfg.uuid = test_uuid();
                     auto [herr, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     if (herr != Error::None || !cli)
                     {
                         co_return;
                     }
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     std::array<std::byte, 4096> echo{};
                     std::size_t got = 0;
                     while (got < payload.size())
                     {
                         const auto n = co_await cli->async_read_some(
                             std::span<std::byte>(echo.data() + got, echo.size() - got), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         got += n;
                     }
                     Ok = (got == payload.size());
                     cli->Close();
                 });
        return Ok;
    }

    // ── 1. 200 次连接循环泄漏检测 ──

    TEST(VmessStress, ConnectLoopNoLeak)
    {
        constexpr int kRounds = 200;
        const std::string payload = "stress-payload";
        int ok_count = 0;
        for (int i = 0; i < kRounds; ++i)
        {
            net::io_context ioc;
            auto [a, b] = MakeMemoryPair(ioc.get_executor());
            server_echo(ioc, std::move(b));
            if (client_roundtrip(ioc, std::move(a), payload))
            {
                ++ok_count;
            }
        }
        EXPECT_EQ(ok_count, kRounds);
    }

    // ── 2. 16 并发连接 ──

    TEST(VmessStress, Concurrent16)
    {
        net::io_context ioc;
        std::atomic<int> success{0};
        const std::string payload = "concurrent-payload";
        for (int i = 0; i < 16; ++i)
        {
            auto [a, b] = MakeMemoryPair(ioc.get_executor());
            net::co_spawn(
                ioc.get_executor(),
                [b = std::move(b)]() mutable -> net::awaitable<void>
                {
                    Vmess::ServerConfig cfg;
                    cfg.uuid = test_uuid();
                    auto [err, req, Conn] =
                        co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
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
                    Vmess::ClientConfig cfg;
                    cfg.uuid = test_uuid();
                    auto [herr, cli] = co_await Vmess::Connect(
                        std::make_shared<MemoryStream>(std::move(a)), cfg,
                        make_addr(Vmess::AddressType::Domain, "example.com", 443));
                    if (herr == Error::None && cli)
                    {
                        std::error_code ec;
                        co_await cli->async_write_some(
                            std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                       payload.size()),
                            ec);
                        std::array<std::byte, 128> echo{};
                        std::size_t got = 0;
                        while (got < payload.size())
                        {
                            const auto n = co_await cli->async_read_some(
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
                        cli->Close();
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
                     while (success.load() < 16 && std::chrono::steady_clock::now() < deadline)
                     {
                         t.expires_after(std::chrono::milliseconds(1));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(success.load(), 16);
    }

    // ── 3. 2MB 数据传输 ──

    TEST(VmessStress, Transfer2MB)
    {
        net::io_context ioc;
        constexpr std::size_t kTotal = 2 * 1024 * 1024;
        constexpr std::size_t kChunk = 64 * 1024;

        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        // 服务端：接受 + 统计接收字节
        std::atomic<std::size_t> received{0};
        net::co_spawn(
            ioc.get_executor(),
            [b = std::move(b), &received]() mutable -> net::awaitable<void>
            {
                Vmess::ServerConfig cfg;
                cfg.uuid = test_uuid();
                auto [err, req, Conn] =
                    co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
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

        // 客户端：工厂 Connect（AEAD 握手）+ 发送 2MB
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     Vmess::ClientConfig cfg;
                     cfg.uuid = test_uuid();
                     auto [herr, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
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
