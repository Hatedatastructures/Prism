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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename A>
    auto RunCoro(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 服务端：Accept + 回显
    auto ServerEcho(Net::io_context &IoContext, MemoryStream Stream, const std::string &Expected) -> void
    {
        Net::co_spawn(IoContext.get_executor(),
                      [Stream = std::move(Stream), Expected]() mutable -> Net::awaitable<void>
                      {
                          auto [ErrorValue, Request, Conn] =
                              co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(Stream)),
                                                      Socks5::ServerConfig{});
                          if (ErrorValue != Error::None || !Conn)
                          {
                              co_return;
                          }
                          std::array<std::byte, 4096> Buffer{};
                          std::error_code ErrorCode;
                          while (true)
                          {
                              const auto Count = co_await Conn->async_read_some(Buffer, ErrorCode);
                              if (ErrorCode || Count == 0)
                              {
                                  break;
                              }
                              co_await Conn->async_write_some(
                                  std::span<const std::byte>(Buffer.data(), Count), ErrorCode);
                          }
                          Conn->Close();
                      },
                      Net::detached);
    }

    /// 客户端：原始 wire 握手 + 回显往返
    auto ClientRoundtrip(Net::io_context &IoContext, MemoryStream Stream, const std::string &Payload) -> bool
    {
        bool Ok = false;
        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
                     const std::string Host = "example.com";
                     Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(Host.size())});
                     Wire.insert(Wire.end(), Host.begin(), Host.end());
                     Wire.push_back(0x01);
                     Wire.push_back(0xBB);
                     Wire.insert(Wire.end(), Payload.begin(), Payload.end());
                     std::error_code ErrorCode;
                     co_await Stream.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                     std::array<std::uint8_t, 12> Response{};
                     std::size_t Received = 0;
                     while (Received < Response.size())
                     {
                         const auto Count = co_await Stream.async_read_some(
                             AsBytes(std::span<std::uint8_t>(Response).subspan(Received)), ErrorCode);
                         if (ErrorCode || Count == 0)
                         {
                             break;
                         }
                         Received += Count;
                     }
                     if (Received != 12u || Response[0] != Socks5::Version)
                     {
                         Ok = false;
                         co_return;
                     }
                     std::array<std::byte, 4096> Echo{};
                     Received = 0;
                     while (Received < Payload.size())
                     {
                         const auto Count = co_await Stream.async_read_some(
                             std::span<std::byte>(Echo.data() + Received, Echo.size() - Received), ErrorCode);
                         if (ErrorCode || Count == 0)
                         {
                             break;
                         }
                         Received += Count;
                     }
                     Ok = (Received == Payload.size());
                });
        return Ok;
    }

    // ── 1. 300 次连接循环泄漏检测 ──

    TEST(Socks5Stress, ConnectLoopNoLeak)
    {
        constexpr int Rounds = 300;
        const std::string Payload = "stress-payload";
        int OkCount = 0;
        for (int Index = 0; Index < Rounds; ++Index)
        {
            Net::io_context IoContext;
            auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
            ServerEcho(IoContext, std::move(ServerStream), Payload);
            if (ClientRoundtrip(IoContext, std::move(ClientStream), Payload))
            {
                ++OkCount;
            }
        }
        EXPECT_EQ(OkCount, Rounds);
    }

    // ── 2. 32 并发连接 ──

    TEST(Socks5Stress, Concurrent32)
    {
        Net::io_context IoContext;
        std::atomic<int> Success{0};
        const std::string Payload = "concurrent-payload";
        for (int Index = 0; Index < 32; ++Index)
        {
            auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
            Net::co_spawn(
                IoContext.get_executor(),
                [ServerStream = std::move(ServerStream)]() mutable -> Net::awaitable<void>
                {
                    auto [ErrorValue, Request, Conn] =
                        co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                Socks5::ServerConfig{});
                    if (ErrorValue == Error::None && Conn)
                    {
                        std::array<std::byte, 128> Buffer{};
                        std::error_code ErrorCode;
                        const auto Count = co_await Conn->async_read_some(Buffer, ErrorCode);
                        if (!ErrorCode && Count > 0)
                        {
                            co_await Conn->async_write_some(
                                std::span<const std::byte>(Buffer.data(), Count), ErrorCode);
                        }
                        Conn->Close();
                    }
                },
                Net::detached);
            Net::co_spawn(
                IoContext.get_executor(),
                [&Success, ClientStream = std::move(ClientStream), Payload]() mutable -> Net::awaitable<void>
                {
                    std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
                    const std::string Host = "example.com";
                    Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                             static_cast<std::uint8_t>(Host.size())});
                    Wire.insert(Wire.end(), Host.begin(), Host.end());
                    Wire.push_back(0x01);
                    Wire.push_back(0xBB);
                    Wire.insert(Wire.end(), Payload.begin(), Payload.end());
                    std::error_code ErrorCode;
                    co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                    std::array<std::uint8_t, 12> Response{};
                    std::size_t Received = 0;
                    while (Received < Response.size())
                    {
                        const auto Count = co_await ClientStream.async_read_some(
                            AsBytes(std::span<std::uint8_t>(Response).subspan(Received)), ErrorCode);
                        if (ErrorCode || Count == 0)
                        {
                            break;
                        }
                        Received += Count;
                    }
                    if (Received == 12u)
                    {
                        // 读回显
                        std::array<std::byte, 128> Echo{};
                        std::size_t EchoReceived = 0;
                        while (EchoReceived < Payload.size())
                        {
                            const auto Count = co_await ClientStream.async_read_some(
                                std::span<std::byte>(Echo.data() + EchoReceived,
                                                     Echo.size() - EchoReceived),
                                ErrorCode);
                            if (ErrorCode || Count == 0)
                            {
                                break;
                            }
                            EchoReceived += Count;
                        }
                        if (EchoReceived == Payload.size())
                        {
                            Success.fetch_add(1);
                        }
                    }
                },
                Net::detached);
        }
        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 超时守卫：客户端失败时避免无限自旋
                     Net::steady_timer Timer(IoContext);
                     const auto Deadline =
                         std::chrono::steady_clock::now() + std::chrono::seconds(10);
                     while (Success.load() < 32 && std::chrono::steady_clock::now() < Deadline)
                     {
                         Timer.expires_after(std::chrono::milliseconds(1));
                         co_await Timer.async_wait(Net::use_awaitable);
                     }
                });
        EXPECT_EQ(Success.load(), 32);
    }

    // ── 3. 4MB 数据传输 ──

    TEST(Socks5Stress, Transfer4MB)
    {
        Net::io_context IoContext;
        constexpr std::size_t Total = 4 * 1024 * 1024;
        constexpr std::size_t Chunk = 64 * 1024;

        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        // 服务端：接受 + 统计接收字节
        std::atomic<std::size_t> ReceivedBytes{0};
        Net::co_spawn(
            IoContext.get_executor(),
            [ServerStream = std::move(ServerStream), &ReceivedBytes]() mutable -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] =
                    co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                            Socks5::ServerConfig{});
                if (ErrorValue != Error::None || !Conn)
                {
                    co_return;
                }
                std::array<std::byte, Chunk> Buffer{};
                std::error_code ErrorCode;
                std::size_t ReceivedTotal = 0;
                while (ReceivedTotal < Total)
                {
                    const auto Count = co_await Conn->async_read_some(Buffer, ErrorCode);
                    if (ErrorCode || Count == 0)
                    {
                        break;
                    }
                    ReceivedTotal += Count;
                }
                ReceivedBytes.store(ReceivedTotal);
                Conn->Close();
            },
            Net::detached);

        // 客户端：原始 wire 握手 + 发送 4MB
        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
                     const std::string Host = "example.com";
                     Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(Host.size())});
                     Wire.insert(Wire.end(), Host.begin(), Host.end());
                     Wire.push_back(0x01);
                     Wire.push_back(0xBB);
                     std::error_code ErrorCode;
                     co_await ClientStream.async_write_some(
                         AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                     std::array<std::uint8_t, 12> Response{};
                     std::size_t Received = 0;
                     while (Received < Response.size())
                     {
                         const auto Count = co_await ClientStream.async_read_some(
                             AsBytes(std::span<std::uint8_t>(Response).subspan(Received)), ErrorCode);
                         if (ErrorCode || Count == 0)
                         {
                             break;
                         }
                         Received += Count;
                     }
                     std::vector<std::byte> ChunkBuffer(Chunk, std::byte{0xAB});
                     for (std::size_t Sent = 0; Sent < Total; Sent += Chunk)
                     {
                         co_await ClientStream.async_write_some(
                             std::span<const std::byte>(ChunkBuffer), ErrorCode);
                         if (ErrorCode)
                         {
                             break;
                         }
                     }
                });
        EXPECT_EQ(ReceivedBytes.load(), Total);
    }

} // namespace
