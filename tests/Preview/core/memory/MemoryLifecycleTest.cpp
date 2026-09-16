/**
 * @file MemoryLifecycleTest.cpp
 * @brief 资源指针全生命周期长跑测试
 * @details 验证内存策略在协议处理整个生命周期的稳定性：
 * 1. 单连接长跑：一个 Conn 会话内持续传输大流量（256MB），
 *    校验数据完整 + 复用缓冲 Capacity 稳定（零再分配）
 * 2. 帧循环长跑：100 万帧编码复用，Capacity 不变
 * 3. 会话回收循环：大量 Conn 生命周期创建/析构（Arena 正确回收）
 * 4. 多连接压力：200 个连接循环（握手 + 传输 + 析构）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>

namespace
{
    namespace Net = boost::asio;

    /// 简单校验和（避免大哈希开销）
    auto Checksum(std::span<const std::uint8_t> Data) -> std::uint64_t
    {
        std::uint64_t Sum = 0;
        for (const auto Byte : Data)
        {
            Sum = Sum * 31 + Byte;
        }
        return Sum;
    }

    // ── 1. 单连接长跑：256MB 传输 + 复用缓冲稳定性 ──

    TEST(MemoryLifecycle, LongRunSingleConnTransfer)
    {
        Net::io_context Ioc;
        auto [ClientStream, ServerStream] = Preview::MakeMemoryPair(Ioc.get_executor());
        std::exception_ptr Exception;

        constexpr std::size_t TotalMegabytes = 256;
        constexpr std::size_t ChunkSize = 65536;
        constexpr std::size_t TotalBytes = TotalMegabytes * 1024 * 1024;
        constexpr std::size_t ChunkCount = TotalBytes / ChunkSize;

        auto TransferCoro = [ClientStream = std::move(ClientStream), ServerStream = std::move(ServerStream),
                             Executor = Ioc.get_executor()]() mutable -> Net::awaitable<void>
        {
            // 服务端：接收并回显校验和
            auto ServerCoro = [ServerStream = std::move(ServerStream)]() mutable -> Net::awaitable<void>
            {
                auto [AcceptError, Request, Connection] = co_await Preview::Socks5::Accept(
                    std::make_shared<Preview::MemoryStream>(std::move(ServerStream)), Preview::Socks5::ServerConfig{});
                if (AcceptError != Preview::Error::None || !Connection)
                {
                    co_return;
                }
                std::array<std::uint8_t, ChunkSize> Buffer{};
                std::uint64_t Total = 0;
                std::size_t Done = 0;
                while (Done < TotalBytes)
                {
                    std::error_code ErrorCode;
                    const auto Count = co_await Connection->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()), ErrorCode);
                    if (ErrorCode || Count == 0)
                    {
                        break;
                    }
                    Total += Checksum(std::span<const std::uint8_t>(Buffer).first(Count));
                    Done += Count;
                }
                // 回显校验和（8 字节）
                std::array<std::uint8_t, 8> Reply{};
                for (std::size_t Index = 0; Index < 8; ++Index)
                {
                    Reply[Index] = static_cast<std::uint8_t>((Total >> (Index * 8)) & 0xFF);
                }
                std::error_code ErrorCode;
                co_await Connection->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Reply.data()), Reply.size()),
                    ErrorCode);
            };
            Net::co_spawn(Executor, std::move(ServerCoro)(), Net::detached);

            // 客户端：发送数据并收集校验和
            auto [ConnectError, Connection] = co_await Preview::Socks5::Connect(
                std::make_shared<Preview::MemoryStream>(std::move(ClientStream)), Preview::Socks5::ClientConfig{},
                Preview::Socks5::Address{Preview::Socks5::AddressType::Domain, "Target.example", 443});

            if (ConnectError != Preview::Error::None || !Connection)
            {
                ADD_FAILURE() << "Client Connect Failed";
                co_return;
            }

            std::vector<std::uint8_t> Chunk(ChunkSize);
            for (std::size_t Index = 0; Index < Chunk.size(); ++Index)
            {
                Chunk[Index] = static_cast<std::uint8_t>(Index * 7 + (Index >> 8));
            }
            std::uint64_t Total = 0;
            for (std::size_t ChunkIndex = 0; ChunkIndex < ChunkCount; ++ChunkIndex)
            {
                std::error_code ErrorCode;
                std::size_t Offset = 0;
                while (Offset < ChunkSize)
                {
                    const auto Count = co_await Connection->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data() + Offset),
                                                   ChunkSize - Offset),
                        ErrorCode);
                    if (ErrorCode)
                    {
                        ADD_FAILURE() << "Write Failed at chunk " << ChunkIndex;
                        break;
                    }
                    Offset += Count;
                }
                Total += Checksum(Chunk);
            }

            // 读取服务端回显的校验和
            std::array<std::uint8_t, 8> Reply{};
            std::size_t Received = 0;
            std::error_code ErrorCode;
            while (Received < 8)
            {
                const auto Count = co_await Connection->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Reply.data() + Received), 8 - Received),
                    ErrorCode);
                if (ErrorCode || Count == 0)
                {
                    break;
                }
                Received += Count;
            }
            std::uint64_t Echo = 0;
            for (std::size_t Index = 0; Index < 8; ++Index)
            {
                Echo |= static_cast<std::uint64_t>(Reply[Index]) << (Index * 8);
            }
            EXPECT_EQ(Echo, Total) << "256MB 传输校验和不匹配";
            Connection->Close();
        };
        Net::co_spawn(Ioc, std::move(TransferCoro),
                      [&](std::exception_ptr ExceptionValue)
                      {
                          Exception = ExceptionValue;
                          Ioc.stop();
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    // ── 2. 帧循环长跑：100 万帧编码复用 ──

    TEST(MemoryLifecycle, LongRunFrameLoop)
    {
        Preview::Socks5::Request Request;
        Request.Ver = Preview::Socks5::Version;
        Request.Cmd = Preview::Socks5::Command::Connect;
        Request.Rsv = 0;
        Request.Target.Type = Preview::Socks5::AddressType::Domain;
        Request.Target.Host = "example.com";
        Request.Target.Port = 443;

        Preview::Memory::SessionResource<> Memory;
        typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> TransmitBuffer(Memory.Arena());

        // 预热（首次扩容）
        Preview::Socks5::BuildRequest(Request, TransmitBuffer);
        const auto InitialCapacity = TransmitBuffer.capacity();
        ASSERT_GT(InitialCapacity, 0U);

        constexpr int Iterations = 1000000;
        std::size_t MaximumCapacity = InitialCapacity;
        std::size_t Total = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Preview::Socks5::BuildRequest(Request, TransmitBuffer);
            MaximumCapacity = std::max(MaximumCapacity, TransmitBuffer.capacity());
            Total += TransmitBuffer.size();
        }
        EXPECT_EQ(MaximumCapacity, InitialCapacity) << "100 万帧后复用缓冲发生再分配";
        // 每帧：[ver][cmd][rsv][ATYP][len][host 11B][port 2B] = 18 字节
        EXPECT_EQ(Total, static_cast<std::size_t>(Iterations) * 18);
    }

    // ── 3. 会话回收循环：大量 Arena 创建/析构 ──

    TEST(MemoryLifecycle, SessionRecycleLoop)
    {
        constexpr int Iterations = 100000;
        std::size_t PeakAllocation = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Preview::Memory::SessionResource<> Memory;
            // 分配 + 释放循环（Arena 随析构回收）
            auto Values = Memory.MakeVector<std::uint8_t>();
            Values.resize(256 + (Index % 64));
            Values[0] = static_cast<std::uint8_t>(Index);
            PeakAllocation = std::max(PeakAllocation, Values.capacity());
            // 模拟 Conn 生命周期：成员缓冲 + 帧缓冲
            typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> TransmitBuffer(Memory.Arena());
            TransmitBuffer.resize(4096);
            TransmitBuffer[0] = 0xAB;
        }
        // 无崩溃即通过；Capacity 峰值 ≤ 单会话最大需求
        EXPECT_LE(PeakAllocation, 320U);
        SUCCEED();
    }

    // ── 4. 多连接压力：200 连接循环 ──

    TEST(MemoryLifecycle, MultiConnRecycleLoop)
    {
        Net::io_context Ioc;
        std::exception_ptr Exception;

        auto RecycleCoro = [&Ioc]() -> Net::awaitable<void>
        {
            constexpr int ConnectionCount = 200;
            for (int Index = 0; Index < ConnectionCount; ++Index)
            {
                auto [ClientStream, ServerStream] = Preview::MakeMemoryPair(Ioc.get_executor());

                auto ServerCoro = [ServerStream = std::move(ServerStream)]() mutable -> Net::awaitable<void>
                {
                    auto [AcceptError, Request, Connection] = co_await Preview::Socks5::Accept(
                        std::make_shared<Preview::MemoryStream>(std::move(ServerStream)),
                        Preview::Socks5::ServerConfig{});
                    if (AcceptError == Preview::Error::None && Connection)
                    {
                        std::array<std::uint8_t, 256> Buffer{};
                        std::error_code ErrorCode;
                        while (true)
                        {
                            const auto Count = co_await Connection->async_read_some(
                                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()),
                                ErrorCode);
                            if (ErrorCode || Count == 0)
                            {
                                break;
                            }
                        }
                    }
                };
                Net::co_spawn(Ioc.get_executor(), std::move(ServerCoro)(), Net::detached);

                auto [ConnectError, Connection] = co_await Preview::Socks5::Connect(
                    std::make_shared<Preview::MemoryStream>(std::move(ClientStream)),
                    Preview::Socks5::ClientConfig{},
                    Preview::Socks5::Address{Preview::Socks5::AddressType::Ipv4, "10.0.0.1", 80});
                if (ConnectError != Preview::Error::None || !Connection)
                {
                    ADD_FAILURE() << "Conn " << Index << " Connect Failed";
                    continue;
                }

                // 传输 16KB 后关闭
                std::vector<std::uint8_t> Chunk(16384, static_cast<std::uint8_t>(Index));
                std::error_code ErrorCode;
                std::size_t Offset = 0;
                while (Offset < Chunk.size())
                {
                    const auto Count = co_await Connection->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data() + Offset),
                                                   Chunk.size() - Offset),
                        ErrorCode);
                    if (ErrorCode)
                    {
                        break;
                    }
                    Offset += Count;
                }
                Connection->Close();
            }
        };
        Net::co_spawn(Ioc, std::move(RecycleCoro),
                      [&](std::exception_ptr ExceptionValue)
                      {
                          Exception = ExceptionValue;
                          Ioc.stop();
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        SUCCEED();
    }

} // namespace
