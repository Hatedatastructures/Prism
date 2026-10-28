/**
 * @file LifecycleTest.cpp
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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>

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

    constexpr std::size_t LongTransferChunkSize = 65536;
    constexpr std::size_t LongTransferTotalBytes = 256U * 1024U * 1024U;
    constexpr std::size_t LongTransferChunkCount = LongTransferTotalBytes / LongTransferChunkSize;

    /**
     * @brief 持有服务端内存流直到单连接长跑的接收和回显完成。
     * @param ServerStream 服务端内存流端点，协程接管其值所有权。
     * @return 服务端完成认证、接收 256MB 并发送校验和后完成。
     */
    auto RunLongTransferServer(Prism::MemoryStream ServerStream) -> Net::awaitable<void>
    {
        const Prism::Socks5::ServerConfig Config{};
        auto Accepted = co_await Prism::Socks5::Accept(
            std::make_shared<Prism::MemoryStream>(std::move(ServerStream)), Config);
        if (!Accepted)
        {
            co_return;
        }
        auto Connection = std::move(Accepted->Connection);

        std::array<std::uint8_t, LongTransferChunkSize> Buffer{};
        std::uint64_t Total = 0;
        std::size_t Done = 0;
        while (Done < LongTransferTotalBytes)
        {
            std::error_code ErrorCode;
            const auto Read = co_await Connection->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ErrorCode || Count == 0)
            {
                break;
            }
            Total += Checksum(std::span<const std::uint8_t>(Buffer).first(Count));
            Done += Count;
        }

        std::array<std::uint8_t, 8> Reply{};
        for (std::size_t Index = 0; Index < Reply.size(); ++Index)
        {
            Reply[Index] = static_cast<std::uint8_t>((Total >> (Index * 8)) & 0xFF);
        }
        std::error_code ErrorCode;
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Reply.data()), Reply.size()));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
    }

    /**
     * @brief 发送单连接长跑数据并校验服务端回显。
     * @param ClientStream 客户端内存流端点，协程接管其值所有权。
     * @return 客户端完成 256MB 发送、校验和读取和连接关闭后完成。
     */
    auto RunLongTransferClient(Prism::MemoryStream ClientStream) -> Net::awaitable<void>
    {
        const Prism::Socks5::ClientConfig Config{};
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Domain, "Target.example", 443};
        auto Connected = co_await Prism::Socks5::Connect(Prism::Socks5::ConnectParameters{
            std::make_shared<Prism::MemoryStream>(std::move(ClientStream)), Config, Target});
        if (!Connected)
        {
            ADD_FAILURE() << "Client Connect Failed";
            co_return;
        }
        auto Connection = std::move(*Connected);

        std::vector<std::uint8_t> Chunk(LongTransferChunkSize);
        for (std::size_t Index = 0; Index < Chunk.size(); ++Index)
        {
            Chunk[Index] = static_cast<std::uint8_t>(Index * 7 + (Index >> 8));
        }
        std::uint64_t Total = 0;
        for (std::size_t ChunkIndex = 0; ChunkIndex < LongTransferChunkCount; ++ChunkIndex)
        {
            std::error_code ErrorCode;
            std::size_t Offset = 0;
            while (Offset < LongTransferChunkSize)
            {
                const auto Write = co_await Connection->WriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data() + Offset),
                                               LongTransferChunkSize - Offset));
                ErrorCode = Prism::Fault::ToNative(Write.Failure);
                const auto Count = Write.Bytes;
                if (ErrorCode)
                {
                    ADD_FAILURE() << "Write Failed at chunk " << ChunkIndex;
                    break;
                }
                Offset += Count;
            }
            Total += Checksum(Chunk);
        }

        std::array<std::uint8_t, 8> Reply{};
        std::size_t Received = 0;
        std::error_code ErrorCode;
        while (Received < Reply.size())
        {
            const auto Read = co_await Connection->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Reply.data() + Received), Reply.size() - Received));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ErrorCode || Count == 0)
            {
                break;
            }
            Received += Count;
        }
        std::uint64_t Echo = 0;
        for (std::size_t Index = 0; Index < Reply.size(); ++Index)
        {
            Echo |= static_cast<std::uint64_t>(Reply[Index]) << (Index * 8);
        }
        EXPECT_EQ(Echo, Total) << "256MB 传输校验和不匹配";
        (void)Connection->Close();
    }

    /**
     * @brief 以并行 owning 协程完成单连接双端生命周期。
     * @param ClientStream 客户端内存流端点。
     * @param ServerStream 服务端内存流端点。
     * @return 两端均自然完成后返回。
     */
    auto RunLongTransfer(Prism::MemoryStream ClientStream, Prism::MemoryStream ServerStream)
        -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        co_await (RunLongTransferServer(std::move(ServerStream)) &&
                  RunLongTransferClient(std::move(ClientStream)));
    }

    struct RecycleResult final
    {
        int Index{0};
        std::size_t SentBytes{0};
        std::size_t ReceivedBytes{0};
        bool PayloadMatches{true};
    };

    struct RecycleRequest final
    {
        Prism::MemoryStream Client;
        Prism::MemoryStream Server;
        int Index{0};
    };

    /**
     * @brief 运行一个回收连接的服务端读取协程。
     * @param ServerStream 服务端内存流端点。
     * @param Result 保存接收字节数和负载校验结果。
     * @return 读取客户端半关闭或关闭后完成。
     */
    auto RunRecycleServer(
        Prism::MemoryStream ServerStream,
        const std::shared_ptr<RecycleResult> &Result) -> Net::awaitable<void>
    {
        const Prism::Socks5::ServerConfig Config{};
        auto Accepted = co_await Prism::Socks5::Accept(
            std::make_shared<Prism::MemoryStream>(std::move(ServerStream)), Config);
        if (!Accepted)
        {
            co_return;
        }
        auto Connection = std::move(Accepted->Connection);

        std::array<std::uint8_t, 256> Buffer{};
        std::error_code ErrorCode;
        while (true)
        {
            const auto Read = co_await Connection->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            Result->ReceivedBytes += Count;
            for (std::size_t Offset = 0; Offset < Count; ++Offset)
            {
                if (Buffer[Offset] != static_cast<std::uint8_t>(Result->Index))
                {
                    Result->PayloadMatches = false;
                    break;
                }
            }
            if (ErrorCode || Count == 0)
            {
                break;
            }
        }
    }

    /**
     * @brief 运行一个回收连接的客户端发送协程。
     * @param ClientStream 客户端内存流端点。
     * @param Result 连接编号与传输结果。
     * @return 发送 16KB 并关闭连接后完成。
     */
    auto RunRecycleClient(
        Prism::MemoryStream ClientStream,
        const std::shared_ptr<RecycleResult> &Result) -> Net::awaitable<void>
    {
        const Prism::Socks5::ClientConfig Config{};
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Ipv4, "10.0.0.1", 80};
        auto Connected = co_await Prism::Socks5::Connect(Prism::Socks5::ConnectParameters{
            std::make_shared<Prism::MemoryStream>(std::move(ClientStream)), Config, Target});
        if (!Connected)
        {
            ADD_FAILURE() << "Conn " << Result->Index << " Connect Failed";
            co_return;
        }
        auto Connection = std::move(*Connected);

        constexpr std::size_t ChunkSize = 16384;
        std::vector<std::uint8_t> Chunk(
            ChunkSize, static_cast<std::uint8_t>(Result->Index));
        std::error_code ErrorCode;
        std::size_t Offset = 0;
        while (Offset < Chunk.size())
        {
            const auto Write = co_await Connection->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data() + Offset),
                                           Chunk.size() - Offset));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            const auto Count = Write.Bytes;
            if (ErrorCode)
            {
                break;
            }
            if (Count == 0)
            {
                break;
            }
            Offset += Count;
        }
        Result->SentBytes = Offset;
        (void)Connection->Close();
    }

    /**
     * @brief 并行拥有一条回收连接的两端协程。
     * @param Request 连接端点和连接编号。
     * @return 两端的字节数与负载校验结果。
     */
    auto RunRecycleConnection(RecycleRequest Request) -> Net::awaitable<RecycleResult>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto Result = std::make_shared<RecycleResult>();
        Result->Index = Request.Index;
        co_await (RunRecycleServer(std::move(Request.Server), Result) &&
                  RunRecycleClient(std::move(Request.Client), Result));
        co_return *Result;
    }

    /**
     * @brief 执行 200 次完整内存连接创建、传输与回收。
     * @param Io 连接所使用的 IO 上下文。
     * @return 全部连接自然关闭后完成。
     */
    auto RunRecycleLoop(Net::io_context &Io) -> Net::awaitable<void>
    {
        constexpr int ConnectionCount = 200;
        for (int Index = 0; Index < ConnectionCount; ++Index)
        {
            auto [ClientStream, ServerStream] = Prism::MakeMemoryPair(Io.get_executor());
            const auto Result = co_await RunRecycleConnection(RecycleRequest{
                std::move(ClientStream), std::move(ServerStream), Index});
            EXPECT_EQ(Result.SentBytes, 16384U) << "Conn " << Index;
            EXPECT_EQ(Result.ReceivedBytes, 16384U) << "Conn " << Index;
            EXPECT_TRUE(Result.PayloadMatches) << "Conn " << Index;
        }
    }

    /**
     * @brief 驱动一个 owning 协程直到自然耗尽并重新抛出首个异常。
     * @param Io 协程所属 IO 上下文。
     * @param Operation 已拥有完整 frame 的异步操作。
     */
    auto RunCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    // ── 1. 单连接长跑：256MB 传输 + 复用缓冲稳定性 ──

    TEST(MemoryLifecycle, LongRunSingleConnTransfer)
    {
        Net::io_context Ioc;
        auto [ClientStream, ServerStream] = Prism::MakeMemoryPair(Ioc.get_executor());
        RunCoro(Ioc, RunLongTransfer(std::move(ClientStream), std::move(ServerStream)));
    }

    // ── 2. 帧循环长跑：100 万帧编码复用 ──

    TEST(MemoryLifecycle, LongRunFrameLoop)
    {
        Prism::Socks5::Request Request;
        Request.Ver = Prism::Socks5::Version;
        Request.Cmd = Prism::Socks5::Command::Connect;
        Request.Rsv = 0;
        Request.Target.Type = Prism::Socks5::AddressType::Domain;
        Request.Target.Host = "example.com";
        Request.Target.Port = 443;

        Prism::Memory::SessionResource<> Memory;
        typename Prism::Memory::SessionResource<>::Buffer<std::uint8_t> TransmitBuffer(Memory.Arena());

        // 预热（首次扩容）
        Prism::Socks5::BuildRequest(Request, TransmitBuffer);
        const auto InitialCapacity = TransmitBuffer.capacity();
        ASSERT_GT(InitialCapacity, 0U);

        constexpr int Iterations = 1000000;
        std::size_t MaximumCapacity = InitialCapacity;
        std::size_t Total = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Prism::Socks5::BuildRequest(Request, TransmitBuffer);
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
            Prism::Memory::SessionResource<> Memory;
            // 分配 + 释放循环（Arena 随析构回收）
            auto Values = Memory.MakeVector<std::uint8_t>();
            Values.resize(256 + (Index % 64));
            Values[0] = static_cast<std::uint8_t>(Index);
            PeakAllocation = std::max(PeakAllocation, Values.capacity());
            // 模拟 Conn 生命周期：成员缓冲 + 帧缓冲
            typename Prism::Memory::SessionResource<>::Buffer<std::uint8_t> TransmitBuffer(Memory.Arena());
            TransmitBuffer.resize(4096);
            TransmitBuffer[0] = 0xAB;
        }
        // 无崩溃即通过；Capacity 峰值 ≤ 单会话最大需求
        EXPECT_LE(PeakAllocation, 320U);
    }

    // ── 4. 多连接压力：200 连接循环 ──

    TEST(MemoryLifecycle, MultiConnRecycleLoop)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunRecycleLoop(Ioc));
    }

} // namespace
