/**
 * @file ProtocolTransferBench.cpp
 * @brief 协议层传输基准（本机真实 TCP loopback，Release）
 * @details Client Conn ↔ Server Conn 端到端传输：
 * 1. socks5 透传路径（纯 relay，协议层零拷贝叠加）
 * 2. vmess 加密路径（Chunk 加密，资源指针 MakeBuffer 复用）
 * 3. vmess 对照：每帧分配 vs 复用缓冲（资源指针收益量化）
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include <Preview/Transport/Reliable.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;
namespace Socks5 = Preview::Socks5;
namespace Transport = Preview::Transport;
namespace Vmess = Preview::Vmess;
using Preview::Error;

namespace
{
    auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    struct Result
    {
        std::array<std::int64_t, 3> Samples{};
        auto Median() const -> std::int64_t
        {
            auto Sorted = Samples;
            std::sort(Sorted.begin(), Sorted.end());
            return Sorted[1];
        }
    };

    auto Report(const char *Name, const std::size_t Bytes, const Result &Statistics) -> void
    {
        const double Megabytes = static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const auto Median = Statistics.Median();
        const double Seconds = static_cast<double>(Median) / 1e9;
        std::printf("%-44s %7.1f MB  med=%7.2f ms (runs %6.2f/%6.2f/%6.2f)  => %9.1f MB/s  %5.1f Gbps\n",
                    Name, Megabytes, Seconds * 1000, Statistics.Samples[0] / 1e6,
                    Statistics.Samples[1] / 1e6, Statistics.Samples[2] / 1e6,
                    Megabytes / Seconds, Megabytes / Seconds * 8 / 1000);
    }

    /// 性能门禁：全部样本数据面完成 + 吞吐下限（防断链静默/死循环挂死/完全退化）
    auto Gate(const char *Name, const std::size_t Bytes, const Result &Statistics) -> bool
    {
        constexpr double MinMbps = 50.0; // 宽松下限（本地 TCP 基线数百 MB/s，防 10x+ 劣化）
        Report(Name, Bytes, Statistics);
        const auto Median = Statistics.Median();
        // 任一运行断链/未完成即 FAIL（部分失败不得被中位数掩盖）
        if (std::any_of(Statistics.Samples.begin(), Statistics.Samples.end(),
                        [](std::int64_t Value) { return Value <= 0; }))
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", Name);
            return false;
        }
        const double MegabitsPerSecond = static_cast<double>(Bytes) / (1024.0 * 1024.0) /
                                         (static_cast<double>(Median) / 1e9);
        if (MegabitsPerSecond < MinMbps)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n", Name, MegabitsPerSecond, MinMbps);
            return false;
        }
        return true;
    }

    // ── socks5 Conn 对 Conn：透传路径 ──
    auto BenchSocks5Transfer(const std::size_t Total, const std::size_t BlockSize) -> std::int64_t
    {
        Net::io_context IoContext;
        Net::ip::tcp::acceptor Acceptor(IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        std::vector<std::uint8_t> Chunk(BlockSize, 0x5A);

        const std::int64_t StartNs = NowNs();
        int Completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            // 服务端：Accept TCP → socks5 Accept → 读丢弃
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                Net::ip::tcp::socket Socket(IoContext);
                co_await Acceptor.async_accept(Socket, Net::use_awaitable);
                auto Reliable = std::make_shared<Transport::Reliable>(std::move(Socket));
                auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(Reliable, Socks5::ServerConfig{});
                if (ErrorValue != Error::None || !Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> Buffer(BlockSize);
                std::error_code ErrorCode;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto BytesRead = co_await Conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()), ErrorCode);
                    if (ErrorCode || BytesRead == 0)
                    {
                        break;
                    }
                    Done += BytesRead;
                }
                Conn->Close();
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            // 客户端：Connect → socks5 握手 → 写
            auto Reliable = std::make_shared<Transport::Reliable>(IoContext.get_executor());
            const auto ConnectError = co_await Reliable->Connect(Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
            if (ConnectError)
            {
                IoContext.stop();
                co_return;
            }
            auto [ErrorValue, Conn] = co_await Socks5::Connect(
                Reliable, Socks5::ClientConfig{},
                Socks5::Address{Socks5::AddressType::Domain, "Target.internal", 443});
            if (ErrorValue != Error::None || !Conn)
            {
                IoContext.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ErrorCode;
            while (Done < Total)
            {
                const auto BytesRead = co_await Conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data()), Chunk.size()), ErrorCode);
                if (ErrorCode || BytesRead == 0)
                {
                    break; // 断链：Completed=0 门禁 FAIL，避免死循环挂死
                }
                Done += BytesRead;
            }
            if (Done < Total)
            {
                Completed = 0;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { IoContext.stop(); });
        IoContext.run();
        if (Completed == 0)
        {
            return 0;
        }
        return NowNs() - StartNs;
    }

    // ── vmess Conn 对 Conn：加密路径 ──
    auto BenchVmessTransfer(const std::size_t Total, const std::size_t BlockSize, const bool Reuse)
        -> std::int64_t
    {
        Net::io_context IoContext;
        Net::ip::tcp::acceptor Acceptor(IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        std::vector<std::uint8_t> Chunk(BlockSize, 0x5A);
        const auto Uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

        const std::int64_t StartNs = NowNs();
        int Completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                Net::ip::tcp::socket Socket(IoContext);
                co_await Acceptor.async_accept(Socket, Net::use_awaitable);
                auto Reliable = std::make_shared<Transport::Reliable>(std::move(Socket));
                Vmess::ServerConfig ServerConfig;
                ServerConfig.uuid = Uuid;
                auto [ErrorValue, Request, Conn] = co_await Vmess::Accept(Reliable, ServerConfig);
                if (ErrorValue != Error::None || !Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> Buffer(BlockSize);
                std::error_code ErrorCode;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto BytesRead = co_await Conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()), ErrorCode);
                    if (ErrorCode || BytesRead == 0)
                    {
                        break;
                    }
                    Done += BytesRead;
                }
                Conn->Close();
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            auto Reliable = std::make_shared<Transport::Reliable>(IoContext.get_executor());
            const auto ConnectError = co_await Reliable->Connect(Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
            if (ConnectError)
            {
                IoContext.stop();
                co_return;
            }
            Vmess::ClientConfig ClientConfig;
            ClientConfig.uuid = Uuid;
            auto [ErrorValue, Conn] = co_await Vmess::Connect(
                Reliable, ClientConfig, Vmess::Address{Vmess::AddressType::Domain, "Target.internal", 443});
            if (ErrorValue != Error::None || !Conn)
            {
                IoContext.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ErrorCode;
            while (Done < Total)
            {
                const auto BytesRead = co_await Conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data()), Chunk.size()), ErrorCode);
                if (ErrorCode || BytesRead == 0)
                {
                    break; // 断链：Completed=0 门禁 FAIL，避免死循环挂死
                }
                Done += BytesRead;
            }
            if (Done < Total)
            {
                Completed = 0;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { IoContext.stop(); });
        IoContext.run();
        if (Completed == 0)
        {
            return 0;
        }
        return NowNs() - StartNs;
    }

    // ── vmess 加密：复用 vs 每帧分配（资源指针收益） ──
    auto BenchVmessChunk(const bool Reuse) -> std::int64_t
    {
        namespace VmessLocal = Preview::Vmess;
        const auto Key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        VmessLocal::ChunkEncryptor Encoder(Key, Nonce);
        constexpr std::size_t ChunkSize = 16384;
        constexpr int IterationCount = 16384; // 16KB x 16384 = 256MB
        std::vector<std::uint8_t> Plain(ChunkSize);
        for (std::size_t I = 0; I < Plain.size(); ++I)
        {
            Plain[I] = static_cast<std::uint8_t>(I);
        }

        const std::int64_t StartNs = NowNs();
        if (Reuse)
        {
            // 资源指针：Arena 缓冲复用（vmess Conn 实际路径）
            Preview::Memory::SessionResource<> MemoryResource;
            auto Output = MemoryResource.MakeBuffer<std::uint8_t>(ChunkSize + VmessLocal::ChunkEncryptor::Overhead);
            volatile std::size_t Sink = 0;
            for (int I = 0; I < IterationCount; ++I)
            {
                Sink += Encoder.Seal(Plain, Output);
            }
        }
        else
        {
            // 无资源指针：每块新建（系统堆分配）
            volatile std::size_t Sink = 0;
            for (int I = 0; I < IterationCount; ++I)
            {
                std::vector<std::uint8_t> Output(ChunkSize + VmessLocal::ChunkEncryptor::Overhead);
                Sink += Encoder.Seal(Plain, Output);
            }
        }
        return NowNs() - StartNs;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockSize = 262144;

    Result Socks5Result, VmessResult, ReuseResult, NaiveResult;
    for (int I = 0; I < 3; ++I)
    {
        Socks5Result.Samples[I] = BenchSocks5Transfer(TotalBytes, BlockSize);
        VmessResult.Samples[I] = BenchVmessTransfer(TotalBytes, BlockSize, true);
        ReuseResult.Samples[I] = BenchVmessChunk(true);
        NaiveResult.Samples[I] = BenchVmessChunk(false);
    }
    if (!Gate("socks5 Conn<->Conn (透传)", TotalBytes, Socks5Result))
    {
        return 1;
    }
    if (!Gate("vmess Conn<->Conn (加密, 资源指针)", TotalBytes, VmessResult))
    {
        return 1;
    }
    std::printf("---- vmess 加密 256MB（纯加密，无传输）----\n");
    if (!Gate("vmess Chunk 复用缓冲 (资源指针)", 256ULL * 1024 * 1024, ReuseResult))
    {
        return 1;
    }
    if (!Gate("vmess Chunk 每帧分配 (无资源指针)", 256ULL * 1024 * 1024, NaiveResult))
    {
        return 1;
    }
    std::printf("ProtocolTransferBench: ALL PASS\n");
    return 0;
}
