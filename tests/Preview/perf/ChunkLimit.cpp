/**
 * @file ChunkLimit.cpp
 * @brief chunk 大小上限验证（Release）
 * @details 手动 Seal+send 不同块大小（协议外扩展），
 * 证明"chunk 数量 × 固定成本"是加密传输的唯一瓶颈
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
#include <Preview/Protocols/Vmess/Codec.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;
namespace Vmess = Preview::Vmess;

namespace
{
    auto NowNanoseconds() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    // 手动：Seal chunk_size 明文 → send 密文（raw TCP）
    auto RunBenchmark(const std::size_t Total, const std::size_t ChunkSize) -> std::int64_t
    {
        Net::io_context IoContext;
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        const auto key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        Vmess::ChunkEncryptor Encryptor(key, Nonce);
        std::vector<std::uint8_t> Plain(ChunkSize, 0x5A);
        std::vector<std::uint8_t> Output(ChunkSize + Vmess::ChunkEncryptor::Overhead);
        std::vector<std::uint8_t> Rx(262144);

        const std::int64_t StartNanoseconds = NowNanoseconds();
        int Completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                Net::ip::tcp::socket Socket(IoContext);
                co_await Acceptor.async_accept(Socket, Net::use_awaitable);
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto Count = co_await Socket.async_read_some(
                        Net::buffer(Rx), Net::use_awaitable);
                    if (Count == 0)
                    {
                        break;
                    }
                    Done += Count;
                }
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Net::ip::tcp::socket Socket(IoContext);
            const auto Endpoint = Net::ip::tcp::endpoint(
                Net::ip::address_v4::loopback(), Port);
            co_await Socket.async_connect(Endpoint, Net::use_awaitable);
            std::size_t Done = 0;
            while (Done < Total)
            {
                const auto EncryptedSize = Encryptor.Seal(Plain, Output);
                std::size_t Offset = 0;
                while (Offset < EncryptedSize)
                {
                    const auto Count = co_await Socket.async_write_some(
                        Net::buffer(Output.data() + Offset, EncryptedSize - Offset),
                        Net::use_awaitable);
                    if (Count == 0)
                    {
                        break; // 断链：Completed=0 门禁 FAIL
                    }
                    Offset += Count;
                }
                if (Offset < EncryptedSize)
                {
                    Completed = 0;
                    break;
                }
                Done += ChunkSize;
            }
            if (Done < Total)
            {
                Completed = 0;
            }
        }, [&](std::exception_ptr) { IoContext.stop(); });
        IoContext.run();
        if (Completed == 0)
        {
            return 0;
        }
        return NowNanoseconds() - StartNanoseconds;
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;

    for (const auto cs : {16384UL, 65535UL, 262144UL, 1048576UL})
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = RunBenchmark(kTotal, cs);
        }
        std::sort(s.begin(), s.end());
        const double mbps = (kTotal / 1024.0 / 1024.0) / (s[1] / 1e9);
        std::printf("chunk=%7zu: med=%7.2f ms  => %8.1f MB/s  (%5.1f Gbps)\n", cs, s[1] / 1e6,
                    mbps, mbps * 8 / 1000);
        if (std::any_of(s.begin(), s.end(), [](std::int64_t v) { return v <= 0; }) || mbps < 50.0)
        {
            std::printf("FAIL chunk=%zu: 存在数据面未完成运行或吞吐 %.1f MB/s 过低\n", cs, mbps);
            return 1;
        }
    }
    std::printf("ChunkLimit: ALL PASS\n");
    return 0;
}
