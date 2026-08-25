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

#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Vmess/Codec.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    // 手动：Seal chunk_size 明文 → send 密文（raw TCP）
    auto bench(const std::size_t Total, const std::size_t chunk_size) -> std::int64_t
    {
        using namespace Preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        const auto key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        Vmess::ChunkEncryptor enc(key, Nonce);
        std::vector<std::uint8_t> plain(chunk_size, 0x5A);
        std::vector<std::uint8_t> out(chunk_size + Vmess::ChunkEncryptor::overhead);
        std::vector<std::uint8_t> Rx(262144);

        const std::int64_t t0 = now_ns();
        int completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await sock.async_read_some(net::buffer(Rx), net::use_awaitable);
                    if (n == 0)
                    {
                        break;
                    }
                    Done += n;
                }
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            net::ip::tcp::socket sock(ioc);
            co_await sock.async_connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port),
                                        net::use_awaitable);
            std::size_t Done = 0;
            while (Done < Total)
            {
                const auto enc_n = enc.Seal(plain, out);
                std::size_t off = 0;
                while (off < enc_n)
                {
                    const auto n = co_await sock.async_write_some(
                        net::buffer(out.data() + off, enc_n - off), net::use_awaitable);
                    if (n == 0)
                    {
                        break; // 断链：completed=0 门禁 FAIL
                    }
                    off += n;
                }
                if (off < enc_n)
                {
                    completed = 0;
                    break;
                }
                Done += chunk_size;
            }
            if (Done < Total)
            {
                completed = 0;
            }
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        if (completed == 0)
        {
            return 0;
        }
        return now_ns() - t0;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;

    for (const auto cs : {16384UL, 65535UL, 262144UL, 1048576UL})
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench(kTotal, cs);
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
