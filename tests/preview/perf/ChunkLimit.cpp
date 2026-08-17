/**
 * @file ChunkLimit.cpp
 * @brief chunk 大小上限验证（Release）
 * @details 手动 seal+send 不同块大小（协议外扩展），
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

#include <common/core/transport/reliable.hpp>
#include <common/protocols/vmess/codec.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    // 手动：seal chunk_size 明文 → send 密文（raw TCP）
    auto bench(const std::size_t total, const std::size_t chunk_size) -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        const auto key = std::array<std::uint8_t, 16>{};
        const auto nonce = std::array<std::uint8_t, 12>{};
        vmess::chunk_encryptor enc(key, nonce);
        std::vector<std::uint8_t> plain(chunk_size, 0x5A);
        std::vector<std::uint8_t> out(chunk_size + vmess::chunk_encryptor::overhead);
        std::vector<std::uint8_t> rx(262144);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                std::size_t done = 0;
                while (done < total)
                {
                    const auto n = co_await sock.async_read_some(net::buffer(rx), net::use_awaitable);
                    if (n == 0)
                    {
                        break;
                    }
                    done += n;
                }
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            net::ip::tcp::socket sock(ioc);
            co_await sock.async_connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port),
                                        net::use_awaitable);
            std::size_t done = 0;
            while (done < total)
            {
                const auto enc_n = enc.seal(plain, out);
                std::size_t off = 0;
                while (off < enc_n)
                {
                    off += co_await sock.async_write_some(
                        net::buffer(out.data() + off, enc_n - off), net::use_awaitable);
                }
                done += chunk_size;
            }
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
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
        std::printf("chunk=%7zu: med=%7.2f ms  => %8.1f MB/s  (%5.1f Gbps)\n", cs, s[1] / 1e6,
                    (kTotal / 1024.0 / 1024.0) / (s[1] / 1e9), (kTotal / 1024.0 / 1024.0) / (s[1] / 1e9) * 8 / 1000);
    }
    return 0;
}
