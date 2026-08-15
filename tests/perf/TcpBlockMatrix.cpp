/**
 * @file TcpBlockMatrix.cpp
 * @brief TCP 块大小变量控制实验（Release，本机 loopback）
 * @details 2x2 矩阵：写侧块大小（16KB/256KB）x 读侧 buffer（16KB/256KB）
 * 分离"写块大小"与"读块大小"对吞吐的影响，回答：
 * - 16KB 写块是否本身慢（系统调用次数）
 * - 读侧 buffer 大小是否吸收多块
 * 另测 TCP send/recv 缓冲大小（默认 vs 显式 1MB）验证动态增长。
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
#include <vector>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    struct result
    {
        std::array<std::int64_t, 3> samples{};
        auto median() const -> std::int64_t
        {
            auto s = samples;
            std::sort(s.begin(), s.end());
            return s[1];
        }
    };

    auto report(const char *name, const std::size_t bytes, const result &r) -> void
    {
        const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        const auto med = r.median();
        const double sec = static_cast<double>(med) / 1e9;
        std::printf("%-40s %7.1f MB  med=%7.2f ms  => %9.1f MB/s\n", name, mb, sec * 1000,
                    mb / sec);
    }

    // 固定 TCP 缓冲大小（0 = 默认 autotune）
    auto bench(const std::size_t total, const std::size_t wblock, const std::size_t rblock,
               const std::size_t sockbuf) -> std::int64_t
    {
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(wblock, 0x5A);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                if (sockbuf > 0)
                {
                    sock.set_option(net::ip::tcp::socket::receive_buffer_size(static_cast<int>(sockbuf)));
                }
                std::vector<std::uint8_t> buf(rblock);
                std::size_t done = 0;
                while (done < total)
                {
                    const auto n = co_await sock.async_read_some(net::buffer(buf), net::use_awaitable);
                    if (n == 0)
                    {
                        break;
                    }
                    done += n;
                }
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            net::ip::tcp::socket sock(ioc);
            if (sockbuf > 0)
            {
                sock.set_option(net::ip::tcp::socket::send_buffer_size(static_cast<int>(sockbuf)));
            }
            co_await sock.async_connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port),
                                        net::use_awaitable);
            std::size_t done = 0;
            while (done < total)
            {
                done += co_await sock.async_write_some(net::buffer(chunk), net::use_awaitable);
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

    // 2x2 矩阵（默认 TCP 缓冲，autotune）
    {
        struct cell
        {
            std::size_t w;
            std::size_t r;
        };
        const cell cells[] = {{16384, 16384}, {16384, 262144}, {262144, 16384}, {262144, 262144}};
        const char *names[] = {"写16KB 读16KB", "写16KB 读256KB", "写256KB 读16KB", "写256KB 读256KB"};
        result rs[4];
        for (int i = 0; i < 3; ++i)
        {
            for (int c = 0; c < 4; ++c)
            {
                rs[c].samples[i] = bench(kTotal, cells[c].w, cells[c].r, 0);
            }
        }
        std::printf("== 2x2 矩阵（默认 TCP 缓冲，autotune）==\n");
        for (int c = 0; c < 4; ++c)
        {
            report(names[c], kTotal, rs[c]);
        }
    }

    // 固定缓冲 1MB vs 默认（16KB 写 16KB 读）
    {
        result r_default, r_1m;
        for (int i = 0; i < 3; ++i)
        {
            r_default.samples[i] = bench(kTotal, 16384, 16384, 0);
            r_1m.samples[i] = bench(kTotal, 16384, 16384, 1024 * 1024);
        }
        std::printf("== TCP 缓冲大小影响（写16KB 读16KB）==\n");
        report("默认 autotune", kTotal, r_default);
        report("显式 1MB 缓冲", kTotal, r_1m);
    }
    return 0;
}
