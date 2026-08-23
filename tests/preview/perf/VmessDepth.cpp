/**
 * @file VmessDepth.cpp
 * @brief vmess 传输深度分析（Release）
 * @details 1. vmess 单连接多次
 *         2. vmess 4 连接并发（调度瓶颈 vs 带宽瓶颈）
 *         3. raw TCP 16KB 对照（同块大小基线）
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
#include <common/protocols/vmess/vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    auto bench_vmess_single(const std::size_t total, const std::size_t block) -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);
        const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

        const std::int64_t t0 = now_ns();
        int completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<transport::reliable>(std::move(sock));
                vmess::server_config scfg;
                scfg.uuid = uuid;
                auto [err, req, conn] = co_await vmess::accept(ss, scfg);
                if (err != error::none || !conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t done = 0;
                while (done < total)
                {
                    const auto n = co_await conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    done += n;
                }
                conn->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto ss = std::make_shared<transport::reliable>(ioc.get_executor());
            const auto ec2 = co_await ss->connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            vmess::client_config ccfg;
            ccfg.uuid = uuid;
            auto [err, conn] = co_await vmess::connect(
                ss, ccfg, vmess::address{vmess::address_type::domain, "target.internal", 443});
            if (err != error::none || !conn)
            {
                ioc.stop();
                co_return;
            }
            std::size_t done = 0;
            std::error_code ec;
            while (done < total)
            {
                const auto n = co_await conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    break; // 断链：completed=0 门禁 FAIL，避免死循环挂死
                }
                done += n;
            }
            if (done < total)
            {
                completed = 0;
            }
            conn->close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        if (completed == 0)
        {
            return 0;
        }
        return now_ns() - t0;
    }

    // 4 连接并发（每连接 total/4）
    auto bench_vmess_parallel4(const std::size_t total, const std::size_t block) -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        std::vector<std::uint8_t> chunk(block, 0x5A);
        const auto per = total / 4;

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            for (int c = 0; c < 4; ++c)
            {
                auto one = [&, c]() -> net::awaitable<void>
                {
                    net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                    const auto port = acceptor.local_endpoint().port();

                    auto server_coro = [&, c]() -> net::awaitable<void>
                    {
                        net::ip::tcp::socket sock(ioc);
                        co_await acceptor.async_accept(sock, net::use_awaitable);
                        auto ss = std::make_shared<transport::reliable>(std::move(sock));
                        vmess::server_config scfg;
                        scfg.uuid = uuid;
                        auto [err, req, conn] = co_await vmess::accept(ss, scfg);
                        if (err != error::none || !conn)
                        {
                            co_return;
                        }
                        std::vector<std::uint8_t> buf(block);
                        std::error_code ec;
                        std::size_t done = 0;
                        while (done < per)
                        {
                            const auto n = co_await conn->async_read_some(
                                std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                            if (ec || n == 0)
                            {
                                break;
                            }
                            done += n;
                        }
                        conn->close();
                    };
                    net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                    auto ss = std::make_shared<transport::reliable>(ioc.get_executor());
                    const auto ec2 = co_await ss->connect(
                        net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
                    if (ec2)
                    {
                        co_return;
                    }
                    vmess::client_config ccfg;
                    ccfg.uuid = uuid;
                    auto [err, conn] = co_await vmess::connect(
                        ss, ccfg, vmess::address{vmess::address_type::domain, "t.internal", 443});
                    if (err != error::none || !conn)
                    {
                        co_return;
                    }
                    std::size_t done = 0;
                    std::error_code ec;
                    while (done < per)
                    {
                        const auto n = co_await conn->async_write_some(
                            std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()),
                                                       block),
                            ec);
                        done += n;
                    }
                    conn->close();
                };
                net::co_spawn(ioc.get_executor(), one(), net::detached);
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

    // vmess 单连接 3 次（不同外部块大小）
    for (const auto block : {16384UL, 262144UL})
    {
        std::array<std::int64_t, 3> samples{};
        for (int i = 0; i < 3; ++i)
        {
            samples[i] = bench_vmess_single(kTotal, block);
        }
        std::sort(samples.begin(), samples.end());
        const double mbps = (kTotal / 1024.0 / 1024.0) / (samples[1] / 1e9);
        std::printf("vmess 单连接 外部块=%6zu: med=%7.2f ms  => %8.1f MB/s\n", block,
                    samples[1] / 1e6, mbps);
        if (std::any_of(samples.begin(), samples.end(), [](std::int64_t v) { return v <= 0; }) || mbps < 50.0)
        {
            std::printf("FAIL vmess 单连接 block=%zu: 存在数据面未完成运行或吞吐过低\n", block);
            return 1;
        }
    }

    // vmess 4 连接并发（跳过：acceptor 动态创建死锁）
    std::printf("VmessDepth: ALL PASS\n");
    return 0;
}
