/**
 * @file ProtocolTransferBench.cpp
 * @brief 协议层传输基准（本机真实 TCP loopback，Release）
 * @details client conn ↔ server conn 端到端传输：
 * 1. socks5 透传路径（纯 relay，协议层零拷贝叠加）
 * 2. vmess 加密路径（chunk 加密，资源指针 make_buffer 复用）
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

#include <common/core/transport/reliable.hpp>
#include <common/protocols/socks5/socks5.hpp>
#include <common/protocols/vmess/vmess.hpp>

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
        std::printf("%-44s %7.1f MB  med=%7.2f ms (runs %6.2f/%6.2f/%6.2f)  => %9.1f MB/s  %5.1f Gbps\n",
                    name, mb, sec * 1000, r.samples[0] / 1e6, r.samples[1] / 1e6, r.samples[2] / 1e6,
                    mb / sec, mb / sec * 8 / 1000);
    }

    // ── socks5 conn 对 conn：透传路径 ──
    auto bench_socks5_transfer(const std::size_t total, const std::size_t block) -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端：accept TCP → socks5 accept → 读丢弃
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<transport::reliable>(std::move(sock));
                auto [err, req, conn] = co_await socks5::accept(ss, socks5::server_config{});
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

            // 客户端：connect → socks5 握手 → 写
            auto ss = std::make_shared<transport::reliable>(ioc.get_executor());
            const auto ec2 = co_await ss->connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            auto [err, conn] = co_await socks5::connect(
                ss, socks5::client_config{},
                socks5::address{socks5::address_type::domain, "target.internal", 443});
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
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), block), ec);
                done += n;
            }
            conn->close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return now_ns() - t0;
    }

    // ── vmess conn 对 conn：加密路径 ──
    auto bench_vmess_transfer(const std::size_t total, const std::size_t block, const bool reuse)
        -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);
        const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

        const std::int64_t t0 = now_ns();
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
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), block), ec);
                done += n;
            }
            conn->close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return now_ns() - t0;
    }

    // ── vmess 加密：复用 vs 每帧分配（资源指针收益） ──
    auto bench_vmess_chunk(const bool reuse) -> std::int64_t
    {
        using namespace preview::vmess;
        const auto key = std::array<std::uint8_t, 16>{};
        const auto nonce = std::array<std::uint8_t, 12>{};
        chunk_encryptor enc(key, nonce);
        constexpr std::size_t kChunk = 16384;
        constexpr int kIters = 16384; // 16KB x 16384 = 256MB
        std::vector<std::uint8_t> plain(kChunk);
        for (std::size_t i = 0; i < plain.size(); ++i)
        {
            plain[i] = static_cast<std::uint8_t>(i);
        }

        const std::int64_t t0 = now_ns();
        if (reuse)
        {
            // 资源指针：arena 缓冲复用（vmess conn 实际路径）
            preview::memory::session_resource<> mem;
            auto out = mem.make_buffer<std::uint8_t>(kChunk + chunk_encryptor::overhead);
            volatile std::size_t sink = 0;
            for (int i = 0; i < kIters; ++i)
            {
                sink += enc.seal(plain, out);
            }
        }
        else
        {
            // 无资源指针：每块新建（系统堆分配）
            volatile std::size_t sink = 0;
            for (int i = 0; i < kIters; ++i)
            {
                std::vector<std::uint8_t> out(kChunk + chunk_encryptor::overhead);
                sink += enc.seal(plain, out);
            }
        }
        return now_ns() - t0;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;
    constexpr std::size_t kBlock = 262144;

    result r_s5, r_vm, r_reuse, r_naive;
    for (int i = 0; i < 3; ++i)
    {
        r_s5.samples[i] = bench_socks5_transfer(kTotal, kBlock);
        r_vm.samples[i] = bench_vmess_transfer(kTotal, kBlock, true);
        r_reuse.samples[i] = bench_vmess_chunk(true);
        r_naive.samples[i] = bench_vmess_chunk(false);
    }
    report("socks5 conn<->conn (透传)", kTotal, r_s5);
    report("vmess conn<->conn (加密, 资源指针)", kTotal, r_vm);
    std::printf("---- vmess 加密 256MB（纯加密，无传输）----\n");
    report("vmess chunk 复用缓冲 (资源指针)", 256ULL * 1024 * 1024, r_reuse);
    report("vmess chunk 每帧分配 (无资源指针)", 256ULL * 1024 * 1024, r_naive);
    return 0;
}
