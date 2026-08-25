/**
 * @file ProtocolTransferBench.cpp
 * @brief 协议层传输基准（本机真实 TCP loopback，Release）
 * @details Client Conn ↔ Server Conn 端到端传输：
 * 1. socks5 透传路径（纯 relay，协议层零拷贝叠加）
 * 2. vmess 加密路径（chunk 加密，资源指针 MakeBuffer 复用）
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

#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>
#include <common/Protocols/Vmess/Vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    struct Result
    {
        std::array<std::int64_t, 3> samples{};
        auto median() const -> std::int64_t
        {
            auto s = samples;
            std::sort(s.begin(), s.end());
            return s[1];
        }
    };

    auto Report(const char *Name, const std::size_t Bytes, const Result &r) -> void
    {
        const double mb = static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const auto med = r.median();
        const double sec = static_cast<double>(med) / 1e9;
        std::printf("%-44s %7.1f MB  med=%7.2f ms (runs %6.2f/%6.2f/%6.2f)  => %9.1f MB/s  %5.1f Gbps\n",
                    Name, mb, sec * 1000, r.samples[0] / 1e6, r.samples[1] / 1e6, r.samples[2] / 1e6,
                    mb / sec, mb / sec * 8 / 1000);
    }

    /// 性能门禁：全部样本数据面完成 + 吞吐下限（防断链静默/死循环挂死/完全退化）
    auto Gate(const char *Name, const std::size_t Bytes, const Result &r) -> bool
    {
        constexpr double kMinMbps = 50.0; // 宽松下限（本地 TCP 基线数百 MB/s，防 10x+ 劣化）
        Report(Name, Bytes, r);
        const auto med = r.median();
        // 任一运行断链/未完成即 FAIL（部分失败不得被中位数掩盖）
        if (std::any_of(r.samples.begin(), r.samples.end(), [](std::int64_t v) { return v <= 0; }))
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", Name);
            return false;
        }
        const double mbps = static_cast<double>(Bytes) / (1024.0 * 1024.0) / (static_cast<double>(med) / 1e9);
        if (mbps < kMinMbps)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n", Name, mbps, kMinMbps);
            return false;
        }
        return true;
    }

    // ── socks5 Conn 对 Conn：透传路径 ──
    auto bench_socks5_transfer(const std::size_t Total, const std::size_t block) -> std::int64_t
    {
        using namespace Preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        int completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端：Accept TCP → socks5 Accept → 读丢弃
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<Transport::Reliable>(std::move(sock));
                auto [err, req, Conn] = co_await Socks5::Accept(ss, Socks5::ServerConfig{});
                if (err != Error::none || !Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await Conn->AsyncReadSome(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Done += n;
                }
                Conn->Close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 客户端：Connect → socks5 握手 → 写
            auto ss = std::make_shared<Transport::Reliable>(ioc.get_executor());
            const auto ec2 = co_await ss->Connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            auto [err, Conn] = co_await Socks5::Connect(
                ss, Socks5::ClientConfig{},
                Socks5::Address{Socks5::AddressType::Domain, "Target.internal", 443});
            if (err != Error::none || !Conn)
            {
                ioc.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ec;
            while (Done < Total)
            {
                const auto n = co_await Conn->AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    break; // 断链：completed=0 门禁 FAIL，避免死循环挂死
                }
                Done += n;
            }
            if (Done < Total)
            {
                completed = 0;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        if (completed == 0)
        {
            return 0;
        }
        return now_ns() - t0;
    }

    // ── vmess Conn 对 Conn：加密路径 ──
    auto bench_vmess_transfer(const std::size_t Total, const std::size_t block, const bool reuse)
        -> std::int64_t
    {
        using namespace Preview;
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
                auto ss = std::make_shared<Transport::Reliable>(std::move(sock));
                Vmess::ServerConfig scfg;
                scfg.uuid = uuid;
                auto [err, req, Conn] = co_await Vmess::Accept(ss, scfg);
                if (err != Error::none || !Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await Conn->AsyncReadSome(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Done += n;
                }
                Conn->Close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto ss = std::make_shared<Transport::Reliable>(ioc.get_executor());
            const auto ec2 = co_await ss->Connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            Vmess::ClientConfig ccfg;
            ccfg.uuid = uuid;
            auto [err, Conn] = co_await Vmess::Connect(
                ss, ccfg, Vmess::Address{Vmess::AddressType::Domain, "Target.internal", 443});
            if (err != Error::none || !Conn)
            {
                ioc.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ec;
            while (Done < Total)
            {
                const auto n = co_await Conn->AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    break; // 断链：completed=0 门禁 FAIL，避免死循环挂死
                }
                Done += n;
            }
            if (Done < Total)
            {
                completed = 0;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        if (completed == 0)
        {
            return 0;
        }
        return now_ns() - t0;
    }

    // ── vmess 加密：复用 vs 每帧分配（资源指针收益） ──
    auto bench_vmess_chunk(const bool reuse) -> std::int64_t
    {
        using namespace Preview::Vmess;
        const auto key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        ChunkEncryptor enc(key, Nonce);
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
            // 资源指针：Arena 缓冲复用（vmess Conn 实际路径）
            Preview::Memory::SessionResource<> mem;
            auto out = mem.MakeBuffer<std::uint8_t>(kChunk + ChunkEncryptor::overhead);
            volatile std::size_t sink = 0;
            for (int i = 0; i < kIters; ++i)
            {
                sink += enc.Seal(plain, out);
            }
        }
        else
        {
            // 无资源指针：每块新建（系统堆分配）
            volatile std::size_t sink = 0;
            for (int i = 0; i < kIters; ++i)
            {
                std::vector<std::uint8_t> out(kChunk + ChunkEncryptor::overhead);
                sink += enc.Seal(plain, out);
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

    Result r_s5, r_vm, r_reuse, r_naive;
    for (int i = 0; i < 3; ++i)
    {
        r_s5.samples[i] = bench_socks5_transfer(kTotal, kBlock);
        r_vm.samples[i] = bench_vmess_transfer(kTotal, kBlock, true);
        r_reuse.samples[i] = bench_vmess_chunk(true);
        r_naive.samples[i] = bench_vmess_chunk(false);
    }
    if (!Gate("socks5 Conn<->Conn (透传)", kTotal, r_s5))
    {
        return 1;
    }
    if (!Gate("vmess Conn<->Conn (加密, 资源指针)", kTotal, r_vm))
    {
        return 1;
    }
    std::printf("---- vmess 加密 256MB（纯加密，无传输）----\n");
    if (!Gate("vmess chunk 复用缓冲 (资源指针)", 256ULL * 1024 * 1024, r_reuse))
    {
        return 1;
    }
    if (!Gate("vmess chunk 每帧分配 (无资源指针)", 256ULL * 1024 * 1024, r_naive))
    {
        return 1;
    }
    std::printf("ProtocolTransferBench: ALL PASS\n");
    return 0;
}
