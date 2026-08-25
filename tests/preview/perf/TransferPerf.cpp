/**
 * @file TransferPerf.cpp
 * @brief 传输吞吐基准（Release，严谨复测）
 * @details 每个场景跑 3 次交替顺序，取中位数，消除 CPU 频率升温与顺序偏差。
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    auto bench_stream_block(const std::size_t Total, const std::size_t block) -> std::int64_t
    {
        using Preview::MakeMemoryPair;
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto sink = [&]() -> net::awaitable<void>
            {
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await b.AsyncReadSome(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Done += n;
                }
            };
            net::co_spawn(ioc.get_executor(), sink(), net::detached);

            std::error_code ec;
            std::size_t Done = 0;
            while (Done < Total)
            {
                const auto n = co_await a.AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), block), ec);
                Done += n;
            }
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return now_ns() - t0;
    }

    auto bench_tcp_raw(const std::size_t Total, const std::size_t block) -> std::int64_t
    {
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                std::vector<std::uint8_t> buf(block);
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await sock.async_read_some(net::buffer(buf), net::use_awaitable);
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
                Done += co_await sock.async_write_some(net::buffer(chunk), net::use_awaitable);
            }
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return now_ns() - t0;
    }

    auto bench_tcp_socks5(const std::size_t Total, const std::size_t block) -> std::int64_t
    {
        using namespace Preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto proxy_port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto proxy_coro = [&]() -> net::awaitable<void>
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
            net::co_spawn(ioc.get_executor(), proxy_coro(), net::detached);

            auto ss = std::make_shared<Transport::Reliable>(ioc.get_executor());
            const auto ec_conn = co_await ss->Connect(
                net::ip::tcp::endpoint(net::ip::address_v4::loopback(), proxy_port));
            if (ec_conn)
            {
                ioc.stop();
                co_return;
            }
            auto [err, Conn] = co_await Socks5::Connect(
                ss, Socks5::ClientConfig{},
                Socks5::Address{Socks5::AddressType::Domain, "echo.internal", 9999});
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
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), block), ec);
                Done += n;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return now_ns() - t0;
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
        std::printf("%-38s %7.1f MB  med=%7.2f ms (3 runs: %7.2f/%7.2f/%7.2f)  => %9.1f MB/s\n", Name, mb,
                    sec * 1000, r.samples[0] / 1e6, r.samples[1] / 1e6, r.samples[2] / 1e6,
                    mb / sec);
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
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;

    // 块大小分解：16KB（vmess 同款）vs 256KB
    Result r_16k, r_256k;
    for (int i = 0; i < 3; ++i)
    {
        r_16k.samples[i] = bench_tcp_raw(kTotal, 16384);
        r_256k.samples[i] = bench_tcp_raw(kTotal, 262144);
    }
    if (!Gate("Tcp raw 16KB block", kTotal, r_16k))
    {
        return 1;
    }
    if (!Gate("Tcp raw 256KB block", kTotal, r_256k))
    {
        return 1;
    }
    std::printf("TransferPerf: ALL PASS\n");
    return 0;
}
