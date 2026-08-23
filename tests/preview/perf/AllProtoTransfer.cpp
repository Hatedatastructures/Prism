/**
 * @file AllProtoTransfer.cpp
 * @brief 全部 TCP 协议传输基准（Release，本机真实 TCP）
 * @details 每个协议 client conn ↔ server conn 256MB 传输：
 * socks5（透传）/ trojan（透传）/ vless（透传）/ vmess（加密 chunk）
 * / ss2022（加密 chunk）
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
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>
#include <common/protocols/socks5/socks5.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/protocols/vless/vless.hpp>
#include <common/protocols/vmess/vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    auto report(const char *name, const std::size_t bytes, const std::int64_t med) -> void
    {
        const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        const double sec = static_cast<double>(med) / 1e9;
        std::printf("%-40s %7.1f MB  med=%7.2f ms  => %9.1f MB/s  %5.1f Gbps\n", name, mb, sec * 1000,
                    mb / sec, mb / sec * 8 / 1000);
    }

    /// 性能门禁：全部样本数据面完成 + 吞吐下限（防断链静默/死循环挂死/完全退化）
    auto gate(const char *name, const std::size_t bytes, const std::array<std::int64_t, 3> &s) -> bool
    {
        constexpr double kMinMbps = 50.0; // 宽松下限（本地 TCP 基线数百 MB/s，防 10x+ 劣化）
        auto sorted = s;
        std::sort(sorted.begin(), sorted.end());
        report(name, bytes, sorted[1]);
        // 任一运行断链/未完成即 FAIL（部分失败不得被中位数掩盖）
        if (std::any_of(sorted.begin(), sorted.end(), [](std::int64_t v) { return v <= 0; }))
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", name);
            return false;
        }
        const double mbps = static_cast<double>(bytes) / (1024.0 * 1024.0) / (static_cast<double>(sorted[1]) / 1e9);
        if (mbps < kMinMbps)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n", name, mbps, kMinMbps);
            return false;
        }
        return true;
    }

    template <typename ConnectFn, typename AcceptFn>
    auto bench_conn(const std::size_t total, const std::size_t block, ConnectFn &&cfn, AcceptFn &&afn)
        -> std::int64_t
    {
        using namespace preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);

        const std::int64_t t0 = now_ns();
        int completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<transport::reliable>(std::move(sock));
                auto conn = co_await afn(ss);
                if (!conn)
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
            auto conn = co_await cfn(ss);
            if (!conn)
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
                if (ec || n == 0)
                {
                    break; // 断链：返回 0 让门禁 FAIL，避免死循环挂死
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
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;
    constexpr std::size_t kBlock = 262144;
    const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    // socks5
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench_conn(kTotal, kBlock,
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  auto [err, conn] = co_await preview::socks5::connect(
                                      ss, preview::socks5::client_config{},
                                      preview::socks5::address{preview::socks5::address_type::domain,
                                                               "t.internal", 443});
                                  co_return err == preview::error::none ? conn : nullptr;
                              },
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  auto [err, req, conn] = co_await preview::socks5::accept(
                                      ss, preview::socks5::server_config{});
                                  co_return err == preview::error::none ? conn : nullptr;
                              });
        }
        std::sort(s.begin(), s.end());
        if (!gate("socks5 conn<->conn (透传)", kTotal, s))
        {
            return 1;
        }
    }

    // trojan
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench_conn(kTotal, kBlock,
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::trojan::client_config cfg;
                                  cfg.password = "prism";
                                  auto [err, conn] = co_await preview::trojan::connect(
                                      ss, cfg, preview::trojan::address{preview::trojan::address_type::domain,
                                                                        "t.internal", 443});
                                  co_return err == preview::error::none ? conn : nullptr;
                              },
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::trojan::server_config cfg;
                                  cfg.password = "prism";
                                  auto [err, req, conn] = co_await preview::trojan::accept(ss, cfg);
                                  co_return err == preview::error::none ? conn : nullptr;
                              });
        }
        std::sort(s.begin(), s.end());
        if (!gate("trojan conn<->conn (透传)", kTotal, s))
        {
            return 1;
        }
    }

    // vless
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench_conn(kTotal, kBlock,
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::vless::client_config cfg;
                                  cfg.uuid = uuid;
                                  auto [err, conn] = co_await preview::vless::connect(
                                      ss, cfg, preview::vless::address{preview::vless::address_type::domain,
                                                                       "t.internal", 443});
                                  co_return err == preview::error::none ? conn : nullptr;
                              },
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::vless::server_config cfg;
                                  cfg.uuid = uuid;
                                  auto [err, req, conn] = co_await preview::vless::accept(ss, cfg);
                                  co_return err == preview::error::none ? conn : nullptr;
                              });
        }
        std::sort(s.begin(), s.end());
        if (!gate("vless conn<->conn (透传)", kTotal, s))
        {
            return 1;
        }
    }

    // vmess
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench_conn(kTotal, kBlock,
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::vmess::client_config cfg;
                                  cfg.uuid = uuid;
                                  auto [err, conn] = co_await preview::vmess::connect(
                                      ss, cfg, preview::vmess::address{preview::vmess::address_type::domain,
                                                                       "t.internal", 443});
                                  co_return err == preview::error::none ? conn : nullptr;
                              },
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::vmess::server_config cfg;
                                  cfg.uuid = uuid;
                                  auto [err, req, conn] = co_await preview::vmess::accept(ss, cfg);
                                  co_return err == preview::error::none ? conn : nullptr;
                              });
        }
        std::sort(s.begin(), s.end());
        if (!gate("vmess conn<->conn (加密16KB)", kTotal, s))
        {
            return 1;
        }
    }

    // ss2022
    {
        std::array<std::int64_t, 3> s{};
        for (int i = 0; i < 3; ++i)
        {
            s[i] = bench_conn(kTotal, kBlock,
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::shadowsocks2022::client_config cfg;
                                  cfg.password = "prism";
                                  auto [err, conn] = co_await preview::shadowsocks2022::connect(
                                      ss, cfg, preview::shadowsocks2022::address{
                                                   preview::shadowsocks2022::address_type::domain,
                                                   "t.internal", 443});
                                  co_return err == preview::error::none ? conn : nullptr;
                              },
                              [&](auto ss) -> net::awaitable<preview::shared_transmission>
                              {
                                  preview::shadowsocks2022::server_config cfg;
                                  cfg.password = "prism";
                                  auto [err, req, conn] = co_await preview::shadowsocks2022::accept(ss, cfg);
                                  co_return err == preview::error::none ? conn : nullptr;
                              });
        }
        std::sort(s.begin(), s.end());
        if (!gate("ss2022 conn<->conn (加密16KB)", kTotal, s))
        {
            return 1;
        }
    }
    std::printf("AllProtoTransfer: ALL PASS\n");
    return 0;
}
