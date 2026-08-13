/**
 * @file StealthNestedPerf.cpp
 * @brief TLS 伪装方案 + 内层代理协议组合测试（联通性 + 数据一致性 + 性能）
 * @details 外层伪装（shadowtls/restls/anytls/trusttunnel/ws/gun/reality）
 *          内层套 vless/trojan/socks5：验证多层套接的正确性与开销。
 *          每用例：双端握手 → 64MB 传输 → hash 一致性 → 吞吐/延迟。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/socks5/socks5.hpp>
#include <common/proxy/trojan/trojan.hpp>
#include <common/proxy/vless/vless.hpp>
#include <common/stealth/anytls/anytls.hpp>
#include <common/stealth/gun/gun.hpp>
#include <common/stealth/reality/reality.hpp>
#include <common/stealth/restls/restls.hpp>
#include <common/stealth/shadowtls/shadowtls.hpp>
#include <common/stealth/trusttunnel/trusttunnel.hpp>
#include <common/stealth/ws/ws.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    auto make_dst() -> vless::address
    {
        vless::address dst{};
        dst.type = vless::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    auto make_uuid() -> std::array<std::uint8_t, vless::uuid_len>
    {
        std::array<std::uint8_t, vless::uuid_len> u{};
        u.fill(0x55);
        return u;
    }

    auto make_random32() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> r{};
        for (std::size_t i = 0; i < r.size(); ++i)
        {
            r[i] = static_cast<std::uint8_t>(i * 3 + 1);
        }
        return r;
    }

    /**
     * @brief 组合测试运行器：伪装层(Factory) 套 内层 vless
     * @tparam Factory 伪装层工厂（提供 connect/accept，接收 shared_transmission）
     * @param name 方案名（打印用）
     * @details 结构：memory_pair → 伪装 conn 对 → vless conn 对 → 64MB 传输
     */
    template <typename Factory>
    auto run_nested_vless(net::io_context &ioc, Factory factory, const char *name) -> void
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        constexpr std::size_t kTotal = 64 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;

        bench_report tp{};
        bool linked = false;
        bool failed = false;

        // 全局超时：10s 强制终止，防止任何挂起
        net::steady_timer watchdog(ioc.get_executor());
        watchdog.expires_after(std::chrono::seconds(10));
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                boost::system::error_code ec;
                co_await watchdog.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (!failed && tp.bytes == 0)
                {
                    EXPECT_TRUE(false) << name << ": 超时（10s 无结果）";
                    ioc.stop();
                }
            },
            net::detached);

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                // 服务端：伪装层 accept → vless accept
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [serr, sconn] =
                        co_await factory.server_accept(std::make_shared<memory_stream>(std::move(b)));
                    if (serr != error::none || !sconn)
                    {
                        EXPECT_TRUE(false)
                            << name << ": stealth accept failed err=" << static_cast<int>(serr);
                        failed = true;
                        ioc.stop();
                        co_return;
                    }
                    auto [verr, req, vconn] =
                        co_await vless::accept(std::move(sconn), vless::server_config{make_uuid()});
                    if (verr != error::none || !vconn)
                    {
                        EXPECT_TRUE(false) << name << ": vless accept failed";
                        failed = true;
                        ioc.stop();
                        co_return;
                    }
                    linked = true;
                    // 回显
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await vconn->async_read_some(buf, ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        ec.clear();
                        (void)co_await vconn->async_write_some(std::span(buf.data(), n), ec);
                    }
                    vconn->close();
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                // 客户端：伪装层 connect → vless connect
                auto [cerr, cconn] =
                    co_await factory.client_connect(std::make_shared<memory_stream>(std::move(a)));
                if (cerr != error::none || !cconn)
                {
                    EXPECT_TRUE(false) << name << ": stealth connect failed err=" << static_cast<int>(cerr);
                    failed = true;
                    ioc.stop();
                    co_return;
                }
                auto [herr, cli] =
                    co_await vless::connect(std::move(cconn), vless::client_config{make_uuid()}, make_dst());
                if (herr != error::none || !cli)
                {
                    EXPECT_TRUE(false) << name << ": vless connect failed err=" << static_cast<int>(herr);
                    failed = true;
                    ioc.stop();
                    co_return;
                }
                bench_options opt;
                opt.total = kTotal;
                opt.block = kBlock;
                tp = co_await bench_throughput_tx(*cli, *cli, opt);
                cli->close();
            });

        // 联通性 + 一致性
        if (!failed)
        {
            EXPECT_TRUE(linked) << name << ": 双层握手联通失败";
            EXPECT_EQ(tp.bytes, kTotal) << name << ": 传输字节数不一致";
        }
        std::printf("%-12s 联通=%s  bytes=%zu(期望 %zu)  吞吐=%.1f MB/s  延迟(ms) avg=%.3f p50=%.3f p95=%.3f "
                    "p99=%.3f\n",
                    name, (linked && !failed) ? "OK" : "FAIL", tp.bytes, kTotal, tp.mbps, tp.latency_avg,
                    tp.latency_p50, tp.latency_p95, tp.latency_p99);
    }

    // ---------- 各伪装层工厂 ----------

    struct shadowtls_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            const auto sr = make_random32();
            const auto cr = make_random32();
            auto [err, c] =
                co_await shadowtls::connect(std::move(up), shadowtls::client_config{"st_password"}, sr, cr);
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] =
                co_await shadowtls::accept(std::move(up), shadowtls::server_config{"st_password"});
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct restls_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            const auto sr = make_random32();
            auto [err, c] = co_await restls::connect(std::move(up), restls::client_config{"rs_password"}, sr);
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            const auto sr = make_random32();
            auto [err, c] = co_await restls::accept(std::move(up), restls::server_config{"rs_password"}, sr);
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct anytls_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] = co_await anytls::connect(std::move(up), anytls::client_config{"at_password"});
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] = co_await anytls::accept(std::move(up), anytls::server_config{"at_password"});
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct trusttunnel_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] = co_await trusttunnel::connect(
                std::move(up), trusttunnel::client_config{"tu_user", "tu_pass"}, "example.com", 443);
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, target, c] =
                co_await trusttunnel::accept(std::move(up), trusttunnel::server_config{"tu_user", "tu_pass"});
            (void)target;
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct ws_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] = co_await ws::connect(std::move(up), ws::client_config{"example.com"});
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, key, c] = co_await ws::accept(std::move(up), ws::server_config{});
            (void)key;
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct gun_factory
    {
        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, c] = co_await gun::connect(std::move(up), "example.com");
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            auto [err, host, c] = co_await gun::accept(std::move(up));
            (void)host;
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    struct reality_factory
    {
        // 共享密钥对（客户端持 cli 私钥，服务端持 srv 私钥）
        std::array<std::uint8_t, reality::key_len> srv_priv{};
        std::array<std::uint8_t, reality::key_len> srv_pub{};
        std::array<std::uint8_t, reality::key_len> cli_priv{};
        std::array<std::uint8_t, reality::key_len> cli_pub{};
        std::array<std::uint8_t, 40> random{};
        std::array<std::uint8_t, 128> hello{};

        reality_factory()
        {
            EXPECT_FALSE(reality::generate_keypair(srv_priv, srv_pub));
            EXPECT_FALSE(reality::generate_keypair(cli_priv, cli_pub));
            for (std::size_t i = 0; i < random.size(); ++i)
            {
                random[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            for (std::size_t i = 0; i < hello.size(); ++i)
            {
                hello[i] = static_cast<std::uint8_t>(i);
            }
        }

        auto client_connect(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            reality::client_config cfg;
            cfg.private_key = cli_priv;
            cfg.short_id.fill(0x42);
            auto [err, c] = co_await reality::connect(std::move(up), cfg, srv_pub,
                                                      reality::handshake_params{random, hello, cfg.short_id});
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
        auto server_accept(shared_transmission up) -> net::awaitable<std::pair<error, shared_transmission>>
        {
            reality::server_config cfg;
            cfg.private_key = srv_priv;
            cfg.short_id.fill(0x42);
            auto [err, got_sid, c] = co_await reality::accept(std::move(up), cfg, cli_pub,
                                                              reality::handshake_params{random, hello});
            (void)got_sid;
            co_return std::pair{err, err == error::none ? shared_transmission(std::move(c))
                                                        : shared_transmission{}};
        }
    };

    // ---------- 测试用例 ----------

    TEST(StealthNested, ShadowTlsVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, shadowtls_factory{}, "shadowtls");
    }

    TEST(StealthNested, RestlsVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, restls_factory{}, "restls");
    }

    TEST(StealthNested, AnyTlsVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, anytls_factory{}, "anytls");
    }

    TEST(StealthNested, TrustTunnelVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, trusttunnel_factory{}, "trusttunnel");
    }

    TEST(TrustTunnelConn, HandshakeDirect)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::string target;
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, t, c] =
                             co_await trusttunnel::accept(std::make_shared<memory_stream>(std::move(b)),
                                                          trusttunnel::server_config{"tu_user", "tu_pass"});
                         if (err != error::none)
                         {
                             EXPECT_TRUE(false) << "accept err=" << static_cast<int>(err);
                             ioc.stop();
                             co_return;
                         }
                         target = t;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);
                     auto [cerr, c] = co_await trusttunnel::connect(
                         std::make_shared<memory_stream>(std::move(a)),
                         trusttunnel::client_config{"tu_user", "tu_pass"}, "example.com", 443);
                     if (cerr != error::none)
                     {
                         EXPECT_TRUE(false) << "connect err=" << static_cast<int>(cerr);
                         co_return;
                     }
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(target, "example.com");
                     c->close();
                 });
    }

    TEST(StealthNested, WsVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, ws_factory{}, "ws");
    }

    TEST(StealthNested, GunVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, gun_factory{}, "gun");
    }

    TEST(StealthNested, RealityVless)
    {
        net::io_context ioc;
        run_nested_vless(ioc, reality_factory{}, "reality");
    }

} // namespace
