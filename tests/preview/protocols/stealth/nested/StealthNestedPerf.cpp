/**
 * @file StealthNestedPerf.cpp
 * @brief TLS 伪装方案 + 内层代理协议组合测试（联通性 + 数据一致性 + 性能）
 * @details 外层伪装（shadowtls/restls/anytls/trusttunnel/ws/gun/reality）
 *          内层套 vless/trojan/socks5：验证多层套接的正确性与开销。
 *          每用例：双端握手 → 64MB 传输 → Hash 一致性 → 吞吐/延迟。
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

#include <common/Bench/Bench.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>
#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <common/Protocols/Anytls/Anytls.hpp>
#include <common/Protocols/Gun/Gun.hpp>
#include <common/Protocols/Reality/Reality.hpp>
#include <common/Protocols/Restls/Restls.hpp>
#include <common/Protocols/Shadowtls/Shadowtls.hpp>
#include <common/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <common/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
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

    auto make_dst() -> Vless::Address
    {
        Vless::Address dst{};
        dst.Type = Vless::AddressType::Ipv4;
        dst.Host = "93.184.216.34";
        dst.Port = 443;
        return dst;
    }

    auto make_uuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> u{};
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
     * @tparam Factory 伪装层工厂（提供 Connect/Accept，接收 SharedTransmission）
     * @param Name 方案名（打印用）
     * @details 结构：memory_pair → 伪装 Conn 对 → vless Conn 对 → 64MB 传输
     */
    template <typename Factory>
    auto run_nested_vless(net::io_context &ioc, Factory factory, const char *Name) -> void
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        constexpr std::size_t kTotal = 64 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;

        BenchReport tp{};
        bool linked = false;
        bool Failed = false;

        // 全局超时：10s 强制终止，防止任何挂起
        net::steady_timer watchdog(ioc.get_executor());
        watchdog.expires_after(std::chrono::seconds(10));
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                boost::system::error_code ec;
                co_await watchdog.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (!Failed && tp.Bytes == 0)
                {
                    EXPECT_TRUE(false) << Name << ": 超时（10s 无结果）";
                    ioc.stop();
                }
            },
            net::detached);

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                // 服务端：伪装层 Accept → vless Accept
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [serr, sconn] =
                        co_await factory.server_accept(std::make_shared<MemoryStream>(std::move(b)));
                    if (serr != Error::none || !sconn)
                    {
                        EXPECT_TRUE(false)
                            << Name << ": stealth Accept Failed err=" << static_cast<int>(serr);
                        Failed = true;
                        ioc.stop();
                        co_return;
                    }
                    auto [verr, req, vconn] =
                        co_await Vless::Accept(std::move(sconn), Vless::ServerConfig{make_uuid()});
                    if (verr != Error::none || !vconn)
                    {
                        EXPECT_TRUE(false) << Name << ": vless Accept Failed";
                        Failed = true;
                        ioc.stop();
                        co_return;
                    }
                    linked = true;
                    // 回显
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await vconn->AsyncReadSome(buf, ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        ec.clear();
                        (void)co_await vconn->AsyncWriteSome(std::span(buf.data(), n), ec);
                    }
                    vconn->Close();
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                // 客户端：伪装层 Connect → vless Connect
                auto [cerr, cconn] =
                    co_await factory.client_connect(std::make_shared<MemoryStream>(std::move(a)));
                if (cerr != Error::none || !cconn)
                {
                    EXPECT_TRUE(false) << Name << ": stealth Connect Failed err=" << static_cast<int>(cerr);
                    Failed = true;
                    ioc.stop();
                    co_return;
                }
                auto [herr, cli] =
                    co_await Vless::Connect(std::move(cconn), Vless::ClientConfig{make_uuid()}, make_dst());
                if (herr != Error::none || !cli)
                {
                    EXPECT_TRUE(false) << Name << ": vless Connect Failed err=" << static_cast<int>(herr);
                    Failed = true;
                    ioc.stop();
                    co_return;
                }
                BenchOptions opt;
                opt.Total = kTotal;
                opt.block = kBlock;
                tp = co_await BenchThroughputTx(*cli, *cli, opt);
                cli->Close();
            });

        // 联通性 + 一致性
        if (!Failed)
        {
            EXPECT_TRUE(linked) << Name << ": 双层握手联通失败";
            EXPECT_EQ(tp.Bytes, kTotal) << Name << ": 传输字节数不一致";
        }
        std::printf("%-12s 联通=%s  Bytes=%zu(期望 %zu)  吞吐=%.1f MB/s  延迟(ms) avg=%.3f p50=%.3f p95=%.3f "
                    "p99=%.3f\n",
                    Name, (linked && !Failed) ? "OK" : "FAIL", tp.Bytes, kTotal, tp.mbps, tp.LatencyAvg,
                    tp.LatencyP50, tp.LatencyP95, tp.LatencyP99);
    }

    // ---------- 各伪装层工厂 ----------

    struct shadowtls_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto sr = make_random32();
            const auto cr = make_random32();
            auto [err, c] =
                co_await Shadowtls::Connect(std::move(up), Shadowtls::ClientConfig{"st_password"}, sr, cr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] =
                co_await Shadowtls::Accept(std::move(up), Shadowtls::ServerConfig{"st_password"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct restls_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto sr = make_random32();
            auto [err, c] = co_await Restls::Connect(std::move(up), Restls::ClientConfig{"rs_password"}, sr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto sr = make_random32();
            auto [err, c] = co_await Restls::Accept(std::move(up), Restls::ServerConfig{"rs_password"}, sr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct anytls_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Connect(std::move(up), Anytls::ClientConfig{"at_password"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Accept(std::move(up), Anytls::ServerConfig{"at_password"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct trusttunnel_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Trusttunnel::Connect(
                std::move(up), Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, Target, c] =
                co_await Trusttunnel::Accept(std::move(up), Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
            (void)Target;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct ws_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Ws::Connect(std::move(up), Ws::ClientConfig{"example.com"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, key, c] = co_await Ws::Accept(std::move(up), Ws::ServerConfig{});
            (void)key;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct gun_factory
    {
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Gun::Connect(std::move(up), "example.com");
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, host, c] = co_await Gun::Accept(std::move(up));
            (void)host;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct reality_factory
    {
        // 共享密钥对（客户端持 cli 私钥，服务端持 srv 私钥）
        std::array<std::uint8_t, Reality::KeyLen> srv_priv{};
        std::array<std::uint8_t, Reality::KeyLen> srv_pub{};
        std::array<std::uint8_t, Reality::KeyLen> cli_priv{};
        std::array<std::uint8_t, Reality::KeyLen> cli_pub{};
        std::array<std::uint8_t, 40> random{};
        std::array<std::uint8_t, 128> hello{};

        reality_factory()
        {
            EXPECT_FALSE(Reality::GenerateKeypair(srv_priv, srv_pub));
            EXPECT_FALSE(Reality::GenerateKeypair(cli_priv, cli_pub));
            for (std::size_t i = 0; i < random.size(); ++i)
            {
                random[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            for (std::size_t i = 0; i < hello.size(); ++i)
            {
                hello[i] = static_cast<std::uint8_t>(i);
            }
        }

        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ClientConfig cfg;
            cfg.private_key = cli_priv;
            cfg.short_id.fill(0x42);
            auto [err, c] = co_await Reality::Connect(std::move(up), cfg, srv_pub,
                                                      Reality::HandshakeParams{random, hello, cfg.short_id});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ServerConfig cfg;
            cfg.private_key = srv_priv;
            cfg.short_id.fill(0x42);
            auto [err, got_sid, c] = co_await Reality::Accept(std::move(up), cfg, cli_pub,
                                                              Reality::HandshakeParams{random, hello});
            (void)got_sid;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
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
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::string Target;
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, t, c] =
                             co_await Trusttunnel::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                          Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
                         if (err != Error::none)
                         {
                             EXPECT_TRUE(false) << "Accept err=" << static_cast<int>(err);
                             ioc.stop();
                             co_return;
                         }
                         Target = t;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);
                     auto [cerr, c] = co_await Trusttunnel::Connect(
                         std::make_shared<MemoryStream>(std::move(a)),
                         Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443);
                     if (cerr != Error::none)
                     {
                         EXPECT_TRUE(false) << "Connect err=" << static_cast<int>(cerr);
                         co_return;
                     }
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(Target, "example.com");
                     c->Close();
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
