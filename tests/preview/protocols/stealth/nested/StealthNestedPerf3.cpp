/**
 * @file StealthNestedPerf3.cpp
 * @brief TLS 伪装 + 内层协议纯传输速度测试（v3，无 Hash/生成开销）
 * @details 上一版 Hash 验证已证明数据一致性。本版专注纯传输速率：
 *          预生成数据块（一次生成，重复发送），Server 只读丢弃。
 *          测量真实 TCP + 伪装层 + 内层协议的裸吞吐。
 *          对照：纯 TCP 基线 / 内层直连 / 伪装+内层。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/Reliable.hpp>
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

    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;
    constexpr std::size_t kBlock = 64 * 1024;

    /// 建立 TCP loopback socket 对
    auto make_tcp_pair(net::any_io_executor ex) -> net::awaitable<std::pair<Transport::Reliable, Transport::Reliable>>
    {
        net::ip::tcp::acceptor acceptor(ex, net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
        Transport::Reliable Client(ex);
        boost::system::error_code cec;
        co_await Client.Connect(acceptor.local_endpoint(), std::chrono::milliseconds{5000});
        Transport::Reliable Server(ex);
        boost::system::error_code aec;
        co_await acceptor.async_accept(Server.NativeSocket(), net::redirect_error(net::use_awaitable, aec));
        co_return std::make_pair(std::move(Client), std::move(Server));
    }

    /// 结果
    struct Result
    {
        bool linked{false};   ///< 双端联通
        std::size_t Bytes{0}; ///< 实际传输字节
        double mbps{0};       ///< 吞吐
        bool timeout{false};  ///< 超时
    };

    /// 纯传输测试：预生成数据块重复发送，Server 只读丢弃
    template <typename Factory>
    auto run_case(Factory factory, const char *Name) -> Result
    {
        auto res = std::make_shared<Result>();
        net::io_context ioc;

        // watchdog：60s 强制终止
        net::steady_timer watchdog(ioc.get_executor());
        watchdog.expires_after(std::chrono::seconds(60));
        net::co_spawn(
            ioc.get_executor(),
            [&, res]() -> net::awaitable<void>
            {
                boost::system::error_code ec;
                co_await watchdog.async_wait(net::redirect_error(net::use_awaitable, ec));
                res->timeout = true;
                ioc.stop();
            },
            net::detached);

        std::exception_ptr ep;
        net::co_spawn(
            ioc,
            [&, res, factory]() mutable -> net::awaitable<void>
            {
                try
                {
                    auto [ca, sa] = co_await make_tcp_pair(ioc.get_executor());
                    auto client_raw = std::make_shared<Preview::Transport::Reliable>(std::move(ca));
                    auto server_raw = std::make_shared<Preview::Transport::Reliable>(std::move(sa));

                    // 服务端 detached：伪装 Accept → 内层 Accept → 读 256MB 丢弃
                    auto server_f = factory;
                    auto server_done = std::make_shared<std::atomic<bool>>(false);
                    net::co_spawn(
                        ioc.get_executor(),
                        [server_raw, server_f, res, server_done]() mutable -> net::awaitable<void>
                        {
                            auto [serr, sconn] = co_await server_f.server_accept(std::move(server_raw));
                            if (serr != Error::none || !sconn)
                            {
                                res->timeout = true;
                                server_done->store(true);
                                co_return;
                            }
                            auto [verr, Inner] = co_await server_f.server_inner(std::move(sconn));
                            if (verr != Error::none || !Inner)
                            {
                                res->timeout = true;
                                server_done->store(true);
                                co_return;
                            }
                            res->linked = true;
                            std::vector<std::uint8_t> buf(kBlock);
                            std::size_t got = 0;
                            while (got < kTotal)
                            {
                                std::error_code ec;
                                const auto n = co_await Inner->AsyncReadSome(
                                    std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()),
                                                         buf.size()),
                                    ec);
                                if (ec || n == 0)
                                {
                                    break;
                                }
                                got += n;
                            }
                            res->Bytes = got;
                            Inner->Close();
                            server_done->store(true);
                        },
                        net::detached);

                    // 客户端：伪装 Connect → 内层 Connect → 发送预生成数据块
                    auto [cerr, cconn] = co_await factory.client_connect(std::move(client_raw));
                    if (cerr != Error::none || !cconn)
                    {
                        res->timeout = true;
                        co_return;
                    }
                    auto [herr, cli] = co_await factory.client_inner(std::move(cconn));
                    if (herr != Error::none || !cli)
                    {
                        res->timeout = true;
                        co_return;
                    }

                    // 预生成一个数据块（一次，无逐字节开销）
                    std::vector<std::uint8_t> payload(kBlock, 0x5A);

                    const auto t0 = std::chrono::steady_clock::now();
                    std::size_t sent = 0;
                    std::size_t yield_cnt = 0;
                    while (sent < kTotal)
                    {
                        std::error_code ec;
                        const auto n = co_await cli->AsyncWriteSome(
                            std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                       payload.size()),
                            ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        sent += n;
                        if ((++yield_cnt & 0x0F) == 0)
                        {
                            co_await net::post(ioc.get_executor(), net::use_awaitable);
                        }
                    }
                    const auto t1 = std::chrono::steady_clock::now();
                    const double sec = std::chrono::duration<double>(t1 - t0).count();
                    res->mbps = static_cast<double>(sent) / (1024.0 * 1024.0) / (sec > 0 ? sec : 1e-9);
                    cli->Close();
                    while (!server_done->load() && !res->timeout)
                    {
                        co_await net::post(ioc.get_executor(), net::use_awaitable);
                    }
                }
                catch (const std::exception &e)
                {
                    res->timeout = true;
                }
            },
            [&](std::exception_ptr e)
            {
                ep = e;
                ioc.stop();
            });

        ioc.run();
        (void)ep;
        return *res;
    }

    // ============ 内层协议适配 ============

    struct inner_vless
    {
        auto server_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Vless::Accept(std::move(s), Vless::ServerConfig{uuid});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Vless::Connect(std::move(s), Vless::ClientConfig{uuid}, dst);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        std::array<std::uint8_t, 16> uuid{};
        Vless::Address dst{};
    };

    struct inner_trojan
    {
        auto server_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Trojan::Accept(std::move(s), Trojan::ServerConfig{"pw"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Trojan::Address dst{};
            dst.Type = Trojan::AddressType::Ipv4;
            dst.Host = "93.184.216.34";
            dst.Port = 443;
            auto [err, c] = co_await Trojan::Connect(std::move(s), Trojan::ClientConfig{"pw"}, dst);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct inner_socks5
    {
        auto server_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Socks5::Accept(std::move(s), Socks5::ServerConfig{});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Socks5::Address dst{};
            dst.Type = Socks5::AddressType::Ipv4;
            dst.Host = "93.184.216.34";
            dst.Port = 443;
            auto [err, c] = co_await Socks5::Connect(std::move(s), Socks5::ClientConfig{}, dst);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    // ============ 伪装层工厂 ============

    struct direct_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            co_return std::pair{Error::none, std::move(up)};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            co_return std::pair{Error::none, std::move(up)};
        }
    };

    struct shadowtls_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Shadowtls::Accept(std::move(up), Shadowtls::ServerConfig{"st"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            std::array<std::uint8_t, 32> cr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
                cr[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            auto [err, c] =
                co_await Shadowtls::Connect(std::move(up), Shadowtls::ClientConfig{"st"}, sr, cr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct anytls_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Accept(std::move(up), Anytls::ServerConfig{"at"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Connect(std::move(up), Anytls::ClientConfig{"at"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct trusttunnel_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, t, c] =
                co_await Trusttunnel::Accept(std::move(up), Trusttunnel::ServerConfig{"u", "p"});
            (void)t;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Trusttunnel::Connect(std::move(up), Trusttunnel::ClientConfig{"u", "p"},
                                                          "example.com", 443);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct ws_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, k, c] = co_await Ws::Accept(std::move(up), Ws::ServerConfig{});
            (void)k;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Ws::Connect(std::move(up), Ws::ClientConfig{"example.com"});
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct gun_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, h, c] = co_await Gun::Accept(std::move(up));
            (void)h;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Gun::Connect(std::move(up), "example.com");
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    struct reality_factory
    {
        std::array<std::uint8_t, Reality::KeyLen> srv_priv{};
        std::array<std::uint8_t, Reality::KeyLen> srv_pub{};
        std::array<std::uint8_t, Reality::KeyLen> cli_priv{};
        std::array<std::uint8_t, Reality::KeyLen> cli_pub{};
        std::array<std::uint8_t, 40> random{};
        std::array<std::uint8_t, 128> hello{};

        reality_factory()
        {
            Reality::GenerateKeypair(srv_priv, srv_pub);
            Reality::GenerateKeypair(cli_priv, cli_pub);
            for (std::size_t i = 0; i < random.size(); ++i)
            {
                random[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            for (std::size_t i = 0; i < hello.size(); ++i)
            {
                hello[i] = static_cast<std::uint8_t>(i);
            }
        }
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ServerConfig cfg;
            cfg.private_key = srv_priv;
            cfg.short_id.fill(0x42);
            auto [err, sid, c] = co_await Reality::Accept(std::move(up), cfg, cli_pub,
                                                          Reality::HandshakeParams{random, hello});
            (void)sid;
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
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
    };

    struct restls_factory
    {
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
            }
            auto [err, c] = co_await Restls::Accept(std::move(up), Restls::ServerConfig{"rs"}, sr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
            }
            auto [err, c] = co_await Restls::Connect(std::move(up), Restls::ClientConfig{"rs"}, sr);
            co_return std::pair{err, err == Error::none ? SharedTransmission(std::move(c))
                                                        : SharedTransmission{}};
        }
    };

    // ============ 组合体与测试 ============

    template <typename F, typename I>
    struct combo
    {
        F stealth;
        I Inner;
        auto server_accept(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return stealth.server_accept(std::move(up));
        }
        auto client_connect(SharedTransmission up) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return stealth.client_connect(std::move(up));
        }
        auto server_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return Inner.server_inner(std::move(s));
        }
        auto client_inner(SharedTransmission s) -> net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return Inner.client_inner(std::move(s));
        }
    };

    inline auto make_vless_inner() -> inner_vless
    {
        inner_vless in;
        in.uuid.fill(0x55);
        in.dst.Type = Vless::AddressType::Ipv4;
        in.dst.Host = "93.184.216.34";
        in.dst.Port = 443;
        return in;
    }
    inline auto make_trojan_inner() -> inner_trojan
    {
        return {};
    }
    inline auto make_socks5_inner() -> inner_socks5
    {
        return {};
    }

#define DEFINE_COMBO_TEST(TestName, FactoryVar, InnerExpr, Label)                                            \
    TEST(StealthNested3, TestName)                                                                           \
    {                                                                                                        \
        auto stealth = FactoryVar;                                                                           \
        auto Inner = InnerExpr;                                                                              \
        using S = decltype(stealth);                                                                         \
        using I = decltype(Inner);                                                                           \
        auto r = run_case(combo<S, I>{stealth, Inner}, Label);                                               \
        std::printf("%-18s linked=%d mbps=%.1f Bytes=%zu timeout=%d\n", Label, r.linked, r.mbps, r.Bytes,    \
                    r.timeout);                                                                              \
        EXPECT_TRUE(r.linked) << Label << " 联通失败";                                                       \
    }

    DEFINE_COMBO_TEST(DirectVless, direct_factory{}, make_vless_inner(), "direct+vless")
    DEFINE_COMBO_TEST(DirectTrojan, direct_factory{}, make_trojan_inner(), "direct+trojan")
    DEFINE_COMBO_TEST(DirectSocks5, direct_factory{}, make_socks5_inner(), "direct+socks5")
    DEFINE_COMBO_TEST(ShadowTlsVless, shadowtls_factory{}, make_vless_inner(), "shadowtls+vless")
    DEFINE_COMBO_TEST(RestlsVless, restls_factory{}, make_vless_inner(), "restls+vless")
    DEFINE_COMBO_TEST(AnyTlsVless, anytls_factory{}, make_vless_inner(), "anytls+vless")
    DEFINE_COMBO_TEST(TrustTunnelVless, trusttunnel_factory{}, make_vless_inner(), "trusttunnel+vless")
    DEFINE_COMBO_TEST(WsVless, ws_factory{}, make_vless_inner(), "ws+vless")
    DEFINE_COMBO_TEST(GunVless, gun_factory{}, make_vless_inner(), "gun+vless")
    DEFINE_COMBO_TEST(RealityVless, reality_factory{}, make_vless_inner(), "reality+vless")
    DEFINE_COMBO_TEST(ShadowTlsTrojan, shadowtls_factory{}, make_trojan_inner(), "shadowtls+trojan")
    DEFINE_COMBO_TEST(RestlsTrojan, restls_factory{}, make_trojan_inner(), "restls+trojan")
    DEFINE_COMBO_TEST(AnyTlsTrojan, anytls_factory{}, make_trojan_inner(), "anytls+trojan")
    DEFINE_COMBO_TEST(TrustTunnelTrojan, trusttunnel_factory{}, make_trojan_inner(), "trusttunnel+trojan")
    DEFINE_COMBO_TEST(WsTrojan, ws_factory{}, make_trojan_inner(), "ws+trojan")
    DEFINE_COMBO_TEST(GunTrojan, gun_factory{}, make_trojan_inner(), "gun+trojan")
    DEFINE_COMBO_TEST(RealityTrojan, reality_factory{}, make_trojan_inner(), "reality+trojan")
    DEFINE_COMBO_TEST(ShadowTlsSocks5, shadowtls_factory{}, make_socks5_inner(), "shadowtls+socks5")
    DEFINE_COMBO_TEST(RestlsSocks5, restls_factory{}, make_socks5_inner(), "restls+socks5")
    DEFINE_COMBO_TEST(AnyTlsSocks5, anytls_factory{}, make_socks5_inner(), "anytls+socks5")
    DEFINE_COMBO_TEST(TrustTunnelSocks5, trusttunnel_factory{}, make_socks5_inner(), "trusttunnel+socks5")
    DEFINE_COMBO_TEST(WsSocks5, ws_factory{}, make_socks5_inner(), "ws+socks5")
    DEFINE_COMBO_TEST(GunSocks5, gun_factory{}, make_socks5_inner(), "gun+socks5")
    DEFINE_COMBO_TEST(RealitySocks5, reality_factory{}, make_socks5_inner(), "reality+socks5")

} // namespace
