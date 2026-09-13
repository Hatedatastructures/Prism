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
#include <stdexcept>
#include <string>
#include <vector>

#include <preview/Transport/Reliable.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Anytls/Anytls.hpp>
#include <preview/Protocols/Gun/Gun.hpp>
#include <preview/Protocols/Reality/Reality.hpp>
#include <preview/Protocols/Restls/Restls.hpp>
#include <preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Anytls = Preview::Anytls;
    namespace Gun = Preview::Gun;
    namespace Reality = Preview::Reality;
    namespace Restls = Preview::Restls;
    namespace Shadowtls = Preview::Shadowtls;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Trusttunnel = Preview::Trusttunnel;
    namespace Vless = Preview::Vless;
    namespace Ws = Preview::Ws;
    namespace Transport = Preview::Transport;
    using Preview::Error;
    using Preview::SharedTransmission;

    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockBytes = 64 * 1024;

    /// 建立 TCP loopback socket 对
    auto MakeTcpPair(Net::any_io_executor ex) -> Net::awaitable<std::pair<Transport::Reliable, Transport::Reliable>>
    {
        Net::ip::tcp::acceptor acceptor(ex, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Transport::Reliable Client(ex);
        boost::system::error_code cec;
        co_await Client.Connect(acceptor.local_endpoint(), std::chrono::milliseconds{5000});
        Transport::Reliable Server(ex);
        boost::system::error_code aec;
        co_await acceptor.async_accept(Server.NativeSocket(), Net::redirect_error(Net::use_awaitable, aec));
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

    template <typename Connection>
    auto ToTransmission(Error ErrorCode, Connection ConnectionValue) -> SharedTransmission
    {
        if (ErrorCode == Error::None)
        {
            return SharedTransmission(std::move(ConnectionValue));
        }
        return {};
    }

    /// 纯传输测试：预生成数据块重复发送，Server 只读丢弃
    template <typename Factory>
    auto RunCase(Factory factory, const char *Name) -> Result
    {
        auto res = std::make_shared<Result>();
        Net::io_context ioc;

        // watchdog：60s 强制终止
        Net::steady_timer watchdog(ioc.get_executor());
        watchdog.expires_after(std::chrono::seconds(60));
        Net::co_spawn(
            ioc.get_executor(),
            [&, res]() -> Net::awaitable<void>
            {
                boost::system::error_code ec;
                co_await watchdog.async_wait(Net::redirect_error(Net::use_awaitable, ec));
                res->timeout = true;
                ioc.stop();
            },
            Net::detached);

        std::exception_ptr ep;
        Net::co_spawn(
            ioc,
            [&, res, factory]() mutable -> Net::awaitable<void>
            {
                try
                {
                    auto [ca, sa] = co_await MakeTcpPair(ioc.get_executor());
                    auto client_raw = std::make_shared<Preview::Transport::Reliable>(std::move(ca));
                    auto server_raw = std::make_shared<Preview::Transport::Reliable>(std::move(sa));

                    // 服务端 detached：伪装 Accept → 内层 Accept → 读 256MB 丢弃
                    auto server_f = factory;
                    auto server_done = std::make_shared<std::atomic<bool>>(false);
                    Net::co_spawn(
                        ioc.get_executor(),
                        [server_raw, server_f, res, server_done]() mutable -> Net::awaitable<void>
                        {
                            auto [serr, sconn] = co_await server_f.ServerAccept(std::move(server_raw));
                            if (serr != Error::None || !sconn)
                            {
                                res->timeout = true;
                                server_done->store(true);
                                co_return;
                            }
                            auto [verr, Inner] = co_await server_f.ServerInner(std::move(sconn));
                            if (verr != Error::None || !Inner)
                            {
                                res->timeout = true;
                                server_done->store(true);
                                co_return;
                            }
                            res->linked = true;
                            std::vector<std::uint8_t> buf(BlockBytes);
                            std::size_t got = 0;
                            while (got < TotalBytes)
                            {
                                std::error_code ec;
                                const auto n = co_await Inner->async_read_some(
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
                        Net::detached);

                    // 客户端：伪装 Connect → 内层 Connect → 发送预生成数据块
                    auto [cerr, cconn] = co_await factory.ClientConnect(std::move(client_raw));
                    if (cerr != Error::None || !cconn)
                    {
                        res->timeout = true;
                        co_return;
                    }
                    auto [herr, cli] = co_await factory.ClientInner(std::move(cconn));
                    if (herr != Error::None || !cli)
                    {
                        res->timeout = true;
                        co_return;
                    }

                    // 预生成一个数据块（一次，无逐字节开销）
                    std::vector<std::uint8_t> payload(BlockBytes, 0x5A);

                    const auto t0 = std::chrono::steady_clock::now();
                    std::size_t sent = 0;
                    std::size_t yield_cnt = 0;
                    while (sent < TotalBytes)
                    {
                        std::error_code ec;
                        const auto n = co_await cli->async_write_some(
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
                            co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                        }
                    }
                    const auto t1 = std::chrono::steady_clock::now();
                    double Seconds = std::chrono::duration<double>(t1 - t0).count();
                    if (Seconds <= 0)
                    {
                        Seconds = 1e-9;
                    }
                    res->mbps = static_cast<double>(sent) / (1024.0 * 1024.0) / Seconds;
                    cli->Close();
                    while (!server_done->load() && !res->timeout)
                    {
                        co_await Net::post(ioc.get_executor(), Net::use_awaitable);
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

    struct InnerVless
    {
        auto ServerInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Vless::Accept(std::move(s), Vless::ServerConfig{uuid});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Vless::Connect(std::move(s), Vless::ClientConfig{uuid}, dst);
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        std::array<std::uint8_t, 16> uuid{};
        Vless::Address dst{};
    };

    struct InnerTrojan
    {
        auto ServerInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Trojan::Accept(std::move(s), Trojan::ServerConfig{"pw"});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Trojan::Address dst{};
            dst.Type = Trojan::AddressType::Ipv4;
            dst.Host = "93.184.216.34";
            dst.Port = 443;
            auto [err, c] = co_await Trojan::Connect(std::move(s), Trojan::ClientConfig{"pw"}, dst);
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct InnerSocks5
    {
        auto ServerInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, req, c] = co_await Socks5::Accept(std::move(s), Socks5::ServerConfig{});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Socks5::Address dst{};
            dst.Type = Socks5::AddressType::Ipv4;
            dst.Host = "93.184.216.34";
            dst.Port = 443;
            auto [err, c] = co_await Socks5::Connect(std::move(s), Socks5::ClientConfig{}, dst);
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    // ============ 伪装层工厂 ============

    struct DirectFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            co_return std::pair{Error::None, std::move(up)};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            co_return std::pair{Error::None, std::move(up)};
        }
    };

    struct ShadowtlsFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Shadowtls::Accept(std::move(up), Shadowtls::ServerConfig{"st"});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            std::array<std::uint8_t, 32> cr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
                cr[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            auto [err, c] =
                co_await Shadowtls::Connect({std::move(up), Shadowtls::ClientConfig{"st"}, sr, cr});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct AnytlsFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Accept(std::move(up), Anytls::ServerConfig{"at"});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Anytls::Connect(std::move(up), Anytls::ClientConfig{"at"});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct TrusttunnelFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, t, c] =
                co_await Trusttunnel::Accept(std::move(up), Trusttunnel::ServerConfig{"u", "p"});
            (void)t;
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Trusttunnel::Connect(
                {std::move(up), Trusttunnel::ClientConfig{"u", "p"}, "example.com", 443});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct WsFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, k, c] = co_await Ws::Accept(std::move(up), Ws::ServerConfig{});
            (void)k;
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Ws::Connect(std::move(up), Ws::ClientConfig{"example.com"});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct GunFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, h, c] = co_await Gun::Accept(std::move(up));
            (void)h;
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [err, c] = co_await Gun::Connect(std::move(up), "example.com");
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct RealityFactory
    {
        std::array<std::uint8_t, Reality::KeyLen> srv_priv{};
        std::array<std::uint8_t, Reality::KeyLen> srv_pub{};
        std::array<std::uint8_t, Reality::KeyLen> cli_priv{};
        std::array<std::uint8_t, Reality::KeyLen> cli_pub{};
        std::array<std::uint8_t, 40> random{};
        std::array<std::uint8_t, 128> hello{};

        RealityFactory()
        {
            if (Reality::GenerateKeypair(srv_priv, srv_pub))
            {
                throw std::runtime_error("Reality server key generation failed");
            }
            if (Reality::GenerateKeypair(cli_priv, cli_pub))
            {
                throw std::runtime_error("Reality client key generation failed");
            }
            for (std::size_t i = 0; i < random.size(); ++i)
            {
                random[i] = static_cast<std::uint8_t>(i * 5 + 2);
            }
            for (std::size_t i = 0; i < hello.size(); ++i)
            {
                hello[i] = static_cast<std::uint8_t>(i);
            }
        }
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ServerConfig cfg;
            cfg.private_key = srv_priv;
            cfg.ShortId.fill(0x42);
            auto [err, sid, c] = co_await Reality::Accept(
                {std::move(up), cfg, cli_pub, Reality::HandshakeParams{random, hello}});
            (void)sid;
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ClientConfig cfg;
            cfg.private_key = cli_priv;
            cfg.ShortId.fill(0x42);
            auto [err, c] = co_await Reality::Connect(
                {std::move(up), cfg, srv_pub, Reality::HandshakeParams{random, hello, cfg.ShortId}});
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    struct RestlsFactory
    {
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
            }
            auto [err, c] = co_await Restls::Accept(std::move(up), Restls::ServerConfig{"rs"}, sr);
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            std::array<std::uint8_t, 32> sr{};
            for (std::size_t i = 0; i < 32; ++i)
            {
                sr[i] = static_cast<std::uint8_t>(i * 3 + 1);
            }
            auto [err, c] = co_await Restls::Connect(std::move(up), Restls::ClientConfig{"rs"}, sr);
            co_return std::pair{err, ToTransmission(err, std::move(c))};
        }
    };

    // ============ 组合体与测试 ============

    template <typename F, typename I>
    struct Combo
    {
        F stealth;
        I Inner;
        auto ServerAccept(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return stealth.ServerAccept(std::move(up));
        }
        auto ClientConnect(SharedTransmission up) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return stealth.ClientConnect(std::move(up));
        }
        auto ServerInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return Inner.ServerInner(std::move(s));
        }
        auto ClientInner(SharedTransmission s) -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            return Inner.ClientInner(std::move(s));
        }
    };

    inline auto MakeVlessInner() -> InnerVless
    {
        InnerVless in;
        in.uuid.fill(0x55);
        in.dst.Type = Vless::AddressType::Ipv4;
        in.dst.Host = "93.184.216.34";
        in.dst.Port = 443;
        return in;
    }
    inline auto MakeTrojanInner() -> InnerTrojan
    {
        return {};
    }
    inline auto MakeSocks5Inner() -> InnerSocks5
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
        auto r = RunCase(Combo<S, I>{stealth, Inner}, Label);                                               \
        std::printf("%-18s linked=%d mbps=%.1f Bytes=%zu timeout=%d\n", Label, r.linked, r.mbps, r.Bytes,    \
                    r.timeout);                                                                              \
        EXPECT_TRUE(r.linked) << Label << " 联通失败";                                                       \
    }

    DEFINE_COMBO_TEST(DirectVless, DirectFactory{}, MakeVlessInner(), "direct+vless")
    DEFINE_COMBO_TEST(DirectTrojan, DirectFactory{}, MakeTrojanInner(), "direct+trojan")
    DEFINE_COMBO_TEST(DirectSocks5, DirectFactory{}, MakeSocks5Inner(), "direct+socks5")
    DEFINE_COMBO_TEST(ShadowTlsVless, ShadowtlsFactory{}, MakeVlessInner(), "shadowtls+vless")
    DEFINE_COMBO_TEST(RestlsVless, RestlsFactory{}, MakeVlessInner(), "restls+vless")
    DEFINE_COMBO_TEST(AnyTlsVless, AnytlsFactory{}, MakeVlessInner(), "anytls+vless")
    DEFINE_COMBO_TEST(TrustTunnelVless, TrusttunnelFactory{}, MakeVlessInner(), "trusttunnel+vless")
    DEFINE_COMBO_TEST(WsVless, WsFactory{}, MakeVlessInner(), "ws+vless")
    DEFINE_COMBO_TEST(GunVless, GunFactory{}, MakeVlessInner(), "gun+vless")
    DEFINE_COMBO_TEST(RealityVless, RealityFactory{}, MakeVlessInner(), "reality+vless")
    DEFINE_COMBO_TEST(ShadowTlsTrojan, ShadowtlsFactory{}, MakeTrojanInner(), "shadowtls+trojan")
    DEFINE_COMBO_TEST(RestlsTrojan, RestlsFactory{}, MakeTrojanInner(), "restls+trojan")
    DEFINE_COMBO_TEST(AnyTlsTrojan, AnytlsFactory{}, MakeTrojanInner(), "anytls+trojan")
    DEFINE_COMBO_TEST(TrustTunnelTrojan, TrusttunnelFactory{}, MakeTrojanInner(), "trusttunnel+trojan")
    DEFINE_COMBO_TEST(WsTrojan, WsFactory{}, MakeTrojanInner(), "ws+trojan")
    DEFINE_COMBO_TEST(GunTrojan, GunFactory{}, MakeTrojanInner(), "gun+trojan")
    DEFINE_COMBO_TEST(RealityTrojan, RealityFactory{}, MakeTrojanInner(), "reality+trojan")
    DEFINE_COMBO_TEST(ShadowTlsSocks5, ShadowtlsFactory{}, MakeSocks5Inner(), "shadowtls+socks5")
    DEFINE_COMBO_TEST(RestlsSocks5, RestlsFactory{}, MakeSocks5Inner(), "restls+socks5")
    DEFINE_COMBO_TEST(AnyTlsSocks5, AnytlsFactory{}, MakeSocks5Inner(), "anytls+socks5")
    DEFINE_COMBO_TEST(TrustTunnelSocks5, TrusttunnelFactory{}, MakeSocks5Inner(), "trusttunnel+socks5")
    DEFINE_COMBO_TEST(WsSocks5, WsFactory{}, MakeSocks5Inner(), "ws+socks5")
    DEFINE_COMBO_TEST(GunSocks5, GunFactory{}, MakeSocks5Inner(), "gun+socks5")
    DEFINE_COMBO_TEST(RealitySocks5, RealityFactory{}, MakeSocks5Inner(), "reality+socks5")

} // namespace
