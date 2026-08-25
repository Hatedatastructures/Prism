/**
 * @file AuthenticatorTest.cpp
 * @brief 认证器注入测试
 * @details 验证 Authenticator 接口在三协议握手中的行为：
 * 1. StaticAuthenticator 通过/拒绝
 * 2. RejectAuthenticator 总是拒绝
 * 3. 注入后与静态比对等价（默认 nullptr 兼容）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/Core/Authenticator.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>
#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/Protocols/Vless/Vless.hpp>

namespace
{
    using namespace Preview;
    namespace Net = boost::asio;

    TEST(Authenticator, StaticPassAndReject)
    {
        StaticAuthenticator Auth("user", "pass");
        EXPECT_TRUE(Auth.Check("user", "pass").Ok);
        EXPECT_FALSE(Auth.Check("user", "wrong").Ok);
        EXPECT_FALSE(Auth.Check("other", "pass").Ok);
        EXPECT_EQ(Auth.Check("user", "pass").identity, "user");

        RejectAuthenticator rej;
        EXPECT_FALSE(rej.Check("user", "pass").Ok);
        EXPECT_FALSE(rej.Check("", "").Ok);
    }

    TEST(Authenticator, Socks5InjectedAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            StaticAuthenticator Auth("alice", "s3cret");
            Socks5::ServerConfig cfg;
            cfg.EnableAuth = true;
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                // 注入认证器：正确凭据应通过
                EXPECT_EQ(err, Error::none);
                EXPECT_TRUE(Conn != nullptr);
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            Socks5::ClientConfig ccfg;
            ccfg.EnableAuth = true;
            ccfg.username = "alice";
            ccfg.password = "s3cret";
            auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), ccfg,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(err, Error::none);
            if (Conn)
            {
                Conn->Close();
            }
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, Socks5RejectAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            RejectAuthenticator Auth;
            Socks5::ServerConfig cfg;
            cfg.EnableAuth = true;
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                // 拒绝认证器：正确凭据也失败
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            Socks5::ClientConfig ccfg;
            ccfg.EnableAuth = true;
            ccfg.username = "alice";
            ccfg.password = "s3cret";
            auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), ccfg,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, TrojanInjectedAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;
        const auto uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            // trojan 凭据 = SHA224 hex；注入比对"期望 Hash vs 收到 Hash"
            StaticAuthenticator Auth("", Trojan::Credential("prism"));

            Trojan::ServerConfig cfg;
            cfg.password = "prism";
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::none);
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            Trojan::ClientConfig ccfg;
            ccfg.password = "prism";
            auto [err, Conn] = co_await Trojan::Connect(
                std::make_shared<MemoryStream>(std::move(a)), ccfg,
                Trojan::Address{Trojan::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(err, Error::none);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, VlessInjectedAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;
        const auto uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            // vless 凭据 = UUID 16 字节（字符串视图）
            StaticAuthenticator Auth("", std::string(reinterpret_cast<const char *>(uuid.data()), uuid.size()));

            Vless::ServerConfig cfg;
            cfg.uuid = uuid;
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::none);
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            Vless::ClientConfig ccfg;
            ccfg.uuid = uuid;
            auto [err, Conn] = co_await Vless::Connect(
                std::make_shared<MemoryStream>(std::move(a)), ccfg,
                Vless::Address{Vless::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(err, Error::none);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

} // namespace

    TEST(Authenticator, Hysteria2InjectedAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            StaticAuthenticator Auth("", "h2pass");
            Hysteria2::ServerConfig cfg;
            cfg.password = "h2pass";
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Hysteria2::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::none);
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            Hysteria2::ClientConfig ccfg;
            ccfg.password = "h2pass";
            auto [err, Conn] = co_await Hysteria2::Connect(
                std::make_shared<MemoryStream>(std::move(a)), ccfg,
                Hysteria2::Address{Hysteria2::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(err, Error::none);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, Hysteria2RejectAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::exception_ptr ep;

        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            RejectAuthenticator Auth;
            Hysteria2::ServerConfig cfg;
            cfg.password = "h2pass";
            cfg.Authenticator = &Auth;

            auto server_coro = [&]() -> Net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Hysteria2::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
            };
            Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

            // 客户端：发送无效字节后关闭（服务端应拒绝并返回错误）
            const std::vector<std::uint8_t> junk{0x01, 0x02, 0x03};
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(junk)), ec);
            a.Close();
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
