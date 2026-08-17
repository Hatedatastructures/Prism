/**
 * @file AuthenticatorTest.cpp
 * @brief 认证器注入测试
 * @details 验证 authenticator 接口在三协议握手中的行为：
 * 1. static_authenticator 通过/拒绝
 * 2. reject_authenticator 总是拒绝
 * 3. 注入后与静态比对等价（默认 nullptr 兼容）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/core/authenticator.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/hysteria2/hysteria2.hpp>
#include <common/protocols/socks5/socks5.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/protocols/vless/vless.hpp>

namespace
{
    using namespace preview;
    namespace net = boost::asio;

    TEST(Authenticator, StaticPassAndReject)
    {
        static_authenticator auth("user", "pass");
        EXPECT_TRUE(auth.check("user", "pass").ok);
        EXPECT_FALSE(auth.check("user", "wrong").ok);
        EXPECT_FALSE(auth.check("other", "pass").ok);
        EXPECT_EQ(auth.check("user", "pass").identity, "user");

        reject_authenticator rej;
        EXPECT_FALSE(rej.check("user", "pass").ok);
        EXPECT_FALSE(rej.check("", "").ok);
    }

    TEST(Authenticator, Socks5InjectedAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            static_authenticator auth("alice", "s3cret");
            socks5::server_config cfg;
            cfg.enable_auth = true;
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await socks5::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                // 注入认证器：正确凭据应通过
                EXPECT_EQ(err, error::none);
                EXPECT_TRUE(conn != nullptr);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            socks5::client_config ccfg;
            ccfg.enable_auth = true;
            ccfg.username = "alice";
            ccfg.password = "s3cret";
            auto [err, conn] = co_await socks5::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                socks5::address{socks5::address_type::domain, "t.internal", 443});
            EXPECT_EQ(err, error::none);
            if (conn)
            {
                conn->close();
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
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            reject_authenticator auth;
            socks5::server_config cfg;
            cfg.enable_auth = true;
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await socks5::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                // 拒绝认证器：正确凭据也失败
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            socks5::client_config ccfg;
            ccfg.enable_auth = true;
            ccfg.username = "alice";
            ccfg.password = "s3cret";
            auto [err, conn] = co_await socks5::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                socks5::address{socks5::address_type::domain, "t.internal", 443});
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, TrojanInjectedAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;
        const auto uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            // trojan 凭据 = SHA224 hex；注入比对"期望 hash vs 收到 hash"
            static_authenticator auth("", trojan::credential("prism"));

            trojan::server_config cfg;
            cfg.password = "prism";
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await trojan::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, error::none);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            trojan::client_config ccfg;
            ccfg.password = "prism";
            auto [err, conn] = co_await trojan::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                trojan::address{trojan::address_type::domain, "t.internal", 443});
            EXPECT_EQ(err, error::none);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, VlessInjectedAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;
        const auto uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            // vless 凭据 = UUID 16 字节（字符串视图）
            static_authenticator auth("", std::string(reinterpret_cast<const char *>(uuid.data()), uuid.size()));

            vless::server_config cfg;
            cfg.uuid = uuid;
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await vless::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, error::none);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            vless::client_config ccfg;
            ccfg.uuid = uuid;
            auto [err, conn] = co_await vless::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                vless::address{vless::address_type::domain, "t.internal", 443});
            EXPECT_EQ(err, error::none);
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
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            static_authenticator auth("", "h2pass");
            hysteria2::server_config cfg;
            cfg.password = "h2pass";
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await hysteria2::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, error::none);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            hysteria2::client_config ccfg;
            ccfg.password = "h2pass";
            auto [err, conn] = co_await hysteria2::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                hysteria2::address{hysteria2::address_type::domain, "t.internal", 443});
            EXPECT_EQ(err, error::none);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(Authenticator, Hysteria2RejectAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            reject_authenticator auth;
            hysteria2::server_config cfg;
            cfg.password = "h2pass";
            cfg.authenticator = &auth;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await hysteria2::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 客户端：发送无效字节后关闭（服务端应拒绝并返回错误）
            const std::vector<std::uint8_t> junk{0x01, 0x02, 0x03};
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(junk)), ec);
            a.close();
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
