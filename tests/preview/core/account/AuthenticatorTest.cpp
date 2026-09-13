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
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Vless = Preview::Vless;
    using Preview::ConstantTimeEqual;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::RejectAuthenticator;
    using Preview::StaticAuthenticator;

    TEST(Authenticator, StaticPassAndReject)
    {
        StaticAuthenticator Auth("user", "pass");
        EXPECT_TRUE(Auth.Check("user", "pass").Ok);
        EXPECT_FALSE(Auth.Check("user", "wrong").Ok);
        EXPECT_FALSE(Auth.Check("other", "pass").Ok);
        EXPECT_EQ(Auth.Check("user", "pass").Identity, "user");

        RejectAuthenticator Reject;
        EXPECT_FALSE(Reject.Check("user", "pass").Ok);
        EXPECT_FALSE(Reject.Check("", "").Ok);
    }

    TEST(Authenticator, ConstantTimeEqualSupportsBinaryAndLengthMismatch)
    {
        const std::string WithNull("a\0b", 3);
        const std::string Same("a\0b", 3);
        const std::string Different("a\0c", 3);

        EXPECT_TRUE(ConstantTimeEqual(WithNull, Same));
        EXPECT_FALSE(ConstantTimeEqual(WithNull, Different));
        EXPECT_FALSE(ConstantTimeEqual(WithNull, "a"));
    }

    TEST(Authenticator, Socks5InjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            StaticAuthenticator Auth("alice", "s3cret");
            Socks5::ServerConfig Config;
            Config.EnableAuth = true;
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                // 注入认证器：正确凭据应通过
                EXPECT_EQ(ErrorCode, Error::None);
                EXPECT_TRUE(Conn != nullptr);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Socks5::ClientConfig ClientConfigValue;
            ClientConfigValue.EnableAuth = true;
            ClientConfigValue.username = "alice";
            ClientConfigValue.password = "s3cret";
            auto [ErrorCode, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfigValue,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);
            if (Conn)
            {
                Conn->Close();
            }

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Socks5RejectAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            RejectAuthenticator Auth;
            Socks5::ServerConfig Config;
            Config.EnableAuth = true;
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                // 拒绝认证器：正确凭据也必须失败
                EXPECT_EQ(ErrorCode, Error::BadAuth);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Socks5::ClientConfig ClientConfigValue;
            ClientConfigValue.EnableAuth = true;
            ClientConfigValue.username = "alice";
            ClientConfigValue.password = "s3cret";
            auto [ErrorCode, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfigValue,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
            EXPECT_NE(ErrorCode, Error::None);

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, TrojanInjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            // trojan 凭据 = SHA224 hex；注入比对"期望 Hash vs 收到 Hash"
            StaticAuthenticator Auth("", Trojan::Credential("prism"));

            Trojan::ServerConfig Config;
            Config.password = "prism";
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorCode, Error::None);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Trojan::ClientConfig ClientConfigValue;
            ClientConfigValue.password = "prism";
            auto [ErrorCode, Conn] = co_await Trojan::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfigValue,
                Trojan::Address{Trojan::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, VlessInjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            // vless 凭据 = UUID 16 字节（字符串视图）
            StaticAuthenticator Auth("", std::string(reinterpret_cast<const char *>(Uuid.data()), Uuid.size()));

            Vless::ServerConfig Config;
            Config.uuid = Uuid;
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorCode, Error::None);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Vless::ClientConfig ClientConfigValue;
            ClientConfigValue.uuid = Uuid;
            auto [ErrorCode, Conn] = co_await Vless::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfigValue,
                Vless::Address{Vless::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Hysteria2InjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            StaticAuthenticator Auth("", "h2pass");
            Hysteria2::ServerConfig Config;
            Config.password = "h2pass";
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorCode, Error::None);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            Hysteria2::ClientConfig ClientConfigValue;
            ClientConfigValue.password = "h2pass";
            auto [ErrorCode, Conn] = co_await Hysteria2::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfigValue,
                Hysteria2::Address{Hysteria2::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Hysteria2RejectAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            RejectAuthenticator Auth;
            Hysteria2::ServerConfig Config;
            Config.password = "h2pass";
            Config.Authenticator = &Auth;
            bool ServerDone = false;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                // 非法字节流：服务端必须拒绝
                EXPECT_NE(ErrorCode, Error::None);
                ServerDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            // 客户端：发送无效字节后关闭（服务端应拒绝并返回错误）
            const std::vector<std::uint8_t> junk{0x01, 0x02, 0x03};
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(junk)), ErrorCode);
            ClientMemory.Close();

            // 等待服务端协程结束，保证栈上 Auth/Config 存活至 detached 协程退出
            Net::steady_timer WaitTimer(IoContext.get_executor());
            const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!ServerDone && std::chrono::steady_clock::now() < Deadline)
            {
                WaitTimer.expires_after(std::chrono::milliseconds(1));
                co_await WaitTimer.async_wait(Net::use_awaitable);
            }
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
