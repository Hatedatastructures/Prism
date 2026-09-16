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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>

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

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct ServerWaitState
    {
        explicit ServerWaitState(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        std::exception_ptr Failure;
        Error ErrorCode{Error::IoError};
        bool HasConnection{false};
    };

    struct ServerWaitRequest
    {
        std::shared_ptr<ServerWaitState> State;
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto StartServer(Net::any_io_executor Executor, Net::awaitable<void> Server,
                     const std::shared_ptr<ServerWaitState> &State) -> void
    {
        auto Completion = [State](std::exception_ptr Failure) -> void
        {
            State->Failure = std::move(Failure);
            (void)State->Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, std::move(Server), std::move(Completion));
    }

    auto WaitForServer(ServerWaitRequest Request) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        auto Completion = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                                    Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return true;
        }

        Request.Client->Close();
        Request.Server->Close();
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                               Watchdog.async_wait(Net::use_awaitable));
        co_return Grace.index() == 0U;
    }

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

    TEST(Authenticator, DirectoryRequestReturnsTypedLease)
    {
        using Preview::Account::AccountDirectory;
        using Preview::Account::AccountRecord;
        using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::AccountId;

        const auto Record = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7001},
            .CredentialValue = Credential::Password("typed-password"),
            .Quota = {.MaxConnections = 1}});
        AccountDirectory Directory;
        ASSERT_TRUE(Directory.Upsert(Record));

        Preview::DirectoryAuthenticator Auth(&Directory);
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = "alice",
            .Credential = CredentialView::Password("typed-password"),
            .Rate = {}});

        static_assert(std::is_same_v<decltype(Result.Lease), Preview::Account::AccountLease>);
        ASSERT_TRUE(Result.Accepted);
        EXPECT_EQ(Result.AccountId, AccountId{7001});
        EXPECT_TRUE(Result.Lease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        Result.Lease.Release();
        Result.Lease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Authenticator, CallbackCannotAcceptWithoutTypedLease)
    {
        using Preview::Account::AuthenticationRequest;
        using Preview::Account::Authenticator;
        using Preview::Account::AuthenticatorCallback;
        using Preview::Account::CredentialView;

        Authenticator Auth(AuthenticatorCallback{[](const AuthenticationRequest &)
                                                 {
                                                     return Preview::Account::AuthenticationResult{
                                                         true,
                                                         Preview::AccountId{7099},
                                                         {},
                                                         Preview::Account::AuthFailure::None};
                                                 }});

        const auto Result = Auth.Authenticate(
            AuthenticationRequest{CredentialView::Password("accepted-without-lease"), {}});

        EXPECT_FALSE(Result.Accepted);
        EXPECT_EQ(Result.Failure, Preview::Account::AuthFailure::Unavailable);
        EXPECT_FALSE(Result.Lease);
    }

    TEST(Authenticator, TypedResultRejectsAuthenticatedResultWithoutLease)
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(Net::system_executor());
        (void)ClientMemory;

        Preview::Runtime::Handler::AcceptResult Result;
        Result.Transmission = std::make_shared<MemoryStream>(std::move(ServerMemory));
        Result.ProtocolAuthenticated = true;
        Result.AccountLeaseRequired = true;
        Result.identity = "credential-secret-must-not-escape";

        auto Typed = Preview::Composition::Adapters::ToTypedResult(std::move(Result));

        EXPECT_EQ(Typed.Status, Error::BadAuth);
        EXPECT_FALSE(Typed.Data.IsValid());
        EXPECT_TRUE(Typed.identity.empty());
        EXPECT_FALSE(Typed.AccountLease);
    }

    TEST(Authenticator, DirectoryAcceptsProtocolCredentialViews)
    {
        using Preview::Account::AccountDirectory;
        using Preview::Account::AccountRecord;
        using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::AccountId;

        const std::array<std::byte, 16> UuidBytes{
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
            std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
            std::byte{0x18}, std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B},
            std::byte{0x1C}, std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}};
        const auto PasswordRecord = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7011},
            .CredentialValue = Credential::Password("socks5-password")});
        const auto UuidRecord = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7012},
            .CredentialValue = Credential::Uuid(UuidBytes)});
        const auto PskRecord = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7013},
            .CredentialValue = Credential::Psk("ss2022-psk")});
        const auto TokenRecord = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7014},
            .CredentialValue = Credential::Token("trojan-token")});
        const auto ExtensionRecord = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = AccountId{7015},
            .CredentialValue = Credential::Extension("extension-token")});
        AccountDirectory Directory;
        ASSERT_TRUE(Directory.Upsert(PasswordRecord));
        ASSERT_TRUE(Directory.Upsert(UuidRecord));
        ASSERT_TRUE(Directory.Upsert(PskRecord));
        ASSERT_TRUE(Directory.Upsert(TokenRecord));
        ASSERT_TRUE(Directory.Upsert(ExtensionRecord));
        Preview::DirectoryAuthenticator Auth(&Directory);

        const auto Check = [&Auth](CredentialView CredentialValue, AccountId ExpectedId)
        {
            auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
                .AccountId = {},
                .Identity = "wire-user",
                .Credential = CredentialValue,
                .Rate = {}});
            EXPECT_TRUE(Result.Accepted);
            EXPECT_EQ(Result.AccountId, ExpectedId);
            EXPECT_TRUE(Result.Lease);
            Result.Lease.Release();
            Result.Lease.Release();
        };
        Check(CredentialView::Password("socks5-password"), AccountId{7011});
        Check(CredentialView::Uuid(UuidBytes), AccountId{7012});
        Check(CredentialView::Psk("ss2022-psk"), AccountId{7013});
        Check(CredentialView::Token("trojan-token"), AccountId{7014});
        Check(CredentialView::Extension("extension-token"), AccountId{7015});

        const auto Invalid = [&Auth](CredentialView CredentialValue)
        {
            const auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
                .AccountId = {},
                .Identity = {},
                .Credential = CredentialValue,
                .Rate = {}});
            EXPECT_FALSE(Result.Accepted);
            EXPECT_EQ(Result.Failure, Preview::AuthFailure::InvalidCredential);
        };
        Invalid(CredentialView::Password(""));
        Invalid(CredentialView::Psk(""));
        Invalid(CredentialView::Token(""));
        Invalid(CredentialView::Extension(""));
        Invalid(CredentialView{});
    }

    TEST(Authenticator, ProtocolBridgeUsesTypedDirectoryAndRejectsLegacyCheck)
    {
        using Preview::Account::AccountDirectory;
        using Preview::Account::AccountRecord;
        using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::Account::ProtocolAuthenticator;

        auto Directory = std::make_shared<AccountDirectory>();
        const auto Record = std::make_shared<const AccountRecord>(AccountRecord::CreateRequest{
            .AccountId = Preview::AccountId{7020},
            .CredentialValue = Credential::Extension("typed-extension")});
        ASSERT_TRUE(Directory->Upsert(Record));

        ProtocolAuthenticator Auth(Directory);
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = "non-secret-identity",
            .Credential = CredentialView::Extension("typed-extension"),
            .Rate = {}});

        ASSERT_TRUE(Result.Accepted);
        EXPECT_EQ(Result.AccountId, Preview::AccountId{7020});
        EXPECT_EQ(Result.Identity, "non-secret-identity");
        EXPECT_TRUE(Result.Lease);
        EXPECT_FALSE(Auth.Check("non-secret-identity", "typed-extension").Ok);
        Result.Lease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);

        std::vector<Preview::AccountId> AccountIds;
        Directory->ForEach([&AccountIds](const auto &Entry)
        {
            AccountIds.push_back(Entry->AccountId());
        });
        ASSERT_EQ(AccountIds.size(), 1U);
        EXPECT_EQ(AccountIds.front(), Preview::AccountId{7020});
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");
            auto Config = std::make_shared<Socks5::ServerConfig>();
            Config->EnableAuth = true;
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            Socks5::ClientConfig ClientConfigValue;
            ClientConfigValue.EnableAuth = true;
            ClientConfigValue.username = "alice";
            ClientConfigValue.password = "s3cret";
            auto [ErrorCode, Conn] = co_await Socks5::Connect(
                Client, ClientConfigValue,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);
            if (Conn)
            {
                Conn->Close();
            }

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_EQ(State->ErrorCode, Error::None);
            EXPECT_TRUE(State->HasConnection);
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<RejectAuthenticator>();
            auto Config = std::make_shared<Socks5::ServerConfig>();
            Config->EnableAuth = true;
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            Socks5::ClientConfig ClientConfigValue;
            ClientConfigValue.EnableAuth = true;
            ClientConfigValue.username = "alice";
            ClientConfigValue.password = "s3cret";
            auto [ErrorCode, Conn] = co_await Socks5::Connect(
                Client, ClientConfigValue,
                Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
            EXPECT_NE(ErrorCode, Error::None);

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_EQ(State->ErrorCode, Error::BadAuth);
            EXPECT_FALSE(State->HasConnection);
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<StaticAuthenticator>("", Trojan::Credential("prism"));
            auto Config = std::make_shared<Trojan::ServerConfig>();
            Config->password = "prism";
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Trojan::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            Trojan::ClientConfig ClientConfigValue;
            ClientConfigValue.password = "prism";
            auto [ErrorCode, Conn] = co_await Trojan::Connect(
                Client, ClientConfigValue,
                Trojan::Address{Trojan::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_EQ(State->ErrorCode, Error::None);
            EXPECT_TRUE(State->HasConnection);
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<StaticAuthenticator>(
                "", std::string(reinterpret_cast<const char *>(Uuid.data()), Uuid.size()));
            auto Config = std::make_shared<Vless::ServerConfig>();
            Config->uuid = Uuid;
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Vless::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            Vless::ClientConfig ClientConfigValue;
            ClientConfigValue.uuid = Uuid;
            auto [ErrorCode, Conn] = co_await Vless::Connect(
                Client, ClientConfigValue,
                Vless::Address{Vless::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_EQ(State->ErrorCode, Error::None);
            EXPECT_TRUE(State->HasConnection);
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<StaticAuthenticator>("", "h2pass");
            auto Config = std::make_shared<Hysteria2::ServerConfig>();
            Config->password = "h2pass";
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            Hysteria2::ClientConfig ClientConfigValue;
            ClientConfigValue.password = "h2pass";
            auto [ErrorCode, Conn] = co_await Hysteria2::Connect(
                Client, ClientConfigValue,
                Hysteria2::Address{Hysteria2::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(ErrorCode, Error::None);

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_EQ(State->ErrorCode, Error::None);
            EXPECT_TRUE(State->HasConnection);
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
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto Auth = std::make_shared<RejectAuthenticator>();
            auto Config = std::make_shared<Hysteria2::ServerConfig>();
            Config->password = "h2pass";
            Config->Authenticator = Auth.get();

            auto ServerCoroutine = [Server, State, Auth, Config]() -> Net::awaitable<void>
            {
                auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
                State->ErrorCode = ErrorCode;
                State->HasConnection = Conn != nullptr;
            };
            StartServer(IoContext.get_executor(), ServerCoroutine(), State);

            // 客户端：发送无效字节后关闭（服务端应拒绝并返回错误）
            const std::vector<std::uint8_t> junk{0x01, 0x02, 0x03};
            std::error_code ErrorCode;
            const auto JunkBytes = AsBytes(std::span<const std::uint8_t>(junk));
            co_await Client->async_write_some(JunkBytes, ErrorCode);
            Client->Close();

            const auto Completed = co_await WaitForServer({State, Client, Server});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_NE(State->ErrorCode, Error::None);
            EXPECT_FALSE(State->HasConnection);
        }, [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
