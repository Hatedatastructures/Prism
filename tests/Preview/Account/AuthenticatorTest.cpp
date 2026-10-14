/**
 * @file AuthenticatorTest.cpp
 * @brief 认证器注入测试
 * @details 验证 Authenticator 接口在三协议握手中的行为：
 * 1. ProviderAccount 认证通过/拒绝
 * 2. RejectAuthenticator 总是拒绝
 * 3. 注入后与静态比对等价（默认 nullptr 兼容）
 */

#include <gtest/gtest.h>
#include <TestSupport/Preview/ProviderBindings.hpp>

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
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <Preview/Account/Account.hpp>
#include "AccountTestSupport.hpp"
#include <Preview/Account/Authenticator.hpp>
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
        std::optional<Preview::Fault::Failure> HandshakeFailure;
        bool HasConnection{false};
        std::shared_ptr<Preview::Transmission> ClientConnection;
        std::shared_ptr<Preview::Transmission> ServerConnection;
        std::optional<Preview::IoResult> ClientWriteResult;
        std::optional<Preview::Fault::Failure> CleanupFailure;
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
            if (!State->Done->try_send(boost::system::error_code{}) && !State->CleanupFailure)
            {
                State->CleanupFailure = Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            }
        };
        Net::co_spawn(Executor, std::move(Server), std::move(Completion));
    }

    /** @brief 记录一次控制命令或退栈失败的首个真实 typed cause。 */
    auto RecordCleanupFailure(const std::shared_ptr<ServerWaitState> &State,
                              const Preview::Fault::Failure Failure) -> void
    {
        if (!State->CleanupFailure)
        {
            State->CleanupFailure = Failure;
        }
    }

    /** @brief 保留关闭命令的失败，不把控制交付当作已忽略的成功。 */
    auto RecordCloseResult(const std::shared_ptr<ServerWaitState> &State,
                           const Preview::Transmission::ControlResult &Result) -> void
    {
        if (!Result)
        {
            RecordCleanupFailure(State, Result.error());
        }
    }

    /** @brief 先提交协议连接关闭，再等待它自己的真实 I/O completion 退栈。 */
    auto DrainConnection(const std::shared_ptr<ServerWaitState> &State,
                         const std::shared_ptr<Preview::Transmission> &Connection)
        -> Net::awaitable<void>
    {
        if (!Connection)
        {
            co_return;
        }
        const auto Closed = Connection->Close();
        RecordCloseResult(State, Closed);
        const auto Drained = co_await Connection->Activity()->Drain();
        if (!Drained)
        {
            RecordCleanupFailure(State, Drained.error());
        }
    }

    /** @brief 关闭一个底层 endpoint 并等待 MemoryStream 自身的控制与 I/O owner。 */
    auto DrainEndpoint(const std::shared_ptr<ServerWaitState> &State,
                       const std::shared_ptr<Preview::Transmission> &Connection,
                       const std::shared_ptr<MemoryStream> &Memory) -> Net::awaitable<void>
    {
        if (Connection)
        {
            co_await DrainConnection(State, Connection);
        }
        else
        {
            const auto Closed = Memory->Close();
            RecordCloseResult(State, Closed);
        }
        const auto Drained = co_await Memory->Activity()->Drain();
        if (!Drained)
        {
            RecordCleanupFailure(State, Drained.error());
        }
    }

    /** @brief 两端 protocol owner 与其底层 memory stream 都要真实退出。 */
    auto DrainServerWaitRequest(ServerWaitRequest Request) -> Net::awaitable<void>
    {
        co_await DrainEndpoint(Request.State, Request.State->ClientConnection, Request.Client);
        co_await DrainEndpoint(Request.State, Request.State->ServerConnection, Request.Server);
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
            co_await DrainServerWaitRequest(Request);
            EXPECT_FALSE(Request.State->CleanupFailure.has_value());
            co_return true;
        }

        const auto ClientClosed = Request.Client->Close();
        RecordCloseResult(Request.State, ClientClosed);
        const auto ServerClosed = Request.Server->Close();
        RecordCloseResult(Request.State, ServerClosed);
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                               Watchdog.async_wait(Net::use_awaitable));
        co_await DrainServerWaitRequest(Request);
        EXPECT_FALSE(Request.State->CleanupFailure.has_value());
        co_return Grace.index() == 0U;
    }

    auto AuthenticateCredential(
        const Preview::DirectoryAuthenticator &Auth,
        Preview::Account::CredentialView CredentialValue,
        const Preview::AccountId ExpectedId) -> void
    {
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {}, .Identity = "wire-user", .Credential = CredentialValue, .Rate = {}});
        EXPECT_TRUE(Result.has_value());
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->AccountId(), ExpectedId);
        EXPECT_TRUE(*Result);
        Result->Release();
        Result->Release();
    }

    auto RunSocks5InjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;
        auto Config = std::make_shared<Socks5::ServerConfig>();
        Config->EnableAuth = true;
        Config->Authenticator = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        Socks5::ClientConfig ClientConfigValue;
        ClientConfigValue.EnableAuth = true;
        ClientConfigValue.Username = "alice";
        ClientConfigValue.Password = "s3cret";
        auto [ErrorCode, Conn] = co_await Socks5::Connect(
            Client, ClientConfigValue,
            Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
        EXPECT_EQ(ErrorCode, Error::None);
        State->ClientConnection = Conn;
        if (Conn)
        {
            const auto Closed = Conn->Close();
            RecordCloseResult(State, Closed);
        }
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunSocks5RejectAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = std::make_shared<RejectAuthenticator>();
        auto Config = std::make_shared<Socks5::ServerConfig>();
        Config->EnableAuth = true;
        Config->Authenticator = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Socks5::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        Socks5::ClientConfig ClientConfigValue;
        ClientConfigValue.EnableAuth = true;
        ClientConfigValue.Username = "alice";
        ClientConfigValue.Password = "s3cret";
        auto [ErrorCode, Conn] = co_await Socks5::Connect(
            Client, ClientConfigValue,
            Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443});
        EXPECT_NE(ErrorCode, Error::None);
        State->ClientConnection = Conn;
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::BadAuth);
        EXPECT_FALSE(State->HasConnection);
    }

    auto AcceptTrojanAndRecord(
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State,
        std::shared_ptr<Trojan::ServerConfig> Config) -> Net::awaitable<void>
    {
        auto Result = co_await Trojan::Accept(std::move(Server), *Config);
        if (!Result)
        {
            State->HandshakeFailure = Result.error();
            co_return;
        }
        if (!Result->Connection)
        {
            State->HandshakeFailure = Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        State->ErrorCode = Error::None;
        State->HasConnection = true;
        State->ServerConnection = std::move(Result->Connection);
    }

    auto RunTrojanInjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Preview::Testing::ProviderAccount(Preview::Account::Credential::Token(Trojan::Credential("prism")), Preview::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Trojan::ServerConfig>();
        Config->Password = "prism";
        Config->AuthenticatorOwner = Auth;
        StartServer(Server->Executor(), AcceptTrojanAndRecord(Server, State, Config), State);

        Trojan::ClientConfig ClientConfigValue;
        ClientConfigValue.Password = "prism";
        auto ConnectResult = co_await Trojan::Connect(Trojan::ConnectParameters{
            Client, ClientConfigValue,
            Trojan::Address{Trojan::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (ConnectResult && *ConnectResult) State->ClientConnection = std::move(*ConnectResult);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto AcceptVlessAndRecord(
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State,
        std::shared_ptr<Vless::ServerConfig> Config) -> Net::awaitable<void>
    {
        auto Result = co_await Vless::Accept(std::move(Server), *Config);
        if (!Result)
        {
            State->HandshakeFailure = Result.error();
            co_return;
        }
        if (!Result->Connection)
        {
            State->HandshakeFailure = Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        State->ErrorCode = Error::None;
        State->HasConnection = true;
        State->ServerConnection = std::move(Result->Connection);
    }

    auto RunVlessInjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8,
                                                       9, 10, 11, 12, 13, 14, 15, 16};
        Preview::Account::UuidBytes CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        auto Auth = Preview::Testing::ProviderAccount(Preview::Account::Credential::Uuid(CredentialBytes), Preview::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Vless::ServerConfig>();
        Config->uuid = Uuid;
        Config->AuthenticatorOwner = Auth;
        StartServer(Server->Executor(), AcceptVlessAndRecord(Server, State, Config), State);

        Vless::ClientConfig ClientConfigValue;
        ClientConfigValue.uuid = Uuid;
        auto ConnectResult = co_await Vless::Connect(Vless::ConnectParameters{
            Client, ClientConfigValue,
            Vless::Address{Vless::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (ConnectResult && *ConnectResult) State->ClientConnection = std::move(*ConnectResult);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunHysteria2InjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Preview::Testing::ProviderAccount(Preview::Account::Credential::Token("h2pass"), Preview::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Hysteria2::ServerConfig>();
        Config->password = "h2pass";
        Config->AuthenticatorOwner = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        Hysteria2::ClientConfig ClientConfigValue;
        ClientConfigValue.password = "h2pass";
        auto [ErrorCode, Conn] = co_await Hysteria2::Connect(
            Client, ClientConfigValue,
            Hysteria2::Address{Hysteria2::AddressType::Domain, "t.internal", 443});
        EXPECT_EQ(ErrorCode, Error::None);
        State->ClientConnection = Conn;
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunHysteria2RejectAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = std::make_shared<RejectAuthenticator>();
        auto Config = std::make_shared<Hysteria2::ServerConfig>();
        Config->password = "h2pass";
        Config->AuthenticatorOwner = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        const std::vector<std::uint8_t> Junk{0x01, 0x02, 0x03};
        State->ClientWriteResult = co_await Client->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Junk)));
        const auto ClientClosed = Client->Close();
        RecordCloseResult(State, ClientClosed);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_NE(State->ErrorCode, Error::None);
        EXPECT_FALSE(State->HasConnection);
    }

    TEST(Authenticator, StaticPassAndReject)
    {
        using Preview::Account::CredentialView;
        const auto AuthOwner = Preview::Testing::ProviderAccount(
            Preview::Testing::ProviderAccountInput{Preview::AccountId{1U},
                Preview::Account::Credential::Password("pass"), "user", "user", {}});
        const auto& Auth = *AuthOwner->Authenticator;
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("pass")));
        EXPECT_FALSE(InspectMatch(Auth, CredentialView::Password("wrong")));
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .Identity = "user", .Credential = CredentialView::Password("pass")});
        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(*Result);
        Result->Release();
        EXPECT_FALSE(Auth.Authenticate(Preview::AuthenticationRequest{
            .Identity = "other", .Credential = CredentialView::Password("pass")}).has_value());

        RejectAuthenticator Reject;
        EXPECT_FALSE(InspectMatch(Reject, CredentialView::Password("pass")));
        EXPECT_FALSE(Reject.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView::Password("pass")}).has_value());
    }

    TEST(Authenticator, DirectoryRequestReturnsTypedLease)
    {
        using Preview::Account::AccountStore;
        using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::AccountId;

        const auto Record = MakeDefinition(AccountInput{
            .AccountId = AccountId{7001},
            .CredentialValue = Credential::Password("typed-password"),
            .Quota = {.MaxConnections = 1}});
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, Record));

        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = "alice",
            .Credential = CredentialView::Password("typed-password"),
            .Rate = {}});

        static_assert(std::is_same_v<std::remove_cvref_t<decltype(*Result)>, Preview::Account::AccountLease>);
        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result->AccountId(), AccountId{7001});
        EXPECT_TRUE(*Result);
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 1U);

        Result->Release();
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Authenticator, InspectDoesNotAcquireLease)
    {
        using Preview::Account::CredentialView;
        auto Directory = std::make_shared<Preview::Account::AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
                .AccountId = Preview::AccountId{7099},
                .CredentialValue = Preview::Account::Credential::Password("probe-only"),
                .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("probe-only")));
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Authenticator, DirectoryAcceptsProtocolCredentialViews)
    {
        using Preview::Account::AccountStore;
                using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::AccountId;

        const std::array<std::byte, 16> UuidBytes{
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
            std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
            std::byte{0x18}, std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B},
            std::byte{0x1C}, std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}};
        const auto PasswordRecord = MakeDefinition(AccountInput{
            .AccountId = AccountId{7011},
            .CredentialValue = Credential::Password("socks5-password")});
        const auto UuidRecord = MakeDefinition(AccountInput{
            .AccountId = AccountId{7012},
            .CredentialValue = Credential::Uuid(UuidBytes)});
        const auto PskRecord = MakeDefinition(AccountInput{
            .AccountId = AccountId{7013},
            .CredentialValue = Credential::Psk("ss2022-psk")});
        const auto TokenRecord = MakeDefinition(AccountInput{
            .AccountId = AccountId{7014},
            .CredentialValue = Credential::Token("trojan-token")});
        const auto ExtensionRecord = MakeDefinition(AccountInput{
            .AccountId = AccountId{7015},
            .CredentialValue = Credential::Extension("extension-token")});
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, PasswordRecord));
        ASSERT_TRUE(Publish(*Directory, UuidRecord));
        ASSERT_TRUE(Publish(*Directory, PskRecord));
        ASSERT_TRUE(Publish(*Directory, TokenRecord));
        ASSERT_TRUE(Publish(*Directory, ExtensionRecord));
        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));

        AuthenticateCredential(Auth, CredentialView::Password("socks5-password"), AccountId{7011});
        AuthenticateCredential(Auth, CredentialView::Uuid(UuidBytes), AccountId{7012});
        AuthenticateCredential(Auth, CredentialView::Psk("ss2022-psk"), AccountId{7013});
        AuthenticateCredential(Auth, CredentialView::Token("trojan-token"), AccountId{7014});
        AuthenticateCredential(Auth, CredentialView::Extension("extension-token"), AccountId{7015});

        VerifyInvalidCredential(Auth, CredentialView::Password(""));
        VerifyInvalidCredential(Auth, CredentialView::Psk(""));
        VerifyInvalidCredential(Auth, CredentialView::Token(""));
        VerifyInvalidCredential(Auth, CredentialView::Extension(""));
        VerifyInvalidCredential(Auth, CredentialView{});
    }

    TEST(Authenticator, TypedDirectoryInspectAndAuthenticate)
    {
        using Preview::Account::AccountStore;
                using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::DirectoryAuthenticator;

        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
            .AccountId = Preview::AccountId{7020},
            .CredentialValue = Credential::Extension("typed-extension")});
        ASSERT_TRUE(Publish(*Directory, Record));

        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = "non-secret-identity",
            .Credential = CredentialView::Extension("typed-extension"),
            .Rate = {}});

        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result->AccountId(), Preview::AccountId{7020});
        EXPECT_TRUE(Result->Identity().empty()); // canonical身份来自材料，不复制任意请求文本。
        EXPECT_TRUE(Result->DisplayIdentity().empty());
        EXPECT_TRUE(*Result);
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Extension("typed-extension")));
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);

        std::vector<Preview::AccountId> AccountIds;
        Directory->ForEach([&AccountIds](const auto &Entry)
        {
            AccountIds.push_back(Entry->AccountId());
        });
        ASSERT_EQ(AccountIds.size(), 1U);
        EXPECT_EQ(AccountIds.front(), Preview::AccountId{7020});
    }

    TEST(Authenticator, UuidCredentialUsesNumericAccountAndKeepsDisplayIdentityEmpty)
    {
        using Preview::Account::AccountStore;
                using Preview::Account::Credential;
        using Preview::Account::CredentialView;
        using Preview::DirectoryAuthenticator;

        Preview::Account::UuidBytes Uuid{};
        Uuid[0] = std::byte{0x21};
        Uuid[15] = std::byte{0x7f};
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
            .AccountId = Preview::AccountId{7021},
            .CredentialValue = Credential::Uuid(Uuid)});
        ASSERT_TRUE(Publish(*Directory, Record));

        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = CredentialView::Uuid(Uuid),
            .Rate = {}});

        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(Result->Identity().empty());
        EXPECT_TRUE(Result->DisplayIdentity().empty());
        EXPECT_EQ(Result->AccountId(), Preview::AccountId{7021});
        ASSERT_TRUE(*Result);
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 1U);
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
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

        Net::co_spawn(
            IoContext,
            RunSocks5InjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
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

        Net::co_spawn(
            IoContext,
            RunSocks5RejectAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
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

        Net::co_spawn(
            IoContext,
            RunTrojanInjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
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

        Net::co_spawn(
            IoContext,
            RunVlessInjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
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

        Net::co_spawn(
            IoContext,
            RunHysteria2InjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
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

        Net::co_spawn(
            IoContext,
            RunHysteria2RejectAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        ASSERT_TRUE(State->ClientWriteResult.has_value());
        EXPECT_EQ(State->ClientWriteResult->Bytes, 3U);
        EXPECT_TRUE(State->ClientWriteResult->Failure.Succeeded());
    }

} // namespace
