/**
 * @file AuthenticatorTest.cpp
 * @brief 认证器静态校验、目录凭据与 typed lease 行为测试。
 */

#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>

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

#include <Prism/Account/Account.hpp>
#include "AccountTestSupport.hpp"
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Prism::Hysteria2;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Vless = Prism::Vless;
    using Prism::ConstantTimeEqual;
    using Prism::AsBytes;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::RejectAuthenticator;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto AuthenticateCredential(
        const Prism::DirectoryAuthenticator &Auth,
        Prism::Account::CredentialView CredentialValue,
        const Prism::AccountId ExpectedId) -> void
    {
        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .AccountId = {}, .Identity = "wire-user", .Credential = CredentialValue, .Rate = {}});
        EXPECT_TRUE(Result.has_value());
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->AccountId(), ExpectedId);
        EXPECT_TRUE(*Result);
        Result->Release();
        Result->Release();
    }

    TEST(Authenticator, StaticPassAndReject)
    {
        using Prism::Account::CredentialView;
        const auto AuthOwner = Prism::Testing::ProviderAccount(
            Prism::Testing::ProviderAccountInput{Prism::AccountId{1U},
                Prism::Account::Credential::Password("pass"), "user", "user", {}});
        const auto& Auth = *AuthOwner->Authenticator;
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("pass")));
        EXPECT_FALSE(InspectMatch(Auth, CredentialView::Password("wrong")));
        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .Identity = "user", .Credential = CredentialView::Password("pass")});
        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(*Result);
        Result->Release();
        auto Identityless = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Password("pass")});
        ASSERT_TRUE(Identityless.has_value());
        EXPECT_EQ(Identityless->Identity(), "user");
        Identityless->Release();
        EXPECT_FALSE(Auth.Authenticate(Prism::AuthenticationRequest{
            .Identity = "other", .Credential = CredentialView::Password("pass")}).has_value());

        RejectAuthenticator Reject;
        EXPECT_FALSE(InspectMatch(Reject, CredentialView::Password("pass")));
        EXPECT_FALSE(Reject.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Password("pass")}).has_value());
    }

    TEST(Authenticator, IdentitylessRequestRejectsAmbiguousCredential)
    {
        using Prism::Account::AccountDefinition;
        using Prism::Account::AccountMaterials;
        using Prism::Account::AccountStore;
        using Prism::Account::Credential;
        using Prism::Account::CredentialMaterial;
        using Prism::Account::CredentialView;
        using Prism::AccountId;

        std::vector<CredentialMaterial> Credentials;
        Credentials.push_back({Prism::Testing::ProviderScope, "user-a",
            Credential::Password("shared-password")});
        Credentials.push_back({Prism::Testing::ProviderScope, "user-b",
            Credential::Password("shared-password")});
        auto Materials = std::make_shared<const AccountMaterials>(
            AccountMaterials::CreateRequest{
                AccountId{7030}, "test-account-7030", std::move(Credentials)});
        const AccountDefinition Definition{std::move(Materials), {}};
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, Definition));
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));
        const auto SharedCredential = Credential::Password("shared-password");

        EXPECT_FALSE(Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = SharedCredential.View()}).has_value());
        auto FirstIdentity = Auth.Authenticate(Prism::AuthenticationRequest{
            .Identity = "user-a", .Credential = SharedCredential.View()});
        ASSERT_TRUE(FirstIdentity.has_value());
        EXPECT_EQ(FirstIdentity->Identity(), "user-a");
        FirstIdentity->Release();
        auto SecondIdentity = Auth.Authenticate(Prism::AuthenticationRequest{
            .Identity = "user-b", .Credential = SharedCredential.View()});
        ASSERT_TRUE(SecondIdentity.has_value());
        EXPECT_EQ(SecondIdentity->Identity(), "user-b");
        SecondIdentity->Release();
    }

    TEST(Authenticator, DirectoryRequestReturnsTypedLease)
    {
        using Prism::Account::AccountStore;
        using Prism::Account::Credential;
        using Prism::Account::CredentialView;
        using Prism::AccountId;

        const auto Record = MakeDefinition(AccountInput{
            .AccountId = AccountId{7001},
            .CredentialValue = Credential::Password("typed-password"),
            .Quota = {.MaxConnections = 1}});
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, Record));

        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = "alice",
            .Credential = CredentialView::Password("typed-password"),
            .Rate = {}});

        static_assert(std::is_same_v<std::remove_cvref_t<decltype(*Result)>, Prism::Account::AccountLease>);
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
        using Prism::Account::CredentialView;
        auto Directory = std::make_shared<Prism::Account::AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
                .AccountId = Prism::AccountId{7099},
                .CredentialValue = Prism::Account::Credential::Password("probe-only"),
                .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("probe-only")));
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Authenticator, DirectoryAcceptsProtocolCredentialViews)
    {
        using Prism::Account::AccountStore;
                using Prism::Account::Credential;
        using Prism::Account::CredentialView;
        using Prism::AccountId;

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
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));

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
        using Prism::Account::AccountStore;
                using Prism::Account::Credential;
        using Prism::Account::CredentialView;
        using Prism::DirectoryAuthenticator;

        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
            .AccountId = Prism::AccountId{7020},
            .CredentialValue = Credential::Extension("typed-extension")});
        ASSERT_TRUE(Publish(*Directory, Record));

        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = "non-secret-identity",
            .Credential = CredentialView::Extension("typed-extension"),
            .Rate = {}});

        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result->AccountId(), Prism::AccountId{7020});
        EXPECT_TRUE(Result->Identity().empty()); // canonical身份来自材料，不复制任意请求文本。
        EXPECT_EQ(Result->DisplayIdentity(), "test-account-7020");
        EXPECT_TRUE(*Result);
        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Extension("typed-extension")));
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);

        std::vector<Prism::AccountId> AccountIds;
        Directory->ForEach([&AccountIds](const auto &Entry)
        {
            AccountIds.push_back(Entry->AccountId());
        });
        ASSERT_EQ(AccountIds.size(), 1U);
        EXPECT_EQ(AccountIds.front(), Prism::AccountId{7020});
    }

    TEST(Authenticator, UuidCredentialUsesNumericAccountAndStableDisplayIdentity)
    {
        using Prism::Account::AccountStore;
                using Prism::Account::Credential;
        using Prism::Account::CredentialView;
        using Prism::DirectoryAuthenticator;

        Prism::Account::UuidBytes Uuid{};
        Uuid[0] = std::byte{0x21};
        Uuid[15] = std::byte{0x7f};
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{
            .AccountId = Prism::AccountId{7021},
            .CredentialValue = Credential::Uuid(Uuid)});
        ASSERT_TRUE(Publish(*Directory, Record));

        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));
        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = CredentialView::Uuid(Uuid),
            .Rate = {}});

        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(Result->Identity().empty());
        EXPECT_EQ(Result->DisplayIdentity(), "test-account-7021");
        EXPECT_EQ(Result->AccountId(), Prism::AccountId{7021});
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

} // namespace
