/**
 * @file AccountCredentialTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "../Runtime/AccountTestSupport.hpp"

TEST(PrismAccountCredential, MapsAllCredentialKinds)
{
    const auto Password = Credential::Password("password-material-17");
    const auto Uuid = Credential::Uuid(std::array<std::byte, 16>{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C},
        std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}, std::byte{0x10}});
    const auto Psk = Credential::Psk("psk-material-29");
    const auto Token = Credential::Token("token-material-41");
    const auto Extension = Credential::Extension("extension-material-53");

    EXPECT_EQ(Password.View().Kind(), CredentialKind::Password);
    EXPECT_EQ(Uuid.View().Kind(), CredentialKind::Uuid);
    EXPECT_EQ(Psk.View().Kind(), CredentialKind::Psk);
    EXPECT_EQ(Token.View().Kind(), CredentialKind::Token);
    EXPECT_EQ(Extension.View().Kind(), CredentialKind::Extension);

    EXPECT_TRUE(Password.Matches(CredentialView::Password("password-material-17")));
    EXPECT_FALSE(Password.Matches(CredentialView::Password("password-material-18")));
    EXPECT_TRUE(Psk.Matches(CredentialView::Psk("psk-material-29")));
    EXPECT_TRUE(Token.Matches(CredentialView::Token("token-material-41")));
    EXPECT_TRUE(Extension.Matches(CredentialView::Extension("extension-material-53")));
}

TEST(PrismAccountCredential, FixedLengthComparisonRejectsLengthMismatch)
{
    const auto Psk = Credential::Psk("fixed-length");

    EXPECT_TRUE(Psk.Matches(CredentialView::Psk("fixed-length")));
    EXPECT_FALSE(Psk.Matches(CredentialView::Psk("fixed-lengt")));
    EXPECT_FALSE(Psk.Matches(CredentialView::Psk("fixed-length-extra")));
}

TEST(PrismAccountCredential, SecretMaterialIsRedacted)
{
    const auto Secret = std::string("redaction-token-67");
    const auto Record = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{100},
        .CredentialValue = Credential::Token(Secret)});

    const auto CredentialRedacted = CredentialOf(Record).Redacted();
    const auto RecordRedacted = Record.Materials->Redacted();
    EXPECT_EQ(CredentialRedacted, "[redacted]");
    EXPECT_EQ(CredentialRedacted.find(Secret), std::string::npos);
    EXPECT_EQ(RecordRedacted.find(Secret), std::string::npos);
    EXPECT_NE(RecordRedacted.find("100"), std::string::npos);
}

TEST(PrismAccountDirectory, MapsCredentialKindsToRecords)
{
    const auto Uuid = std::array<std::byte, 16>{
        std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
        std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28},
        std::byte{0x29}, std::byte{0x2A}, std::byte{0x2B}, std::byte{0x2C},
        std::byte{0x2D}, std::byte{0x2E}, std::byte{0x2F}, std::byte{0x30}};
    const auto PasswordRecord = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{101},
        .CredentialValue = Credential::Password("mapped-password-value")});
    const auto UuidRecord = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{102},
        .CredentialValue = Credential::Uuid(Uuid)});
    const auto PskRecord = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{103},
        .CredentialValue = Credential::Psk("mapped-psk-value")});
    const auto TokenRecord = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{104},
        .CredentialValue = Credential::Token("mapped-token-value")});
    const auto ExtensionRecord = MakeDefinition(AccountInput{
        .AccountId = Prism::AccountId{105},
        .CredentialValue = Credential::Extension("mapped-extension-value")});

    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, PasswordRecord));
    ASSERT_TRUE(Publish(Directory, UuidRecord));
    ASSERT_TRUE(Publish(Directory, PskRecord));
    ASSERT_TRUE(Publish(Directory, TokenRecord));
    ASSERT_TRUE(Publish(Directory, ExtensionRecord));

    EXPECT_EQ(FindCredentialAccount(Directory, CredentialView::Password("mapped-password-value"))->AccountId().Value(),
              101U);
    EXPECT_EQ(FindCredentialAccount(Directory, CredentialView::Uuid(Uuid))->AccountId().Value(), 102U);
    EXPECT_EQ(FindCredentialAccount(Directory, CredentialView::Psk("mapped-psk-value"))->AccountId().Value(), 103U);
    EXPECT_EQ(FindCredentialAccount(Directory, CredentialView::Token("mapped-token-value"))->AccountId().Value(),
              104U);
    EXPECT_EQ(FindCredentialAccount(Directory, CredentialView::Extension("mapped-extension-value"))
                  ->AccountId()
                  .Value(),
              105U);
}

TEST(PrismAccountCredential, RejectsUnknownEmptyAndMalformedAtConstruction)
{
    EXPECT_THROW((Credential(CredentialKind::Unknown, Prism::Account::SecureBytes{})),
                 std::invalid_argument);
    EXPECT_THROW((void)Credential::Password(""), std::invalid_argument);

    const std::array<std::byte, 1> MalformedUuid{std::byte{0x01}};
    EXPECT_THROW((Credential(CredentialKind::Uuid,
                             Prism::Account::SecureBytes(std::span<const std::byte>(MalformedUuid)))),
                 std::invalid_argument);
    EXPECT_THROW((MakeDefinition(AccountInput{
                     .AccountId = Prism::AccountId{},
                     .CredentialValue = Credential::Password("valid-account-password")})),
                 std::invalid_argument);
}

TEST(PrismAccountAuthenticator, RejectsMalformedCredentialAtAuthentication)
{
    auto Directory = std::make_shared<AccountStore>();
    Prism::DirectoryAuthenticator Authenticator(CompileView(*Directory));
    const auto Result = Authenticator.Authenticate(Prism::AuthenticationRequest{
        .Credential = CredentialView{}, .Rate = RateRequest{0, 1, 1}});

    EXPECT_FALSE(Result);
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_EQ(Result.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::InvalidCredential).Native);
}

