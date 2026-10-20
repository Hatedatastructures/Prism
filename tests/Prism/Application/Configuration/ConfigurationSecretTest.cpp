/**
 * @file ConfigurationSecretTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"

namespace
{
    /**
     * @brief 统计并解析当前配置使用的 credential secret。
     * @details 仅匹配本测试的三个 secret ref，保持 resolver 调用次数可观察。
     */
    struct CachedSecretResolver final
    {
        std::size_t *Calls;
        const std::array<std::pair<std::string_view, std::string_view>, 3> *Secrets;

        [[nodiscard]] auto operator()(const std::string_view Reference) const
            -> std::optional<std::string>
        {
            ++*Calls;
            for (const auto &[Name, Value] : *Secrets)
            {
                if (Name == Reference)
                {
                    return std::string(Value);
                }
            }
            return std::nullopt;
        }
    };
} // namespace

TEST(PrismTask3Generation, RejectsUnresolvedSecretReferences)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back(
            {.Id = "missing-account", .SecretRef = "missing"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.Generation = Prism::GenerationId{1};
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string> { return std::nullopt; };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
    }

TEST(PrismTask3Generation, RejectsUnresolvedSecretReferencesWithoutResolver)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back(
            {.Id = "missing-account", .SecretRef = "missing"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

TEST(PrismTask3Generation, RejectsEmptyResolvedSecret)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back(
            {.Id = "empty-account", .SecretRef = "empty"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string>
        {
            return std::string{};
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

TEST(PrismTask3Generation, RejectsThrowingSecretResolver)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back(
            {.Id = "throwing-account", .SecretRef = "throwing"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string>
        {
            throw std::runtime_error("resolver failure");
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

TEST(PrismTask3Generation, AcceptsResolvedSecretReferences)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back(
            {.Id = "resolved-account", .SecretRef = "secret/account"});
        Options.SecretResolver = [](std::string_view Reference) -> std::optional<std::string>
        {
            return Reference == "secret/account" ? std::optional<std::string>{"resolved-value"}
                                                  : std::nullopt;
        };
        Options.Generation = Prism::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        const auto Secret = (*Result)->LookupSecret("secret/account");
        ASSERT_EQ(Secret.size(), 14U);
        constexpr std::array<unsigned int, 14> ExpectedBytes{
            114U, 101U, 115U, 111U, 108U, 118U, 101U,
            100U, 45U, 118U, 97U, 108U, 117U, 101U};
        for (std::size_t Index = 0; Index < Secret.size(); ++Index)
        {
            EXPECT_EQ(std::to_integer<unsigned int>(Secret[Index]), ExpectedBytes[Index]);
        }
        EXPECT_EQ((*Result)->Configuration().Accounts.back().SecretRef, "secret/account");
    }

TEST(PrismTask3Generation, AcceptsInlineConfigurationSecretsWithoutExternalResolver)
    {
        auto Json = ReplaceFirst(
            std::string(ValidJson),
            "  \"Routes\": [],",
            "  \"Secrets\": {\"secret/account\": \"inline-value\"},\n"
            "  \"Routes\": [],");
        Json = ReplaceFirst(
            std::move(Json),
            "  \"Accounts\": [{\"Id\": \"local\", \"SecretRef\": \"\", \"Credential\": \"local-token\"}],",
            "  \"Accounts\": [{\"Id\": \"local\", \"SecretRef\": \"\", \"Credential\": \"local-token\"},"
            " {\"Id\": \"inline-account\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"}],");
        const auto Parsed = ConfigurationParser::Parse({.Json = Json});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        auto Configuration = *Parsed;

        bool ExternalResolverCalled = false;
        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.SecretResolver = [&ExternalResolverCalled](std::string_view)
            -> std::optional<std::string>
        {
            ExternalResolverCalled = true;
            return std::nullopt;
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_FALSE(ExternalResolverCalled);
        const auto Secret = (*Result)->LookupSecret("secret/account");
        ASSERT_EQ(Secret.size(), 12U);
        EXPECT_TRUE(std::equal(
            Secret.begin(), Secret.end(), reinterpret_cast<const std::byte *>("inline-value")));
    }

TEST(PrismTask3Generation, CachesRepeatedCarrierSecretReferences)
    {
        const auto Json = MakeConfigurationJson(
            NativeProtocol,
            std::string(RealityCarrier) + "," + std::string(ShadowTlsCarrier) + "," +
                std::string(RestlsCarrier),
            {});
        const auto Parsed = ConfigurationParser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        auto Configuration = *Parsed;
        Configuration.Accounts.front().SecretRef = "secret/reality/private-key";
        Configuration.Accounts.front().Credential.clear();

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);

        constexpr std::array<std::pair<std::string_view, std::string_view>, 3> Secrets{
            std::pair{"secret/reality/private-key", "reality-key-material"},
            std::pair{"secret/shadowtls/password", "shadowtls-password"},
            std::pair{"secret/restls/password", "restls-password"}};
        std::size_t ResolverCalls = 0;
        Options.SecretResolver = CachedSecretResolver{&ResolverCalls, &Secrets};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_EQ(ResolverCalls, 3U);

        const auto &Generated = (*Result)->Configuration();
        EXPECT_EQ(Generated.Accounts.front().SecretRef, "secret/reality/private-key");
        EXPECT_TRUE(Generated.Accounts.front().Credential.empty());
        EXPECT_EQ(std::get<RealityOptions>(Generated.Carriers[0].Options).PrivateKeyRef,
                  "secret/reality/private-key");
        EXPECT_EQ(std::get<ShadowTlsOptions>(Generated.Carriers[1].Options).PasswordSecretRef,
                  "secret/shadowtls/password");
        EXPECT_EQ(std::get<RestlsOptions>(Generated.Carriers[2].Options).PasswordSecretRef,
                  "secret/restls/password");

        const auto AccountSecret = (*Result)->LookupSecret("secret/reality/private-key");
        const auto RealitySecret = (*Result)->LookupSecret("secret/reality/private-key");
        ASSERT_FALSE(AccountSecret.empty());
        EXPECT_EQ(AccountSecret.data(), RealitySecret.data());
        for (const auto &[Name, Value] : Secrets)
        {
            const auto Resolved = (*Result)->LookupSecret(Name);
            ASSERT_EQ(Resolved.size(), Value.size());
            EXPECT_TRUE(std::equal(
                Resolved.begin(), Resolved.end(),
                reinterpret_cast<const std::byte *>(Value.data())));
        }
    }

TEST(PrismTask3Generation, RejectsTrustTunnelCarrierBeforeResolvingSecrets)
    {
        auto Configuration = ParseValid();
        Configuration.Accounts.push_back(
            {"trusttunnel-account", "secret/trusttunnel/password", ""});
        CarrierConfiguration Carrier;
        Carrier.Id = "carrier-trusttunnel";
        Carrier.Name = "trusttunnel";
        Carrier.Builtin = "trusttunnel";
        Carrier.Match.ServerNames = {"www.amazon.com"};
        Carrier.Options = Prism::Contract::NativeTlsOptions{"cert.pem", "key.pem"};
        Configuration.Carriers.push_back(std::move(Carrier));

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeDescriptorSnapshot({"carrier", "trusttunnel", CapabilitySet{}, {}});
        ASSERT_NE(Options.Builtins, nullptr);
        std::size_t ResolverCalls = 0;
        Options.SecretResolver = [&ResolverCalls](std::string_view)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            return std::string{"not-reached"};
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
        EXPECT_EQ(ResolverCalls, 0U);
    }

TEST(PrismTask3Generation, RejectsMissingCapabilitiesBeforePublication)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Runtime.RequiredCapabilities = {"Tls"};
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.Generation = Prism::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
    }

TEST(PrismTask3Generation, RejectsBuiltinCapabilitiesNotProvidedByFrozenDescriptor)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Builtins.push_back(
            {"builtin-core-only", "protocol", "core-only", {}, {"Tls"}});
        Options.Configuration.Runtime.RequiredCapabilities = {"Tls"};

        Registry RegistryValue;
        Prism::Composition::Builtin::BuiltinDescriptor Descriptor;
        Descriptor.Kind = Prism::KindId::From("protocol");
        Descriptor.Name = Prism::NameId::From("core-only");
        Descriptor.Provides = CapabilitySet{Capability::Core};
        Descriptor.Callback = [](const Prism::Composition::Builtin::BuiltinRequest &)
            -> Prism::Foundation::Expected<void> { return {}; };
        ASSERT_TRUE(RegistryValue.Register(std::move(Descriptor)));
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);
        Options.Builtins = *Frozen;
        Options.Generation = Prism::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "Builtins[0].Provides");
    }

TEST(PrismTask3Generation, RejectsUnknownBuiltinReferenceAgainstEmptySnapshot)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Builtins.push_back(
            {"builtin-unknown", "protocol", "unknown", {}, {}});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Builtins[0]");
    }
