/**
 * @file CandidateRegistryTest.cpp
 * @brief Settings candidate registry behavior tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <optional>
#include <string>
#include <utility>

#include <preview/Composition/Recognition/CandidateFactory.hpp>
#include <preview/Composition/Recognition/CandidateRegistry.hpp>
#include <preview/Composition/Settings/Loader.hpp>

namespace
{

    namespace Composition = Preview::Composition::Recognition;
    namespace Core = Preview::Recognition;
    namespace Net = boost::asio;

    auto MakeHttpBinding(const Preview::Settings::RecognitionCandidate &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        auto Binding = Composition::CandidateFactory::MakeHttp(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                          Candidate.Fallback});
        return Binding;
    }

} // namespace

TEST(CandidateRegistry, NormalizesProtocolNamesAndBuildsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("HTTP", MakeHttpBinding));

    Preview::Settings::RecognitionCandidate Candidate;
    Candidate.Id = 11;
    Candidate.Name = "http-entry";
    Candidate.Protocol = "http";

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Id, 11);
    EXPECT_EQ(Binding->Spec.Name, "http-entry");
    EXPECT_EQ(Binding->Spec.Protocol, Core::ProtocolType::Http);
}

TEST(CandidateRegistry, SupportsShadowsocksAlias)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("ss2022", MakeHttpBinding));

    Preview::Settings::RecognitionCandidate Candidate;
    Candidate.Id = 12;
    Candidate.Protocol = "shadowsocks";

    EXPECT_TRUE(Registry.Has("SS2022"));
    EXPECT_TRUE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsDuplicateNormalizedProtocol)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("http", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("HTTP", MakeHttpBinding));
}

TEST(CandidateRegistry, RejectsDuplicateProtocolAliases)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("shadowsocks", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("SS2022", MakeHttpBinding));
}

TEST(CandidateRegistry, FactoryOwnsRegisteredBuilders)
{
    Composition::SettingsCandidateFactory Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.Register("http", MakeHttpBinding));
        Factory = Registry.MakeFactory();
    }

    Preview::Settings::RecognitionCandidate Candidate;
    Candidate.Id = 13;
    Candidate.Protocol = "http";

    EXPECT_TRUE(Factory);
    EXPECT_TRUE(Factory(Candidate).has_value());
}

TEST(CandidateRegistry, MissingProtocolReturnsNoBinding)
{
    Composition::CandidateRegistry Registry;
    Preview::Settings::RecognitionCandidate Candidate;
    Candidate.Protocol = "vless";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    EXPECT_FALSE(Registry.Has("vless"));
}

TEST(CandidateRegistry, RegistersCoreProtocolFactories)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterHttp());
    ASSERT_TRUE(Registry.RegisterSocks5());
    ASSERT_TRUE(Registry.RegisterVless());
    ASSERT_TRUE(Registry.RegisterTrojan());
    ASSERT_TRUE(Registry.RegisterVmess());
    ASSERT_TRUE(Registry.RegisterSs2022());

    const std::array<Preview::Settings::RecognitionCandidate, 6> Candidates{
        Preview::Settings::RecognitionCandidate{1, "http", "http", 0, 0, false},
        Preview::Settings::RecognitionCandidate{2, "socks5", "socks5", 0, 0, false},
        Preview::Settings::RecognitionCandidate{3, "vless", "vless", 0, 0, false},
        Preview::Settings::RecognitionCandidate{4, "trojan", "trojan", 0, 0, false},
        Preview::Settings::RecognitionCandidate{5, "vmess", "vmess", 0, 0, false},
        Preview::Settings::RecognitionCandidate{6, "ss2022", "ss2022", 0, 0, false},
    };

    for (const auto &Candidate : Candidates)
    {
        const auto Binding = Registry.Build(Candidate);
        ASSERT_TRUE(Binding.has_value()) << Candidate.Protocol;
        EXPECT_EQ(Binding->Spec.Id, Candidate.Id);
        EXPECT_TRUE(Binding->Accept);
        EXPECT_TRUE(Binding->Spec.Inspect);
        EXPECT_TRUE(Binding->Spec.Commit);
    }
}

TEST(CandidateRegistry, ComposesRegisteredCarrierWithCoreCandidate)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterHttp());
    ASSERT_TRUE(Registry.RegisterCarrier(
        "NATIVE",
        [](Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::SharedTransmission>
        {
            co_return Inbound;
        }));

    Preview::Settings::RecognitionCandidate Candidate{17, "native-http", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Candidate.ServerNames = {"example.com"};
    Candidate.Alpn = {"h2"};

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Protocol, Core::ProtocolType::Http);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
    EXPECT_TRUE(Binding->Accept);
}

TEST(CandidateRegistry, RejectsUnregisteredCarrierInsteadOfPassthrough)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterHttp());

    Preview::Settings::RecognitionCandidate Candidate{18, "missing-carrier", "http", 0, 0, false};
    Candidate.Scheme = "reality";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsSchemeMismatchFromPrebuiltTlsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register(
        "http",
        [](const auto &Candidate) -> std::optional<Composition::CandidateBinding>
        {
            auto Binding = Composition::CandidateFactory::MakeHttp(
                Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                              Candidate.Fallback});
            Binding.Spec.Kind = Core::CandidateKind::TlsCarrier;
            Binding.Spec.Scheme = "reality";
            return Binding;
        }));

    Preview::Settings::RecognitionCandidate Candidate{19, "mismatch", "http", 0, 0, false};
    Candidate.Scheme = "native";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, FactoryOwnsCarrierBuilders)
{
    Composition::SettingsCandidateFactory Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.RegisterHttp());
        ASSERT_TRUE(Registry.RegisterCarrier(
            "native",
            [](Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::SharedTransmission>
            {
                co_return Inbound;
            }));
        Factory = Registry.MakeFactory();
    }

    Preview::Settings::RecognitionCandidate Candidate{20, "owned", "http", 0, 0, false};
    Candidate.Scheme = "native";
    const auto Binding = Factory(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
}
