/**
 * @file ProfileCompileHandleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ProfileCompileTestSupport.hpp"

TEST(ProfileCompileTest, RejectsEarlyResponseAndOpaqueMixedTrial)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{1, "socks", Prism::Contract::ProtocolType::Socks5,
                                           rec::CandidateKind::EarlyResponse}));
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{2, "vmess", Prism::Contract::ProtocolType::Vmess, rec::CandidateKind::Opaque}));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::EarlyResponseOpaqueConflict);
    }

TEST(ProfileCompileTest, RejectsQuicCandidateFromTcpProfile)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 30;
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{30, "hysteria2", Prism::Contract::ProtocolType::Hysteria2,
                                           rec::CandidateKind::QuicCarrier}));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::QuicCandidateRequiresGateway);
    }

TEST(ProfileCompileTest, RejectsTlsCarrierWithoutScheme)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 31;
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{31, "tls", Prism::Contract::ProtocolType::Http,
                                           rec::CandidateKind::TlsCarrier}));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::MissingCarrierScheme);
    }

TEST(ProfileCompileTest, SortsCandidatesStablyByTierThenPriority)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{1, "late", Prism::Contract::ProtocolType::Http,
                                                                  rec::CandidateKind::Cleartext, 2, 1}));
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{2, "first", Prism::Contract::ProtocolType::Socks5,
                                                                  rec::CandidateKind::Cleartext, 1, 0}));
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{3, "same-tier", Prism::Contract::ProtocolType::Tls,
                                                                  rec::CandidateKind::Cleartext, 1, 0}));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        ASSERT_EQ(Result.value()->CandidateCount(), 3U);
        EXPECT_EQ(Result.value()->CandidateIdAt(0), 2);
        EXPECT_EQ(Result.value()->CandidateIdAt(1), 3);
        EXPECT_EQ(Result.value()->CandidateIdAt(2), 1);
    }

TEST(ProfileCompileTest, BuildsSealedDecisionAndSniIndexes)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        auto Http = MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http);
        Http.FirstBytes = {0x47};
        Http.MinimumBytes = 4;
        Spec.Candidates.push_back(std::move(Http));
        auto Socks = MakeCandidate(2, "socks", Prism::Contract::ProtocolType::Socks5);
        Socks.FirstBytes = {0x05};
        Spec.Candidates.push_back(std::move(Socks));
        Spec.Routes.push_back(MakeRoute("example.com", 1));
        Spec.Routes.push_back(MakeRoute("*.example.com", 2));
        Spec.Routes.push_back(MakeRoute("*.sub.example.com", 1));
        Spec.Routes.push_back(MakeRoute("*.com", 2));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        const auto &Profile = *Result.value();
        EXPECT_TRUE(Profile.IsDecisionSealed());
        EXPECT_EQ(Profile.LookupCandidates(0x47).Count(), 1U);
        EXPECT_TRUE(Profile.LookupCandidates(0x47).Test(1));
        EXPECT_TRUE(Profile.LookupCandidates(0x05).Test(2));
        ASSERT_TRUE(Profile.LookupRoute("EXAMPLE.COM").has_value());
        EXPECT_EQ(Profile.LookupRoute("EXAMPLE.COM").value(), 1);
        ASSERT_TRUE(Profile.LookupRoute("a.sub.example.com").has_value());
        EXPECT_EQ(Profile.LookupRoute("a.sub.example.com").value(), 1);
        ASSERT_TRUE(Profile.LookupRoute("a.com").has_value());
        EXPECT_EQ(Profile.LookupRoute("a.com").value(), 2);
        EXPECT_FALSE(Profile.LookupRoute("example.net").has_value());
    }

TEST(ProfileCompileTest, IndexesTlsRouteCandidateByRecordType)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;
        auto Tls = MakeCandidate(CandidateOptions{1, "native", Prism::Contract::ProtocolType::Tls,
                                                  rec::CandidateKind::TlsCarrier});
        Tls.Scheme = "native";
        Tls.MinimumBytes = 5;
        Spec.Candidates.push_back(std::move(Tls));
        Spec.Routes.push_back(MakeRoute("edge.example", 1));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(Result.value()->LookupCandidates(0x16).Test(1));
        EXPECT_FALSE(Result.value()->FallbackCandidates().Test(1));
    }

TEST(ProfileCompileTest, WildcardMatchesExactlyOneLabelAndExactRouteWins)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeCandidate(1, "base", Prism::Contract::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "sub", Prism::Contract::ProtocolType::Socks5));
        Spec.Routes.push_back(MakeRoute("*.example.com", 1));
        Spec.Routes.push_back(MakeRoute("*.sub.example.com", 2));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        const auto &Profile = *Result.value();
        EXPECT_FALSE(Profile.LookupRoute("example.com").has_value());
        ASSERT_TRUE(Profile.LookupRoute("a.example.com").has_value());
        EXPECT_EQ(Profile.LookupRoute("a.example.com").value(), 1);
        EXPECT_FALSE(Profile.LookupRoute("a.b.example.com").has_value());
        ASSERT_TRUE(Profile.LookupRoute("a.sub.example.com").has_value());
        EXPECT_EQ(Profile.LookupRoute("a.sub.example.com").value(), 2);

        rec::ProfileSpec ExactSpec;
        ExactSpec.Mode = rec::RecognitionMode::MixedTrial;
        ExactSpec.Candidates.push_back(MakeCandidate(1, "base", Prism::Contract::ProtocolType::Http));
        ExactSpec.Routes.push_back(MakeRoute("example.com", 1));
        ExactSpec.Routes.push_back(MakeRoute("*.example.com", 1));
        const auto ExactResult = Compile(std::move(ExactSpec));
        ASSERT_TRUE(ExactResult.has_value());
        ASSERT_TRUE(ExactResult.value()->LookupRoute("EXAMPLE.COM").has_value());
        EXPECT_EQ(ExactResult.value()->LookupRoute("EXAMPLE.COM").value(), 1);
    }

TEST(ProfileCompileTest, CompilesExplicitDefaultCandidateRoute)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.DefaultCandidate = 2;
        Spec.Candidates.push_back(MakeCandidate(1, "specific", Prism::Contract::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "fallback", Prism::Contract::ProtocolType::Socks5));
        Spec.Routes.push_back(MakeRoute("specific.example.com", 1));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(Result.value()->HasRoutes());
        ASSERT_TRUE(Result.value()->LookupRoute("specific.example.com").has_value());
        EXPECT_EQ(Result.value()->LookupRoute("specific.example.com").value(), 1U);
        ASSERT_TRUE(Result.value()->LookupRoute("unknown.example.net").has_value());
        EXPECT_EQ(Result.value()->LookupRoute("unknown.example.net").value(), 2U);
        ASSERT_TRUE(Result.value()->LookupRoute("").has_value());
        EXPECT_EQ(Result.value()->LookupRoute("").value(), 2U);
    }

TEST(ProfileCompileTest, RejectsDanglingDefaultCandidateRoute)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.DefaultCandidate = 9;
        Spec.Candidates.push_back(MakeCandidate(1, "candidate", Prism::Contract::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DanglingRoute);
    }

TEST(ProfileCompileTest, KeepsOpaqueProtocolMagicOnFallbackWithoutExplicitFirstBytes)
    {
        constexpr std::array<std::pair<rec::CandidateId, Prism::Contract::ProtocolType>, 3> OpaqueProtocols{
            std::pair{1, Prism::Contract::ProtocolType::Trojan}, std::pair{2, Prism::Contract::ProtocolType::Vmess},
            std::pair{3, Prism::Contract::ProtocolType::Vless}};
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        for (const auto [Id, Protocol] : OpaqueProtocols)
        {
            Spec.Candidates.push_back(
                MakeCandidate(CandidateOptions{Id, "opaque-" + std::to_string(Id), Protocol,
                                               rec::CandidateKind::Opaque}));
        }

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        const auto &Profile = *Result.value();
        const auto Fallback = Profile.FallbackCandidates();
        const auto Indexed = Profile.IndexedCandidates(0x0D);
        for (const auto [Id, Protocol] : OpaqueProtocols)
        {
            (void)Protocol;
            EXPECT_TRUE(Fallback.Test(Id));
            EXPECT_FALSE(Indexed.Test(Id));
        }
    }

TEST(ProfileCompileTest, CandidateHandleOwnsProfileForLaterUse)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeCandidate(1, "owned", Prism::Contract::ProtocolType::Http));
        const auto Result = Compile(std::move(Spec));
        ASSERT_TRUE(Result.has_value());

        auto Owner = Result.value();
        auto Handle = Owner->FindCandidate(1);
        Owner.reset();

        ASSERT_TRUE(Handle.IsValid());
        EXPECT_EQ(Handle.Id(), 1);
        EXPECT_EQ(Handle.Name(), "owned");
        EXPECT_TRUE(Handle.Scheme().empty());
        EXPECT_EQ(Handle.Protocol(), Prism::Contract::ProtocolType::Http);
        EXPECT_EQ(Handle.Inspect(rec::ProbeSnapshot{}), rec::MatchState::Structural);
    }

TEST(ProfileCompileTest, CandidateHandleExposesOuterScheme)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        auto Candidate = MakeCandidate(7, "edge-vless", Prism::Contract::ProtocolType::Vless);
        Candidate.Scheme = "reality";
        Spec.Candidates.push_back(std::move(Candidate));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        const auto Handle = Result.value()->FindCandidate(7);
        EXPECT_EQ(Handle.Name(), "edge-vless");
        EXPECT_EQ(Handle.Scheme(), "reality");
    }

TEST(ProfileCompileTest, CandidateHandlePropagatesInspectException)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        auto Candidate = MakeCandidate(1, "throws", Prism::Contract::ProtocolType::Http);
        Candidate.Inspect = [](const rec::ProbeSnapshot &) -> rec::MatchState
        {
            throw std::runtime_error("inspect failure");
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Result = Compile(std::move(Spec));
        ASSERT_TRUE(Result.has_value());

        const auto Handle = Result.value()->FindCandidate(1);

        const auto Invoke = [&Handle]() -> void
        {
            (void)Handle.Inspect(rec::ProbeSnapshot{});
        };
        EXPECT_THROW(Invoke(), std::runtime_error);
    }

