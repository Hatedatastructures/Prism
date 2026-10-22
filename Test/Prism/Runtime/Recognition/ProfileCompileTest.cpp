/**
 * @file ProfileCompileTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ProfileCompileTestSupport.hpp"

TEST(ProfileCompileTest, CompilesSingleConfiguredCandidate)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Candidates.push_back(MakeCandidate(7, "http", Prism::Contract::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        ASSERT_NE(Result.value(), nullptr);
        EXPECT_EQ(Result.value()->Mode(), rec::RecognitionMode::Configured);
        EXPECT_EQ(Result.value()->CandidateCount(), 1U);
        EXPECT_EQ(Result.value()->ConfiguredCandidate(), 7);
        EXPECT_EQ(Result.value()->CandidateIdAt(0), 7);
        EXPECT_TRUE(Result.value()->IsDecisionSealed());
    }

TEST(ProfileCompileTest, RejectsConfiguredWhenCandidateCountIsNotExactlyOne)
    {
        rec::ProfileSpec Empty;
        Empty.Mode = rec::RecognitionMode::Configured;
        Empty.ConfiguredCandidate = 7;
        EXPECT_EQ(Compile(std::move(Empty)).error(), rec::ProfileError::ConfiguredCandidateCount);

        rec::ProfileSpec Multiple;
        Multiple.Mode = rec::RecognitionMode::Configured;
        Multiple.ConfiguredCandidate = 7;
        Multiple.Candidates.push_back(MakeCandidate(7, "http", Prism::Contract::ProtocolType::Http));
        Multiple.Candidates.push_back(MakeCandidate(8, "socks", Prism::Contract::ProtocolType::Socks5));
        EXPECT_EQ(Compile(std::move(Multiple)).error(), rec::ProfileError::ConfiguredCandidateCount);
    }

TEST(ProfileCompileTest, RejectsEmptyMixedTrial)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::MixedTrialRequiresCandidate);
    }

TEST(ProfileCompileTest, CompilesDeterministicRouteWithMultipleCandidates)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;

        auto Http = MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http);
        Http.FirstBytes = {0x16};
        auto Socks5 = MakeCandidate(2, "socks5", Prism::Contract::ProtocolType::Socks5);
        Socks5.FirstBytes = {0x05};
        Spec.Candidates.push_back(std::move(Http));
        Spec.Candidates.push_back(std::move(Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        ASSERT_NE(Result.value(), nullptr);
        EXPECT_EQ(Result.value()->Mode(), rec::RecognitionMode::Deterministic);
        EXPECT_EQ(Result.value()->CandidateCount(), 2U);
        EXPECT_EQ(Result.value()->ConfiguredCandidate(), rec::InvalidCandidate);
    }

TEST(ProfileCompileTest, RejectsDeterministicFallbackOverlappingIndexedCandidate)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;

        auto Fallback = MakeCandidate(1, "fallback", Prism::Contract::ProtocolType::Http);
        Fallback.FirstBytes = {0x05};
        Fallback.Fallback = true;
        Spec.Candidates.push_back(std::move(Fallback));

        auto Indexed = MakeCandidate(2, "indexed", Prism::Contract::ProtocolType::Socks5);
        Indexed.FirstBytes = {0x06};
        Spec.Candidates.push_back(std::move(Indexed));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DeterministicSelectorConflict);
    }

TEST(ProfileCompileTest, KeepsDeterministicTlsRoutesForFallbackCandidates)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;

        auto First = MakeCandidate(CandidateOptions{1, "first-tls", Prism::Contract::ProtocolType::Tls,
                                                     rec::CandidateKind::TlsCarrier});
        First.Scheme = "native";
        First.Fallback = true;
        auto Second = MakeCandidate(CandidateOptions{2, "second-tls", Prism::Contract::ProtocolType::Tls,
                                                      rec::CandidateKind::TlsCarrier});
        Second.Scheme = "native";
        Second.Fallback = true;
        Spec.Candidates.push_back(std::move(First));
        Spec.Candidates.push_back(std::move(Second));
        Spec.Routes.push_back(MakeRoute("first.example", 1));
        Spec.Routes.push_back(MakeRoute("second.example", 2));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
    }

TEST(ProfileCompileTest, RejectsConfiguredCandidateInDeterministicRoute)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;
        Spec.ConfiguredCandidate = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::ConfiguredCandidateNotAllowed);
    }

TEST(ProfileCompileTest, RejectsUndiscriminatedDeterministicCandidates)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;
        Spec.Candidates.push_back(MakeCandidate(1, "first", Prism::Contract::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "second", Prism::Contract::ProtocolType::Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DeterministicCandidateNeedsSelector);
    }

TEST(ProfileCompileTest, RejectsOverlappingDeterministicPlainSelectors)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;
        auto First = MakeCandidate(1, "first", Prism::Contract::ProtocolType::Http);
        First.FirstBytes = {0x43};
        auto Second = MakeCandidate(2, "second", Prism::Contract::ProtocolType::Socks5);
        Second.FirstBytes = {0x43};
        Spec.Candidates.push_back(std::move(First));
        Spec.Candidates.push_back(std::move(Second));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DeterministicSelectorConflict);
    }

TEST(ProfileCompileTest, AllowsOverlappingTlsSelectorsWhenSniRoutesDisambiguate)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Deterministic;
        auto First = MakeCandidate(CandidateOptions{1, "first-tls", Prism::Contract::ProtocolType::Tls,
                                                     rec::CandidateKind::TlsCarrier});
        First.Scheme = "native";
        auto Second = MakeCandidate(CandidateOptions{2, "second-tls", Prism::Contract::ProtocolType::Tls,
                                                      rec::CandidateKind::TlsCarrier});
        Second.Scheme = "native";
        Spec.Candidates.push_back(std::move(First));
        Spec.Candidates.push_back(std::move(Second));
        Spec.Routes.push_back(MakeRoute("first.example", 1));
        Spec.Routes.push_back(MakeRoute("second.example", 2));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result.value()->CandidateCount(), 2U);
    }

TEST(ProfileCompileTest, RejectsDeterministicRouteToCleartextCandidate)
    {
        rec::ProfileSpec Routed;
        Routed.Mode = rec::RecognitionMode::Deterministic;
        auto Http = MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http);
        Http.FirstBytes = {'C'};
        Routed.Candidates.push_back(std::move(Http));
        Routed.Routes.push_back(MakeRoute("edge.example", 1));

        const auto RoutedResult = Compile(std::move(Routed));
        ASSERT_FALSE(RoutedResult.has_value());
        EXPECT_EQ(RoutedResult.error(), rec::ProfileError::DeterministicRouteRequiresTlsCandidate);

        rec::ProfileSpec Defaulted;
        Defaulted.Mode = rec::RecognitionMode::Deterministic;
        Defaulted.DefaultCandidate = 1;
        auto DefaultHttp = MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http);
        DefaultHttp.FirstBytes = {'C'};
        Defaulted.Candidates.push_back(std::move(DefaultHttp));

        const auto DefaultResult = Compile(std::move(Defaulted));
        ASSERT_FALSE(DefaultResult.has_value());
        EXPECT_EQ(DefaultResult.error(), rec::ProfileError::DeterministicRouteRequiresTlsCandidate);
    }

TEST(ProfileCompileTest, RejectsMixedTrialTlsRouteToCleartextCandidate)
    {
        rec::ProfileSpec Routed;
        Routed.Mode = rec::RecognitionMode::MixedTrial;
        auto Tls = MakeCandidate(CandidateOptions{1, "native", Prism::Contract::ProtocolType::Tls,
                                                  rec::CandidateKind::TlsCarrier});
        Tls.Scheme = "native";
        auto Http = MakeCandidate(2, "http", Prism::Contract::ProtocolType::Http);
        Http.FirstBytes = {'C'};
        Routed.Candidates.push_back(std::move(Tls));
        Routed.Candidates.push_back(std::move(Http));
        Routed.Routes.push_back(MakeRoute("edge.example", 2));

        const auto RoutedResult = Compile(std::move(Routed));
        ASSERT_FALSE(RoutedResult.has_value());
        EXPECT_EQ(RoutedResult.error(), rec::ProfileError::TlsRouteRequiresTlsCandidate);

        rec::ProfileSpec Defaulted;
        Defaulted.Mode = rec::RecognitionMode::MixedTrial;
        Defaulted.DefaultCandidate = 2;
        auto DefaultTls = MakeCandidate(CandidateOptions{1, "native", Prism::Contract::ProtocolType::Tls,
                                                         rec::CandidateKind::TlsCarrier});
        DefaultTls.Scheme = "native";
        auto DefaultHttp = MakeCandidate(2, "http", Prism::Contract::ProtocolType::Http);
        DefaultHttp.FirstBytes = {'C'};
        Defaulted.Candidates.push_back(std::move(DefaultTls));
        Defaulted.Candidates.push_back(std::move(DefaultHttp));

        const auto DefaultResult = Compile(std::move(Defaulted));
        ASSERT_FALSE(DefaultResult.has_value());
        EXPECT_EQ(DefaultResult.error(), rec::ProfileError::TlsRouteRequiresTlsCandidate);
    }

TEST(ProfileCompileTest, RejectsDuplicateCandidateIdAndName)
    {
        rec::ProfileSpec DuplicateId;
        DuplicateId.Mode = rec::RecognitionMode::MixedTrial;
        DuplicateId.Candidates.push_back(MakeCandidate(1, "one", Prism::Contract::ProtocolType::Http));
        DuplicateId.Candidates.push_back(MakeCandidate(1, "two", Prism::Contract::ProtocolType::Socks5));
        EXPECT_EQ(Compile(std::move(DuplicateId)).error(), rec::ProfileError::DuplicateCandidateId);

        rec::ProfileSpec DuplicateName;
        DuplicateName.Mode = rec::RecognitionMode::MixedTrial;
        DuplicateName.Candidates.push_back(MakeCandidate(1, "same", Prism::Contract::ProtocolType::Http));
        DuplicateName.Candidates.push_back(MakeCandidate(2, "same", Prism::Contract::ProtocolType::Socks5));
        EXPECT_EQ(Compile(std::move(DuplicateName)).error(), rec::ProfileError::DuplicateCandidateName);
    }

TEST(ProfileCompileTest, RejectsOutOfRangeCandidateIdAndDanglingRoute)
    {
        rec::ProfileSpec OutOfRange;
        OutOfRange.Mode = rec::RecognitionMode::MixedTrial;
        OutOfRange.Candidates.push_back(
            MakeCandidate(static_cast<rec::CandidateId>(rec::CandidateBitmap::Capacity),
                          "invalid", Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(OutOfRange)).error(), rec::ProfileError::CandidateIdOutOfRange);

        rec::ProfileSpec DanglingRoute;
        DanglingRoute.Mode = rec::RecognitionMode::MixedTrial;
        DanglingRoute.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));
        DanglingRoute.Routes.push_back(MakeRoute("example.com", 2));
        EXPECT_EQ(Compile(std::move(DanglingRoute)).error(), rec::ProfileError::DanglingRoute);
    }

TEST(ProfileCompileTest, RejectsCandidateCountAboveBudget)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxCandidates = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "one", Prism::Contract::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "two", Prism::Contract::ProtocolType::Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::CandidateLimitExceeded);
    }

TEST(ProfileCompileTest, RejectsHardBudgetLimits)
    {
        rec::ProfileSpec ProbeBudget;
        ProbeBudget.Mode = rec::RecognitionMode::MixedTrial;
        ProbeBudget.Budget.MaxProbeBytes = 64 * 1024 + 1;
        ProbeBudget.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(ProbeBudget)).error(), rec::ProfileError::MaxProbeBytesExceeded);

        rec::ProfileSpec CryptoBudget;
        CryptoBudget.Mode = rec::RecognitionMode::MixedTrial;
        CryptoBudget.Budget.MaxCryptoTrials = 17;
        CryptoBudget.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(CryptoBudget)).error(), rec::ProfileError::MaxCryptoTrialsExceeded);
    }

TEST(ProfileCompileTest, RejectsCandidateMetadataBeyondBudget)
    {
        rec::ProfileSpec LongName;
        LongName.Mode = rec::RecognitionMode::MixedTrial;
        LongName.Candidates.push_back(MakeCandidate(1, std::string(129, 'n'), Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(LongName)).error(), rec::ProfileError::CandidateNameTooLong);

        rec::ProfileSpec LongScheme;
        LongScheme.Mode = rec::RecognitionMode::MixedTrial;
        auto SchemeCandidate = MakeCandidate(1, "scheme", Prism::Contract::ProtocolType::Http);
        SchemeCandidate.Scheme.assign(65, 's');
        LongScheme.Candidates.push_back(std::move(SchemeCandidate));
        EXPECT_EQ(Compile(std::move(LongScheme)).error(), rec::ProfileError::SchemeNameTooLong);
    }

TEST(ProfileCompileTest, RejectsRouteCountBeyondBudget)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxRoutes = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));
        Spec.Routes.push_back(MakeRoute("one.example", 1));
        Spec.Routes.push_back(MakeRoute("two.example", 1));

        EXPECT_EQ(Compile(std::move(Spec)).error(), rec::ProfileError::MaxRoutesExceeded);
    }

TEST(ProfileCompileTest, AcceptsHardBudgetBoundariesAndRejectsCandidateBeyondProbeBudget)
    {
        rec::ProfileSpec ProbeBoundary;
        ProbeBoundary.Mode = rec::RecognitionMode::MixedTrial;
        ProbeBoundary.Budget.MaxProbeBytes = 64 * 1024;
        ProbeBoundary.Candidates.push_back(MakeCandidate(1, "probe", Prism::Contract::ProtocolType::Http));
        EXPECT_TRUE(Compile(std::move(ProbeBoundary)).has_value());

        rec::ProfileSpec CryptoBoundary;
        CryptoBoundary.Mode = rec::RecognitionMode::MixedTrial;
        CryptoBoundary.Budget.MaxCryptoTrials = 16;
        CryptoBoundary.Candidates.push_back(
            MakeCandidate(CandidateOptions{1, "crypto", Prism::Contract::ProtocolType::Vmess, rec::CandidateKind::Opaque}));
        EXPECT_TRUE(Compile(std::move(CryptoBoundary)).has_value());

        rec::ProfileSpec CandidateBoundary;
        CandidateBoundary.Mode = rec::RecognitionMode::MixedTrial;
        CandidateBoundary.Budget.MaxProbeBytes = 4;
        auto Candidate = MakeCandidate(1, "too-large", Prism::Contract::ProtocolType::Http);
        Candidate.MinimumBytes = 5;
        CandidateBoundary.Candidates.push_back(std::move(Candidate));
        EXPECT_EQ(Compile(std::move(CandidateBoundary)).error(),
                  rec::ProfileError::MinimumBytesExceedsBudget);
    }

TEST(ProfileCompileTest, RejectsCandidateBudgetCapacityAbove128)
    {
        rec::ProfileSpec AtCapacity;
        AtCapacity.Mode = rec::RecognitionMode::MixedTrial;
        AtCapacity.Budget.MaxCandidates = 128;
        AtCapacity.Candidates.push_back(MakeCandidate(1, "one", Prism::Contract::ProtocolType::Http));
        EXPECT_TRUE(Compile(std::move(AtCapacity)).has_value());

        rec::ProfileSpec BeyondCapacity;
        BeyondCapacity.Mode = rec::RecognitionMode::MixedTrial;
        BeyondCapacity.Budget.MaxCandidates = 129;
        BeyondCapacity.Candidates.push_back(MakeCandidate(1, "one", Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(BeyondCapacity)).error(), rec::ProfileError::CandidateCapacityExceeded);
    }

TEST(ProfileCompileTest, RejectsMissingCandidateCallbacks)
    {
        rec::ProfileSpec MissingInspect;
        MissingInspect.Mode = rec::RecognitionMode::MixedTrial;
        auto InspectCandidate = MakeCandidate(1, "inspect", Prism::Contract::ProtocolType::Http);
        InspectCandidate.Inspect = {};
        MissingInspect.Candidates.push_back(std::move(InspectCandidate));
        EXPECT_EQ(Compile(std::move(MissingInspect)).error(), rec::ProfileError::MissingInspect);

        rec::ProfileSpec MissingCommit;
        MissingCommit.Mode = rec::RecognitionMode::MixedTrial;
        auto CommitCandidate = MakeCandidate(1, "commit", Prism::Contract::ProtocolType::Http);
        CommitCandidate.Commit = {};
        MissingCommit.Candidates.push_back(std::move(CommitCandidate));
        EXPECT_EQ(Compile(std::move(MissingCommit)).error(), rec::ProfileError::MissingCommit);

        rec::ProfileSpec MissingPrepare;
        MissingPrepare.Mode = rec::RecognitionMode::MixedTrial;
        auto PrepareCandidate =
            MakeCandidate(CandidateOptions{1, "opaque", Prism::Contract::ProtocolType::Vmess, rec::CandidateKind::Opaque});
        PrepareCandidate.Prepare = {};
        MissingPrepare.Candidates.push_back(std::move(PrepareCandidate));
        EXPECT_EQ(Compile(std::move(MissingPrepare)).error(), rec::ProfileError::MissingPrepare);
    }

TEST(ProfileCompileTest, RejectsConfiguredCandidateIdMismatch)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 2;
        Spec.Candidates.push_back(MakeCandidate(1, "http", Prism::Contract::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::ConfiguredCandidateNotFound);
    }

TEST(ProfileCompileTest, RejectsEmptyNameInvalidMinimumAndDuplicateRoute)
    {
        rec::ProfileSpec EmptyName;
        EmptyName.Mode = rec::RecognitionMode::MixedTrial;
        EmptyName.Candidates.push_back(MakeCandidate(1, "", Prism::Contract::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(EmptyName)).error(), rec::ProfileError::EmptyCandidateName);

        rec::ProfileSpec InvalidMinimum;
        InvalidMinimum.Mode = rec::RecognitionMode::MixedTrial;
        auto Candidate = MakeCandidate(1, "minimum", Prism::Contract::ProtocolType::Http);
        Candidate.MinimumBytes = 0;
        InvalidMinimum.Candidates.push_back(std::move(Candidate));
        EXPECT_EQ(Compile(std::move(InvalidMinimum)).error(), rec::ProfileError::InvalidMinimumBytes);

        rec::ProfileSpec DuplicateRoute;
        DuplicateRoute.Mode = rec::RecognitionMode::MixedTrial;
        DuplicateRoute.Candidates.push_back(MakeCandidate(1, "route", Prism::Contract::ProtocolType::Http));
        DuplicateRoute.Routes.push_back(MakeRoute("example.com", 1));
        DuplicateRoute.Routes.push_back(MakeRoute("EXAMPLE.COM", 1));
        EXPECT_EQ(Compile(std::move(DuplicateRoute)).error(), rec::ProfileError::DuplicateRoute);
    }

TEST(ProfileCompileTest, RejectsMalformedWildcardRoutes)
    {
        constexpr std::array<std::string_view, 17> InvalidPatterns{
            "*.*.example.com", "*.example.*", "*.example..com", "*.example.com..",
            "foo.*.example.com", "*example.com", "*.example.com/path", "*.example .com",
            "*.example:com", "*.example_com", "*.caf\xC3\xA9.example.com", "*.example.-com",
            "*.example.com-", "-example.com", "example-.com", ".example.com", "example..com"};
        for (const auto Pattern : InvalidPatterns)
        {
            rec::ProfileSpec Spec;
            Spec.Mode = rec::RecognitionMode::MixedTrial;
            Spec.Candidates.push_back(MakeCandidate(1, "route", Prism::Contract::ProtocolType::Http));
            Spec.Routes.push_back(MakeRoute(std::string(Pattern), 1));

            const auto Result = Compile(std::move(Spec));

            ASSERT_FALSE(Result.has_value()) << Pattern;
            EXPECT_EQ(Result.error(), rec::ProfileError::InvalidRoutePattern) << Pattern;
        }
    }

