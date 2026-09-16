/**
 * @file ProfileCompileTest.cpp
 * @brief Profile 编译与启动配置校验测试
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <Preview/Runtime/Recognition/Profile.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace rec = Preview::Recognition;

    struct CandidateOptions
    {
        rec::CandidateId Id{rec::InvalidCandidate};
        std::string Name;
        rec::ProtocolType Protocol{rec::ProtocolType::Unknown};
        rec::CandidateKind Kind{rec::CandidateKind::Cleartext};
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
    };

    static_assert(std::is_aggregate_v<rec::CandidateSpec>);
    static_assert(!std::is_constructible_v<rec::CandidateSpec, rec::CandidateId, rec::ProtocolType,
                                           rec::CandidateKind, std::uint16_t, rec::InspectFn, rec::PrepareFn,
                                           rec::CommitFn>);
    static_assert(!std::is_constructible_v<rec::CandidateSpec, rec::CandidateId, std::string, rec::ProtocolType,
                                           rec::CandidateKind, std::uint16_t, rec::InspectFn, rec::PrepareFn,
                                           rec::CommitFn>);

    auto MakeCandidate(CandidateOptions Options) -> rec::CandidateSpec
    {
        rec::CandidateSpec Candidate;
        Candidate.Id = Options.Id;
        Candidate.Name = std::move(Options.Name);
        Candidate.Protocol = Options.Protocol;
        Candidate.Kind = Options.Kind;
        Candidate.Priority = Options.Priority;
        Candidate.Tier = Options.Tier;
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) -> rec::MatchState
        {
            return rec::MatchState::Structural;
        };
        Candidate.Commit = [](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            rec::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = rec::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        if (Options.Kind == rec::CandidateKind::Opaque)
        {
            Candidate.Prepare = [](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
            {
                rec::PrepareResult Result;
                Result.Candidate = Context.Candidate;
                Result.Status = rec::RecognitionStatus::Accepted;
                co_return Result;
            };
        }
        return Candidate;
    }

    auto MakeCandidate(rec::CandidateId Id, std::string Name, rec::ProtocolType Protocol) -> rec::CandidateSpec
    {
        return MakeCandidate(CandidateOptions{Id, std::move(Name), Protocol});
    }

    auto MakeRoute(std::string Pattern, rec::CandidateId Candidate) -> rec::RouteBinding
    {
        rec::RouteBinding Route;
        Route.Pattern = std::move(Pattern);
        Route.Candidate = Candidate;
        return Route;
    }

    auto Compile(rec::ProfileSpec Spec)
    {
        return rec::Profile::Compile(std::move(Spec));
    }

    TEST(ProfileCompileTest, CompilesSingleConfiguredCandidate)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Candidates.push_back(MakeCandidate(7, "http", rec::ProtocolType::Http));

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
        Multiple.Candidates.push_back(MakeCandidate(7, "http", rec::ProtocolType::Http));
        Multiple.Candidates.push_back(MakeCandidate(8, "socks", rec::ProtocolType::Socks5));
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
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;

        auto Http = MakeCandidate(1, "http", rec::ProtocolType::Http);
        Http.FirstBytes = {0x16};
        auto Socks5 = MakeCandidate(2, "socks5", rec::ProtocolType::Socks5);
        Socks5.FirstBytes = {0x05};
        Spec.Candidates.push_back(std::move(Http));
        Spec.Candidates.push_back(std::move(Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_TRUE(Result.has_value());
        ASSERT_NE(Result.value(), nullptr);
        EXPECT_EQ(Result.value()->Mode(), rec::RecognitionMode::DeterministicRoute);
        EXPECT_EQ(Result.value()->CandidateCount(), 2U);
        EXPECT_EQ(Result.value()->ConfiguredCandidate(), rec::InvalidCandidate);
    }

    TEST(ProfileCompileTest, RejectsConfiguredCandidateInDeterministicRoute)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;
        Spec.ConfiguredCandidate = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::ConfiguredCandidateNotAllowed);
    }

    TEST(ProfileCompileTest, RejectsUndiscriminatedDeterministicCandidates)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;
        Spec.Candidates.push_back(MakeCandidate(1, "first", rec::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "second", rec::ProtocolType::Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DeterministicCandidateNeedsSelector);
    }

    TEST(ProfileCompileTest, RejectsOverlappingDeterministicPlainSelectors)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;
        auto First = MakeCandidate(1, "first", rec::ProtocolType::Http);
        First.FirstBytes = {0x43};
        auto Second = MakeCandidate(2, "second", rec::ProtocolType::Socks5);
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
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;
        auto First = MakeCandidate(CandidateOptions{1, "first-tls", rec::ProtocolType::Tls,
                                                     rec::CandidateKind::TlsCarrier});
        First.Scheme = "native";
        auto Second = MakeCandidate(CandidateOptions{2, "second-tls", rec::ProtocolType::Tls,
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
        auto Http = MakeCandidate(1, "http", rec::ProtocolType::Http);
        Http.FirstBytes = {'C'};
        Routed.Candidates.push_back(std::move(Http));
        Routed.Routes.push_back(MakeRoute("edge.example", 1));

        const auto RoutedResult = Compile(std::move(Routed));
        ASSERT_FALSE(RoutedResult.has_value());
        EXPECT_EQ(RoutedResult.error(), rec::ProfileError::DeterministicRouteRequiresTlsCandidate);

        rec::ProfileSpec Defaulted;
        Defaulted.Mode = rec::RecognitionMode::Deterministic;
        Defaulted.DefaultCandidate = 1;
        auto DefaultHttp = MakeCandidate(1, "http", rec::ProtocolType::Http);
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
        auto Tls = MakeCandidate(CandidateOptions{1, "native", rec::ProtocolType::Tls,
                                                  rec::CandidateKind::TlsCarrier});
        Tls.Scheme = "native";
        auto Http = MakeCandidate(2, "http", rec::ProtocolType::Http);
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
        auto DefaultTls = MakeCandidate(CandidateOptions{1, "native", rec::ProtocolType::Tls,
                                                         rec::CandidateKind::TlsCarrier});
        DefaultTls.Scheme = "native";
        auto DefaultHttp = MakeCandidate(2, "http", rec::ProtocolType::Http);
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
        DuplicateId.Candidates.push_back(MakeCandidate(1, "one", rec::ProtocolType::Http));
        DuplicateId.Candidates.push_back(MakeCandidate(1, "two", rec::ProtocolType::Socks5));
        EXPECT_EQ(Compile(std::move(DuplicateId)).error(), rec::ProfileError::DuplicateCandidateId);

        rec::ProfileSpec DuplicateName;
        DuplicateName.Mode = rec::RecognitionMode::MixedTrial;
        DuplicateName.Candidates.push_back(MakeCandidate(1, "same", rec::ProtocolType::Http));
        DuplicateName.Candidates.push_back(MakeCandidate(2, "same", rec::ProtocolType::Socks5));
        EXPECT_EQ(Compile(std::move(DuplicateName)).error(), rec::ProfileError::DuplicateCandidateName);
    }

    TEST(ProfileCompileTest, RejectsOutOfRangeCandidateIdAndDanglingRoute)
    {
        rec::ProfileSpec OutOfRange;
        OutOfRange.Mode = rec::RecognitionMode::MixedTrial;
        OutOfRange.Candidates.push_back(
            MakeCandidate(static_cast<rec::CandidateId>(rec::CandidateBitmap::Capacity),
                          "invalid", rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(OutOfRange)).error(), rec::ProfileError::CandidateIdOutOfRange);

        rec::ProfileSpec DanglingRoute;
        DanglingRoute.Mode = rec::RecognitionMode::MixedTrial;
        DanglingRoute.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));
        DanglingRoute.Routes.push_back(MakeRoute("example.com", 2));
        EXPECT_EQ(Compile(std::move(DanglingRoute)).error(), rec::ProfileError::DanglingRoute);
    }

    TEST(ProfileCompileTest, RejectsCandidateCountAboveBudget)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxCandidates = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "one", rec::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "two", rec::ProtocolType::Socks5));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::CandidateLimitExceeded);
    }

    TEST(ProfileCompileTest, RejectsHardBudgetLimits)
    {
        rec::ProfileSpec ProbeBudget;
        ProbeBudget.Mode = rec::RecognitionMode::MixedTrial;
        ProbeBudget.Budget.MaxProbeBytes = 64 * 1024 + 1;
        ProbeBudget.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(ProbeBudget)).error(), rec::ProfileError::MaxProbeBytesExceeded);

        rec::ProfileSpec CryptoBudget;
        CryptoBudget.Mode = rec::RecognitionMode::MixedTrial;
        CryptoBudget.Budget.MaxCryptoTrials = 17;
        CryptoBudget.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(CryptoBudget)).error(), rec::ProfileError::MaxCryptoTrialsExceeded);
    }

    TEST(ProfileCompileTest, RejectsCandidateMetadataBeyondBudget)
    {
        rec::ProfileSpec LongName;
        LongName.Mode = rec::RecognitionMode::MixedTrial;
        LongName.Candidates.push_back(MakeCandidate(1, std::string(129, 'n'), rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(LongName)).error(), rec::ProfileError::CandidateNameTooLong);

        rec::ProfileSpec LongScheme;
        LongScheme.Mode = rec::RecognitionMode::MixedTrial;
        auto SchemeCandidate = MakeCandidate(1, "scheme", rec::ProtocolType::Http);
        SchemeCandidate.Scheme.assign(65, 's');
        LongScheme.Candidates.push_back(std::move(SchemeCandidate));
        EXPECT_EQ(Compile(std::move(LongScheme)).error(), rec::ProfileError::SchemeNameTooLong);
    }

    TEST(ProfileCompileTest, RejectsRouteCountBeyondBudget)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxRoutes = 1;
        Spec.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));
        Spec.Routes.push_back(MakeRoute("one.example", 1));
        Spec.Routes.push_back(MakeRoute("two.example", 1));

        EXPECT_EQ(Compile(std::move(Spec)).error(), rec::ProfileError::MaxRoutesExceeded);
    }

    TEST(ProfileCompileTest, AcceptsHardBudgetBoundariesAndRejectsCandidateBeyondProbeBudget)
    {
        rec::ProfileSpec ProbeBoundary;
        ProbeBoundary.Mode = rec::RecognitionMode::MixedTrial;
        ProbeBoundary.Budget.MaxProbeBytes = 64 * 1024;
        ProbeBoundary.Candidates.push_back(MakeCandidate(1, "probe", rec::ProtocolType::Http));
        EXPECT_TRUE(Compile(std::move(ProbeBoundary)).has_value());

        rec::ProfileSpec CryptoBoundary;
        CryptoBoundary.Mode = rec::RecognitionMode::MixedTrial;
        CryptoBoundary.Budget.MaxCryptoTrials = 16;
        CryptoBoundary.Candidates.push_back(
            MakeCandidate(CandidateOptions{1, "crypto", rec::ProtocolType::Vmess, rec::CandidateKind::Opaque}));
        EXPECT_TRUE(Compile(std::move(CryptoBoundary)).has_value());

        rec::ProfileSpec CandidateBoundary;
        CandidateBoundary.Mode = rec::RecognitionMode::MixedTrial;
        CandidateBoundary.Budget.MaxProbeBytes = 4;
        auto Candidate = MakeCandidate(1, "too-large", rec::ProtocolType::Http);
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
        AtCapacity.Candidates.push_back(MakeCandidate(1, "one", rec::ProtocolType::Http));
        EXPECT_TRUE(Compile(std::move(AtCapacity)).has_value());

        rec::ProfileSpec BeyondCapacity;
        BeyondCapacity.Mode = rec::RecognitionMode::MixedTrial;
        BeyondCapacity.Budget.MaxCandidates = 129;
        BeyondCapacity.Candidates.push_back(MakeCandidate(1, "one", rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(BeyondCapacity)).error(), rec::ProfileError::CandidateCapacityExceeded);
    }

    TEST(ProfileCompileTest, RejectsMissingCandidateCallbacks)
    {
        rec::ProfileSpec MissingInspect;
        MissingInspect.Mode = rec::RecognitionMode::MixedTrial;
        auto InspectCandidate = MakeCandidate(1, "inspect", rec::ProtocolType::Http);
        InspectCandidate.Inspect = {};
        MissingInspect.Candidates.push_back(std::move(InspectCandidate));
        EXPECT_EQ(Compile(std::move(MissingInspect)).error(), rec::ProfileError::MissingInspect);

        rec::ProfileSpec MissingCommit;
        MissingCommit.Mode = rec::RecognitionMode::MixedTrial;
        auto CommitCandidate = MakeCandidate(1, "commit", rec::ProtocolType::Http);
        CommitCandidate.Commit = {};
        MissingCommit.Candidates.push_back(std::move(CommitCandidate));
        EXPECT_EQ(Compile(std::move(MissingCommit)).error(), rec::ProfileError::MissingCommit);

        rec::ProfileSpec MissingPrepare;
        MissingPrepare.Mode = rec::RecognitionMode::MixedTrial;
        auto PrepareCandidate =
            MakeCandidate(CandidateOptions{1, "opaque", rec::ProtocolType::Vmess, rec::CandidateKind::Opaque});
        PrepareCandidate.Prepare = {};
        MissingPrepare.Candidates.push_back(std::move(PrepareCandidate));
        EXPECT_EQ(Compile(std::move(MissingPrepare)).error(), rec::ProfileError::MissingPrepare);
    }

    TEST(ProfileCompileTest, RejectsConfiguredCandidateIdMismatch)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 2;
        Spec.Candidates.push_back(MakeCandidate(1, "http", rec::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::ConfiguredCandidateNotFound);
    }

    TEST(ProfileCompileTest, RejectsEmptyNameInvalidMinimumAndDuplicateRoute)
    {
        rec::ProfileSpec EmptyName;
        EmptyName.Mode = rec::RecognitionMode::MixedTrial;
        EmptyName.Candidates.push_back(MakeCandidate(1, "", rec::ProtocolType::Http));
        EXPECT_EQ(Compile(std::move(EmptyName)).error(), rec::ProfileError::EmptyCandidateName);

        rec::ProfileSpec InvalidMinimum;
        InvalidMinimum.Mode = rec::RecognitionMode::MixedTrial;
        auto Candidate = MakeCandidate(1, "minimum", rec::ProtocolType::Http);
        Candidate.MinimumBytes = 0;
        InvalidMinimum.Candidates.push_back(std::move(Candidate));
        EXPECT_EQ(Compile(std::move(InvalidMinimum)).error(), rec::ProfileError::InvalidMinimumBytes);

        rec::ProfileSpec DuplicateRoute;
        DuplicateRoute.Mode = rec::RecognitionMode::MixedTrial;
        DuplicateRoute.Candidates.push_back(MakeCandidate(1, "route", rec::ProtocolType::Http));
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
            Spec.Candidates.push_back(MakeCandidate(1, "route", rec::ProtocolType::Http));
            Spec.Routes.push_back(MakeRoute(std::string(Pattern), 1));

            const auto Result = Compile(std::move(Spec));

            ASSERT_FALSE(Result.has_value()) << Pattern;
            EXPECT_EQ(Result.error(), rec::ProfileError::InvalidRoutePattern) << Pattern;
        }
    }

    TEST(ProfileCompileTest, RejectsEarlyResponseAndOpaqueMixedTrial)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{1, "socks", rec::ProtocolType::Socks5,
                                           rec::CandidateKind::EarlyResponse}));
        Spec.Candidates.push_back(
            MakeCandidate(CandidateOptions{2, "vmess", rec::ProtocolType::Vmess, rec::CandidateKind::Opaque}));

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
            MakeCandidate(CandidateOptions{30, "hysteria2", rec::ProtocolType::Hysteria2,
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
            MakeCandidate(CandidateOptions{31, "tls", rec::ProtocolType::Http,
                                           rec::CandidateKind::TlsCarrier}));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::MissingCarrierScheme);
    }

    TEST(ProfileCompileTest, SortsCandidatesStablyByTierThenPriority)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{1, "late", rec::ProtocolType::Http,
                                                                  rec::CandidateKind::Cleartext, 2, 1}));
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{2, "first", rec::ProtocolType::Socks5,
                                                                  rec::CandidateKind::Cleartext, 1, 0}));
        Spec.Candidates.push_back(MakeCandidate(CandidateOptions{3, "same-tier", rec::ProtocolType::Tls,
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
        auto Http = MakeCandidate(1, "http", rec::ProtocolType::Http);
        Http.FirstBytes = {0x47};
        Http.MinimumBytes = 4;
        Spec.Candidates.push_back(std::move(Http));
        auto Socks = MakeCandidate(2, "socks", rec::ProtocolType::Socks5);
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
        Spec.Mode = rec::RecognitionMode::DeterministicRoute;
        auto Tls = MakeCandidate(CandidateOptions{1, "native", rec::ProtocolType::Tls,
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
        Spec.Candidates.push_back(MakeCandidate(1, "base", rec::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "sub", rec::ProtocolType::Socks5));
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
        ExactSpec.Candidates.push_back(MakeCandidate(1, "base", rec::ProtocolType::Http));
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
        Spec.Candidates.push_back(MakeCandidate(1, "specific", rec::ProtocolType::Http));
        Spec.Candidates.push_back(MakeCandidate(2, "fallback", rec::ProtocolType::Socks5));
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
        Spec.Candidates.push_back(MakeCandidate(1, "candidate", rec::ProtocolType::Http));

        const auto Result = Compile(std::move(Spec));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), rec::ProfileError::DanglingRoute);
    }

    TEST(ProfileCompileTest, KeepsOpaqueProtocolMagicOnFallbackWithoutExplicitFirstBytes)
    {
        constexpr std::array<std::pair<rec::CandidateId, rec::ProtocolType>, 3> OpaqueProtocols{
            std::pair{1, rec::ProtocolType::Trojan}, std::pair{2, rec::ProtocolType::Vmess},
            std::pair{3, rec::ProtocolType::Vless}};
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
        Spec.Candidates.push_back(MakeCandidate(1, "owned", rec::ProtocolType::Http));
        const auto Result = Compile(std::move(Spec));
        ASSERT_TRUE(Result.has_value());

        auto Owner = Result.value();
        auto Handle = Owner->FindCandidate(1);
        Owner.reset();

        ASSERT_TRUE(Handle.IsValid());
        EXPECT_EQ(Handle.Id(), 1);
        EXPECT_EQ(Handle.Name(), "owned");
        EXPECT_TRUE(Handle.Scheme().empty());
        EXPECT_EQ(Handle.Protocol(), rec::ProtocolType::Http);
        EXPECT_EQ(Handle.Inspect(rec::ProbeSnapshot{}), rec::MatchState::Structural);
    }

    TEST(ProfileCompileTest, CandidateHandleExposesOuterScheme)
    {
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        auto Candidate = MakeCandidate(7, "edge-vless", rec::ProtocolType::Vless);
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
        auto Candidate = MakeCandidate(1, "throws", rec::ProtocolType::Http);
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

} // namespace
