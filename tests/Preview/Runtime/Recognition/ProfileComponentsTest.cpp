/**
 * @file ProfileComponentsTest.cpp
 * @brief Recognition Profile 拆分后的候选、决策和路由组件测试
 */

#include <Preview/Runtime/Recognition/Candidate.hpp>
#include <Preview/Runtime/Recognition/CandidateHandle.hpp>
#include <Preview/Runtime/Recognition/ProfileDecision.hpp>
#include <Preview/Runtime/Recognition/ProfileRoutes.hpp>
#include <Preview/Runtime/Recognition/ProfileTypes.hpp>
#include <Preview/Runtime/Recognition/ProfileValidation.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

namespace
{

    namespace rec = Preview::Recognition;

    auto MakeCandidate(rec::CandidateId Id, std::string Name) -> rec::CandidateSpec
    {
        rec::CandidateSpec Candidate;
        Candidate.Id = Id;
        Candidate.Name = std::move(Name);
        return Candidate;
    }

    TEST(ProfileComponentsTest, CandidateStoreKeepsIdAddressableValues)
    {
        rec::CandidateStore Store({MakeCandidate(7, "first"), MakeCandidate(9, "second")});

        ASSERT_NE(Store.Find(7), nullptr);
        EXPECT_EQ(Store.Find(7)->Name, "first");
        EXPECT_EQ(Store.Find(9)->Name, "second");
        EXPECT_EQ(Store.Find(8), nullptr);
    }

    TEST(ProfileComponentsTest, DecisionBuilderPublishesFirstByteAndFallbackIndexes)
    {
        auto First = MakeCandidate(7, "first");
        First.FirstBytes = {0x16};
        auto Fallback = MakeCandidate(9, "fallback");
        Fallback.Fallback = true;

        rec::DecisionTable Decision;
        EXPECT_FALSE(rec::ProfileSupport::BuildDecisionTable({First, Fallback}, Decision));
        EXPECT_TRUE(Decision.IsSealed());
        EXPECT_TRUE(Decision.Lookup(std::uint8_t{0x16}).Test(7));
        EXPECT_TRUE(Decision.Lookup(std::uint8_t{0x16}).Test(9));
    }

    TEST(ProfileComponentsTest, RouteBuilderPreservesExactAndLongestWildcardPrecedence)
    {
        const std::vector Candidates{MakeCandidate(7, "exact"), MakeCandidate(9, "wildcard")};
        const std::vector Routes{rec::RouteBinding{"*.example.com", 9},
            rec::RouteBinding{"edge.example.com", 7}};
        rec::ProfileRouteIndex Index;
        const rec::ProfileRouteBuildContext Context{rec::RecognitionMode::MixedTrial, Routes, Candidates,
            rec::RecognitionBudget{}, rec::InvalidCandidate, Index};

        EXPECT_FALSE(rec::ProfileSupport::BuildRoutes(Context));
        EXPECT_EQ(rec::ProfileSupport::LookupRoute(Index, "edge.example.com"), 7);
        EXPECT_EQ(rec::ProfileSupport::LookupRoute(Index, "other.example.com"), 9);
        EXPECT_FALSE(rec::ProfileSupport::LookupRoute(Index, "deep.other.example.com"));
    }

} // namespace
