/**
 * @file ConfiguredComponentsTest.cpp
 * @brief Configured 识别窄边界组件的编译与状态合同测试。
 */

#include <Preview/Runtime/Recognition/CandidateSelection.hpp>
#include <Preview/Runtime/Recognition/ConfiguredAcceptor.hpp>
#include <Preview/Runtime/Recognition/RecognitionConfig.hpp>

#include <gtest/gtest.h>

#include <type_traits>

namespace
{

    namespace rec = Preview::Recognition;

    TEST(ConfiguredComponentsTest, RecognitionConfigExposesCallerOwnedControlState)
    {
        rec::RecognitionControl Control;
        EXPECT_FALSE(Control.IsCancelled());
        EXPECT_FALSE(Control.IsExpired());

        Control.Cancelled = [] { return true; };
        EXPECT_TRUE(Control.IsCancelled());
    }

    TEST(ConfiguredComponentsTest, CandidateSelectionStartsWithoutASelectedRoute)
    {
        const rec::detail::RouteDecision Decision;
        EXPECT_FALSE(Decision.Candidate.has_value());
        EXPECT_FALSE(Decision.Applicable);
        EXPECT_FALSE(Decision.NeedMore);
        EXPECT_EQ(Decision.Required, 0U);
    }

    TEST(ConfiguredComponentsTest, PreparedCandidateOwnsOneShotAcceptance)
    {
        static_assert(std::is_move_constructible_v<rec::PreparedCandidate>);
        static_assert(!std::is_copy_constructible_v<rec::PreparedCandidate>);

        const rec::PreparedCandidate Candidate;
        EXPECT_FALSE(Candidate.IsValid());
        EXPECT_EQ(Candidate.Id(), rec::InvalidCandidate);
    }

} // namespace
