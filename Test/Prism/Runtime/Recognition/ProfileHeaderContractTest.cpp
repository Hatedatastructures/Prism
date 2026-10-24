/**
 * @file ProfileHeaderContractTest.cpp
 * @brief ProfileModel 独立包含与 Profile 公共类型兼容合同测试。
 */

#include <gtest/gtest.h>

#include <type_traits>

#include <Prism/Runtime/Recognition/Profile.hpp>

namespace
{

    namespace rec = Prism::Recognition;

    static_assert(std::is_aggregate_v<rec::ProfileModel>);
    static_assert(std::is_aggregate_v<rec::ProfileWildcardRoute>);
    static_assert(std::is_same_v<rec::SharedProfile, std::shared_ptr<const rec::Profile>>);

} // namespace

TEST(ProfileModelHeaderContract, ExposesCompiledValueState)
{
    rec::ProfileModel Model;

    EXPECT_EQ(Model.Mode, rec::RecognitionMode::Configured);
    EXPECT_EQ(Model.ConfiguredCandidate, rec::InvalidCandidate);
    EXPECT_EQ(Model.Budget.MaxCandidates, 16U);
    EXPECT_EQ(Model.Candidates, nullptr);
    EXPECT_FALSE(Model.Decision.IsSealed());
    EXPECT_EQ(Model.Routes.DefaultCandidate, rec::InvalidCandidate);
}
