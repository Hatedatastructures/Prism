/**
 * @file ProfileModel.hpp
 * @brief Preview 识别 Profile 的已编译值模型。
 * @details 只保存 Profile 发布后所需的值和不可变 owner；不包含编译算法或在线状态机。
 */

#pragma once

#include <Preview/Runtime/Recognition/Candidate.hpp>
#include <Preview/Runtime/Recognition/DecisionTable.hpp>
#include <Preview/Runtime/Recognition/ProfileRoutes.hpp>
#include <Preview/Runtime/Recognition/ProfileTypes.hpp>

#include <memory>

namespace Preview::Recognition
{

    class Profile;
    using SharedProfile = std::shared_ptr<const Profile>;

    /**
     * @struct ProfileModel
     * @brief Profile 构造所需的已编译值状态。
     * @details CandidateStore、DecisionTable 和 ProfileRouteIndex 在构造完成后只读发布；
     *          该模型本身不执行校验、索引构造或识别状态转移。
     */
    struct ProfileModel
    {
        RecognitionMode Mode{RecognitionMode::Configured};
        CandidateId ConfiguredCandidate{InvalidCandidate};
        RecognitionBudget Budget{};
        SharedCandidateStore Candidates{};
        DecisionTable Decision;
        ProfileRouteIndex Routes;
    };

} // namespace Preview::Recognition
