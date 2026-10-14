/**
 * @file MixedTrialPlan.hpp
 * @brief MixedTrial 候选计划和结构检查 owner。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <vector>

#include <Preview/Runtime/Recognition/CandidateSelection.hpp>
#include <Preview/Runtime/Recognition/MixedTrialModel.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>

namespace Preview::Recognition
{

    /**
     * @class MixedTrialPlan
     * @brief 按 Profile 发布顺序建立候选集合和下一次读取边界。
     * @details 只执行索引、边界和纯结构检查，不执行认证 I/O。
     */
    class MixedTrialPlan
    {
    public:
        explicit MixedTrialPlan(SharedProfile Profile) : Profile_(std::move(Profile))
        {
        }

        [[nodiscard]] auto AllCandidates() const -> std::vector<CandidateId>
        {
            std::vector<CandidateId> Result;
            if (!Profile_)
            {
                return Result;
            }
            Result.reserve(Profile_->CandidateCount());
            for (std::size_t Index = 0; Index < Profile_->CandidateCount(); ++Index)
            {
                Result.push_back(Profile_->CandidateIdAt(Index));
            }
            return Result;
        }

        [[nodiscard]] auto MinimumBoundary(const std::vector<CandidateId> &Candidates) const -> std::size_t
        {
            if (!Profile_)
            {
                return 1;
            }
            std::size_t Result = Profile_->Budget().MaxProbeBytes;
            for (const auto Id : Candidates)
            {
                Result = (std::min)(Result, Profile_->FindCandidate(Id).MinimumBytes());
            }
            return (std::max)(std::size_t{1}, Result);
        }

        [[nodiscard]] auto IndexedCandidates(const ProbeBuffer &Buffer) const -> std::vector<CandidateId>
        {
            if (!Profile_ || Buffer.Data().empty())
            {
                return {};
            }
            const auto FirstByte = std::to_integer<std::uint8_t>(Buffer.Data().front());
            const auto Bitmap = Profile_->LookupCandidates(FirstByte);
            const auto Ordered = AllCandidates();
            std::vector<CandidateId> Result;
            Result.reserve(Bitmap.Count());
            for (const auto Id : Ordered)
            {
                if (Bitmap.Test(Id))
                {
                    Result.push_back(Id);
                }
            }
            return Result;
        }

        [[nodiscard]] auto InspectCandidates(const std::vector<CandidateId> &Candidates,
                                             const ProbeSnapshot &Snapshot) const -> MixedTrialInspection
        {
            MixedTrialInspection Result;
            Result.Active.reserve(Candidates.size());
            for (const auto Id : Candidates)
            {
                const auto Handle = Profile_->FindCandidate(Id);
                const auto State = Handle.Inspect(Snapshot);
                if (State == MatchState::Rejected)
                {
                    continue;
                }
                Result.Active.push_back(Id);
                if (State == MatchState::Structural || State == MatchState::Authenticated)
                {
                    Result.Structural.push_back(Id);
                }
                if (State == MatchState::NeedMore)
                {
                    Result.NeedMore = true;
                    const auto Minimum = Handle.MinimumBytes();
                    std::size_t Boundary = Snapshot.Size() + 1;
                    if (Snapshot.Size() < Minimum)
                    {
                        Boundary = Minimum;
                    }
                    Result.Required = Result.Required == 0 ? Boundary : (std::min)(Result.Required, Boundary);
                }
            }
            return Result;
        }

    private:
        SharedProfile Profile_;
    };

} // namespace Preview::Recognition
