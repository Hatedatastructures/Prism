/**
 * @file DecisionTable.hpp
 * @brief 固定首字节候选索引
 * @details 只保存不可变在线查询所需的位图与最小字节边界，不包含协议 parser、Settings 或 handler。
 *          编译阶段可通过 Add/Set 构造，Seal 发布后仅调用 const Lookup。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <preview/Runtime/Recognition/Types.hpp>

namespace Preview::Recognition
{

    /**
     * @struct DecisionResult
     * @brief 首字节索引查询结果
     */
    struct DecisionResult
    {
        MatchState State{MatchState::Rejected};
        CandidateBitmap Candidates{};
        std::size_t RequiredBytes{1};
        bool Deterministic{false};
    };

    /**
     * @class DecisionTable
     * @brief 256 路首字节索引与 fallback 位图
     * @details fallback 候选可从任意首字节开始，因此 Lookup 会将对应索引与 fallback 求并集。
     */
    class DecisionTable
    {
    public:
        static constexpr std::size_t FirstByteCount = 256;

        DecisionTable() = default;
        DecisionTable(const DecisionTable &) = default;
        DecisionTable(DecisionTable &&) noexcept = default;
        auto operator=(const DecisionTable &) -> DecisionTable & = delete;
        auto operator=(DecisionTable &&) noexcept -> DecisionTable & = delete;

        /**
         * @brief 添加首字节候选
         * @param FirstByte 首字节
         * @param Id 候选编号
         * @return 候选编号有效返回 true
         */
        [[nodiscard]] auto AddFirstByte(std::uint8_t FirstByte, CandidateId Id) noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            return FirstByte_[FirstByte].Set(Id);
        }

        /**
         * @brief 添加任意首字节候选
         * @param Id 候选编号
         * @return 候选编号有效返回 true
         */
        [[nodiscard]] auto AddFallback(CandidateId Id) noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            return Fallback_.Set(Id);
        }

        /**
         * @brief 设置首字节位图
         * @param FirstByte 首字节
         * @param Candidates 候选位图
         * @return 未发布且设置成功返回 true
         */
        [[nodiscard]] auto SetFirstByte(std::uint8_t FirstByte,
                                        const CandidateBitmap &Candidates) noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            FirstByte_[FirstByte] = Candidates;
            return true;
        }

        /**
         * @brief 设置 fallback 位图
         * @param Candidates 候选位图
         * @return 未发布且设置成功返回 true
         */
        [[nodiscard]] auto SetFallback(const CandidateBitmap &Candidates) noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            Fallback_ = Candidates;
            return true;
        }

        /**
         * @brief 设置候选所需最小字节数
         * @param Id 候选编号
         * @param MinimumBytes 最小边界（至少为 1）
         * @return 候选编号有效且边界合法返回 true
         */
        [[nodiscard]] auto SetMinimumBytes(CandidateId Id, std::size_t MinimumBytes) noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            const auto Index = static_cast<std::size_t>(Id);
            if (Index >= CandidateBitmap::Capacity || MinimumBytes == 0)
            {
                return false;
            }
            MinimumBytes_[Index] = MinimumBytes;
            return true;
        }

        /**
         * @brief 发布决策表并禁止后续构造修改
         * @return 首次发布返回 true，重复调用返回 false
         */
        [[nodiscard]] auto Seal() noexcept -> bool
        {
            if (Sealed_)
            {
                return false;
            }
            Sealed_ = true;
            return true;
        }

        /**
         * @brief 查询决策表是否已发布
         * @return 已发布返回 true
         */
        [[nodiscard]] auto IsSealed() const noexcept -> bool
        {
            return Sealed_;
        }

        /**
         * @brief 查询指定首字节候选
         * @param FirstByte 首字节
         * @return 首字节索引与 fallback 的并集
         */
        [[nodiscard]] auto Lookup(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
        {
            auto Candidates = FirstByte_[FirstByte];
            Candidates.Union(Fallback_);
            return Candidates;
        }

        /**
         * @brief 按输入数据查询候选
         * @param Data 当前已捕获数据
         * @return NeedMore/Rejected/Structural 以及候选位图
         */
        [[nodiscard]] auto Lookup(std::span<const std::byte> Data) const noexcept -> DecisionResult
        {
            DecisionResult Result;
            if (Data.empty())
            {
                const auto Indexed = IndexedCandidates();
                Result.Candidates = Indexed;
                const bool HasFallback = Fallback_.Any();
                Result.Candidates.Union(Fallback_);
                if (Result.Candidates.Empty())
                {
                    Result.State = MatchState::Rejected;
                    return Result;
                }
                if (HasFallback)
                {
                    Result.RequiredBytes = RequiredBytesFor(Result.Candidates);
                }
                else
                {
                    Result.RequiredBytes = MinimumRequiredBytesFor(Indexed);
                }
                Result.State = MatchState::NeedMore;
                return Result;
            }

            const auto FirstByte = std::to_integer<std::uint8_t>(Data.front());
            Result.Candidates = Lookup(FirstByte);
            if (Result.Candidates.Empty())
            {
                Result.State = MatchState::Rejected;
                return Result;
            }

            Result.RequiredBytes = RequiredBytesFor(Result.Candidates);
            if (Data.size() < Result.RequiredBytes)
            {
                Result.State = MatchState::NeedMore;
                return Result;
            }

            Result.State = MatchState::Structural;
            Result.Deterministic = Result.Candidates.Count() == 1;
            return Result;
        }

        /// 获取首字节索引位图（编译/测试用）
        [[nodiscard]] auto CandidatesFor(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
        {
            return Lookup(FirstByte);
        }

        /// 获取 fallback 位图（编译/测试用）
        [[nodiscard]] auto Fallback() const noexcept -> CandidateBitmap
        {
            return Fallback_;
        }

    private:
        [[nodiscard]] auto IndexedCandidates() const noexcept -> CandidateBitmap
        {
            CandidateBitmap Candidates;
            for (const auto &Bucket : FirstByte_)
            {
                Candidates.Union(Bucket);
            }
            return Candidates;
        }

        [[nodiscard]] auto MinimumRequiredBytesFor(const CandidateBitmap &Candidates) const noexcept
            -> std::size_t
        {
            std::size_t RequiredBytes = 1;
            bool Found = false;
            for (std::size_t Index = 0; Index < CandidateBitmap::Capacity; ++Index)
            {
                const auto Id = static_cast<CandidateId>(Index);
                if (Candidates.Test(Id))
                {
                    const auto MinimumBytes = (std::max)(std::size_t{1}, MinimumBytes_[Index]);
                    if (Found)
                    {
                        RequiredBytes = (std::min)(RequiredBytes, MinimumBytes);
                    }
                    else
                    {
                        RequiredBytes = MinimumBytes;
                    }
                    Found = true;
                }
            }
            return RequiredBytes;
        }

        [[nodiscard]] auto RequiredBytesFor(const CandidateBitmap &Candidates) const noexcept -> std::size_t
        {
            std::size_t RequiredBytes = 1;
            for (std::size_t Index = 0; Index < CandidateBitmap::Capacity; ++Index)
            {
                const auto Id = static_cast<CandidateId>(Index);
                if (Candidates.Test(Id))
                {
                    RequiredBytes = (std::max)(RequiredBytes, MinimumBytes_[Index]);
                }
            }
            return RequiredBytes;
        }

        std::array<CandidateBitmap, FirstByteCount> FirstByte_{};
        CandidateBitmap Fallback_{};
        std::array<std::size_t, CandidateBitmap::Capacity> MinimumBytes_{};
        bool Sealed_{false};
    };

} // namespace Preview::Recognition
