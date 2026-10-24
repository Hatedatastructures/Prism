/**
 * @file DecisionTable.hpp
 * @brief 固定首字节候选索引
 * @details 只保存不可变在线查询所需的位图与最小字节边界，不包含协议 parser、Settings 或 handler。
 *          编译阶段可通过 Add/Set 构造，Seal 发布后仅调用 const Lookup。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <Prism/Runtime/Recognition/Types.hpp>

namespace Prism::Recognition
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
        [[nodiscard]] auto AddFirstByte(std::uint8_t FirstByte, CandidateId Id) noexcept -> bool;

        /**
         * @brief 添加任意首字节候选
         * @param Id 候选编号
         * @return 候选编号有效返回 true
         */
        [[nodiscard]] auto AddFallback(CandidateId Id) noexcept -> bool;

        /**
         * @brief 设置首字节位图
         * @param FirstByte 首字节
         * @param Candidates 候选位图
         * @return 未发布且设置成功返回 true
         */
        [[nodiscard]] auto SetFirstByte(
            std::uint8_t FirstByte, const CandidateBitmap &Candidates) noexcept -> bool;

        /**
         * @brief 设置 fallback 位图
         * @param Candidates 候选位图
         * @return 未发布且设置成功返回 true
         */
        [[nodiscard]] auto SetFallback(const CandidateBitmap &Candidates) noexcept -> bool;

        /**
         * @brief 设置候选所需最小字节数
         * @param Id 候选编号
         * @param MinimumBytes 最小边界（至少为 1）
         * @return 候选编号有效且边界合法返回 true
         */
        [[nodiscard]] auto SetMinimumBytes(CandidateId Id, std::size_t MinimumBytes) noexcept -> bool;

        /**
         * @brief 发布决策表并禁止后续构造修改
         * @return 首次发布返回 true，重复调用返回 false
         */
        [[nodiscard]] auto Seal() noexcept -> bool;

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
        [[nodiscard]] auto Lookup(std::uint8_t FirstByte) const noexcept -> CandidateBitmap;

        /**
         * @brief 按输入数据查询候选
         * @param Data 当前已捕获数据
         * @return NeedMore/Rejected/Structural 以及候选位图
         */
        [[nodiscard]] auto Lookup(std::span<const std::byte> Data) const noexcept -> DecisionResult;

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
        [[nodiscard]] auto IndexedCandidates() const noexcept -> CandidateBitmap;

        [[nodiscard]] auto MinimumRequiredBytesFor(const CandidateBitmap &Candidates) const noexcept
            -> std::size_t;

        [[nodiscard]] auto RequiredBytesFor(const CandidateBitmap &Candidates) const noexcept
            -> std::size_t;

        std::array<CandidateBitmap, FirstByteCount> FirstByte_{};
        CandidateBitmap Fallback_{};
        std::array<std::size_t, CandidateBitmap::Capacity> MinimumBytes_{};
        bool Sealed_{false};
    };

} // namespace Prism::Recognition
