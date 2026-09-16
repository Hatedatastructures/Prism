/**
 * @file Types.hpp
 * @brief Preview 识别基础类型
 * @details 定义多模式识别共享的状态、预算、固定候选位图和预读快照。
 *          类型不依赖具体协议、配置或 handler。
 */

#pragma once

#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace Preview::Recognition
{

    /// 识别运行模式
    enum class RecognitionMode : std::uint8_t
    {
        Configured,
        DeterministicRoute,
        /// 确定性方案的 canonical 名称；与旧 DeterministicRoute 值兼容
        Deterministic = DeterministicRoute,
        MixedTrial,
    };

    /**
     * @brief 返回识别模式的 canonical 名称
     * @param Mode 识别模式
     * @return 配置、诊断和性能结果使用的稳定名称
     * @details `DeterministicRoute` 与 `Deterministic` 是同一个兼容值，统一输出
     *          新的 canonical 名称 `Deterministic`。
     */
    [[nodiscard]] inline auto ToStringView(RecognitionMode Mode) noexcept -> std::string_view
    {
        switch (Mode)
        {
        case RecognitionMode::Configured: return "Configured";
        case RecognitionMode::DeterministicRoute: return "Deterministic";
        case RecognitionMode::MixedTrial: return "MixedTrial";
        }
        return "Unknown";
    }

    /// 候选检查阶段
    enum class MatchState : std::uint8_t
    {
        NeedMore,
        Rejected,
        Structural,
        Authenticated,
    };

    /// 识别终态
    enum class RecognitionStatus : std::uint8_t
    {
        Accepted,
        NoMatch,
        Ambiguous,
        BudgetExceeded,
        TimedOut,
        EndOfStream,
        IoError,
        Polluted,
    };

    /**
     * @brief 返回识别终态的稳定诊断名称
     * @param Status 识别终态
     * @return 小写下划线格式的状态名称
     */
    [[nodiscard]] inline auto ToStringView(RecognitionStatus Status) noexcept -> std::string_view
    {
        switch (Status)
        {
        case RecognitionStatus::Accepted: return "accepted";
        case RecognitionStatus::NoMatch: return "no_match";
        case RecognitionStatus::Ambiguous: return "ambiguous";
        case RecognitionStatus::BudgetExceeded: return "budget_exceeded";
        case RecognitionStatus::TimedOut: return "timed_out";
        case RecognitionStatus::EndOfStream: return "end_of_stream";
        case RecognitionStatus::IoError: return "io_error";
        case RecognitionStatus::Polluted: return "polluted";
        }
        return "unknown";
    }

    /// 编译后的候选索引编号
    using CandidateId = std::uint16_t;

    inline constexpr CandidateId InvalidCandidate = std::numeric_limits<CandidateId>::max();

    /**
     * @class CandidateBitmap
     * @brief 固定 128 位候选位图
     * @details 位图在在线路径按值传递，不分配、不加锁。候选编号范围为 [0, 127]。
     */
    struct CandidateBitmap
    {
        static constexpr std::size_t Capacity = 128;
        static constexpr std::size_t MaxCandidates = Capacity;
        static constexpr std::size_t WordCount = 2;

        std::array<std::uint64_t, WordCount> Words{};

        /**
         * @brief 设置候选位
         * @param Id 候选编号
         * @return 编号有效并成功设置返回 true
         */
        [[nodiscard]] auto Set(CandidateId Id) noexcept -> bool
        {
            const auto Index = static_cast<std::size_t>(Id);
            if (Index >= Capacity)
            {
                return false;
            }
            Words[Index / 64] |= (std::uint64_t{1} << (Index % 64));
            return true;
        }

        /**
         * @brief 清除候选位
         * @param Id 候选编号
         * @return 编号有效返回 true
         */
        [[nodiscard]] auto Reset(CandidateId Id) noexcept -> bool
        {
            const auto Index = static_cast<std::size_t>(Id);
            if (Index >= Capacity)
            {
                return false;
            }
            Words[Index / 64] &= ~(std::uint64_t{1} << (Index % 64));
            return true;
        }

        /**
         * @brief 查询候选位
         * @param Id 候选编号
         * @return 编号有效且已设置返回 true
         */
        [[nodiscard]] auto Test(CandidateId Id) const noexcept -> bool
        {
            const auto Index = static_cast<std::size_t>(Id);
            if (Index >= Capacity)
            {
                return false;
            }
            return (Words[Index / 64] & (std::uint64_t{1} << (Index % 64))) != 0;
        }

        /// Test 的语义别名，便于索引调用方表达候选包含关系
        [[nodiscard]] auto Contains(CandidateId Id) const noexcept -> bool
        {
            return Test(Id);
        }

        /// 清空全部候选位
        auto Clear() noexcept -> void
        {
            Words = {};
        }

        /// 是否没有候选
        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Words[0] == 0 && Words[1] == 0;
        }

        /// 是否至少包含一个候选
        [[nodiscard]] auto Any() const noexcept -> bool
        {
            return !Empty();
        }

        /// 计算候选数量
        [[nodiscard]] auto Count() const noexcept -> std::size_t
        {
            return static_cast<std::size_t>(std::popcount(Words[0])) +
                   static_cast<std::size_t>(std::popcount(Words[1]));
        }

        /**
         * @brief 与另一个位图求交集
         * @param Other 右侧位图
         */
        auto Intersect(const CandidateBitmap &Other) noexcept -> void
        {
            Words[0] &= Other.Words[0];
            Words[1] &= Other.Words[1];
        }

        /**
         * @brief 与另一个位图求并集
         * @param Other 右侧位图
         */
        auto Union(const CandidateBitmap &Other) noexcept -> void
        {
            Words[0] |= Other.Words[0];
            Words[1] |= Other.Words[1];
        }

        [[nodiscard]] auto operator==(const CandidateBitmap &) const noexcept -> bool = default;
    };

    /// 一次识别允许使用的资源预算
    struct RecognitionBudget
    {
        std::size_t MaxProbeBytes{64 * 1024};
        std::uint16_t MaxCandidates{16};
        std::uint16_t MaxCryptoTrials{8};
        std::size_t MaxRoutes{256};
        std::size_t MaxCandidateNameBytes{128};
        std::size_t MaxSchemeBytes{64};
        std::chrono::milliseconds Timeout{3000};
    };

    /// ProbeBuffer::Ensure 结果
    struct ProbeFillResult
    {
        RecognitionStatus Status{RecognitionStatus::Accepted};
        std::size_t Added{0};
        std::error_code Error{};
    };

    /**
     * @struct ProbeSnapshot
     * @brief 预读数据的稳定只读快照
     * @details 通过 shared_ptr 持有 vector 所有权，避免可增长 ProbeBuffer 的 span
     *          在协程挂起恢复后悬垂。Snapshot 活跃时，ProbeBuffer 增长必须 COW。
     */
    struct ProbeSnapshot
    {
        std::shared_ptr<const std::vector<std::byte>> Storage;

        [[nodiscard]] auto Data() const noexcept -> std::span<const std::byte>
        {
            if (!Storage)
            {
                return {};
            }
            return std::span<const std::byte>(*Storage);
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            if (Storage)
            {
                return Storage->size();
            }
            return 0;
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Size() == 0;
        }
    };

} // namespace Preview::Recognition
