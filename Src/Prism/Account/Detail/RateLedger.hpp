/** @file RateLedger.hpp
 * @brief 唯一速率账本、最多八个冻结窗口视图和无等待消费预约。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Rate.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

namespace Prism::Account::Detail
{
    /** @brief 全部可变窗口状态只在实际 rate transaction 内访问。 */
    struct RateBucket final
    {
        std::uint64_t Window{0U};
        std::uint64_t Used{0U};
    };
    struct RateView final
    {
        RatePolicy Policy;
        std::uint64_t WindowMilliseconds{1000U};
        std::uint64_t Limit{0U};
        bool WorkerSharded{false};
        std::uint32_t WorkerCount{0U};
        RateBucket Global;
        std::vector<RateBucket> Workers;
        RateView(RatePolicy Value, const std::uint32_t Count);
    };
    /** @brief process/account runtime 拥有的 rate ledger；更新策略不创建第二份消费账本。 */
    class RateLedger final : public std::enable_shared_from_this<RateLedger>
    {
        using Failure = Prism::Fault::Failure;
        using Code = Prism::Fault::Code;
    public:
        explicit RateLedger(const std::uint32_t WorkerCount);
        /** @brief 冷、非协程准备新窗口视图，复制当前未到期用量，不能零重置。
         * @details 无Previous时合并所有仍存活且未过期视图的最大已用预算，覆盖旧lease保活的策略事实。
         */
        [[nodiscard]] auto Prepare(RatePolicy Policy, const std::shared_ptr<RateView>& Previous)
            -> std::expected<std::shared_ptr<RateView>, Failure>;
        /** @brief 热消费一次预约，竞争返回 ResourceUnavailable，不忙等或隐藏为 RateLimited。 */
        [[nodiscard]] auto TryReserve(const std::shared_ptr<RateView>& View, RateRequest Request) noexcept
            -> std::expected<RateReservation, Failure>;
        [[nodiscard]] auto TotalUnits() const noexcept -> std::uint64_t;
        [[nodiscard]] auto WorkerCount() const noexcept -> std::uint32_t;
    private:
        friend class RateReservation;
        static auto Advance(RateBucket& Bucket, const std::uint64_t Window) noexcept -> void;
        [[nodiscard]] auto Configure(RateView& View) const noexcept -> Failure;
        auto Release() noexcept -> void;
        const std::uint32_t WorkerCount_;
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT;
        std::array<std::weak_ptr<RateView>, 8U> Views_;
        std::uint64_t LastNow_{0U};
        std::atomic<std::uint64_t> TotalUnits_{0U};
    };



}
