/** @file RateTypes.hpp
 * @brief 冻结账户速率策略与真实消费输入。
 */
#pragma once
#include <cstdint>
#include <limits>
#include <variant>
namespace Prism::Account
{
    struct UnlimitedRatePolicy {};
    struct StrictGlobalRatePolicy
    {
        std::uint64_t LimitPerWindow{0};
        std::uint64_t WindowMilliseconds{1000};
    };
    struct WorkerShardedRatePolicy
    {
        static constexpr std::uint32_t MaxWorkerCount{4096U};
        std::uint32_t WorkerCount{1U};
        std::uint64_t GlobalLimitPerWindow{0U};
        std::uint64_t WindowMilliseconds{1000U};
        [[nodiscard]] auto PerWorkerLimit() const noexcept -> std::uint64_t
        {
            if (WorkerCount == 0U || GlobalLimitPerWindow == 0U) { return 0U; }
            return GlobalLimitPerWindow / WorkerCount + static_cast<std::uint64_t>(GlobalLimitPerWindow % WorkerCount != 0U);
        }
        [[nodiscard]] auto MaxOvershoot() const noexcept -> std::uint64_t
        {
            const auto Limit = PerWorkerLimit();
            if (Limit == 0U || WorkerCount == 0U) { return 0U; }
            if (Limit > std::numeric_limits<std::uint64_t>::max() / WorkerCount) { return UINT64_MAX; }
            return Limit * WorkerCount - GlobalLimitPerWindow;
        }
    };
    using RatePolicy = std::variant<UnlimitedRatePolicy, StrictGlobalRatePolicy, WorkerShardedRatePolicy>;
    /** @brief 输入只同步消费；Now 是同一时钟的毫秒，limited 策略不接受零时间。 */
    struct RateRequest
    {
        std::uint32_t WorkerId{0U};
        std::uint64_t Now{0U};
        std::uint32_t Units{1U};
    };
}
