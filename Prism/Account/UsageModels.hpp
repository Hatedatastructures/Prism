/** @file UsageModels.hpp
 * @brief 持久流量账本的领域请求、预约和余额；字节均为逻辑有效载荷。
 */
#pragma once
#include <Prism/Account/PolicyConfiguration.hpp>
#include <cstdint>
#include <optional>
#include <string>

namespace Prism::Account
{
    /** @brief 固定偏移的自然周期；所有边界为 UTC Unix 毫秒，结束边界不包含。 */
    struct UsageCycle final
    {
        std::int64_t Start{0};
        std::optional<std::int64_t> End;
        friend auto operator==(const UsageCycle&, const UsageCycle&) -> bool = default;
    };

    /** @brief 周期选择由持久调度所有；当前未结束周期不因配置变更或时钟回拨重建。 */
    struct UsageCycleRequest final
    {
        std::string AccountKey;
        CycleConfiguration Desired;
        std::int64_t Now{0};
    };

    struct UsageSchedule final
    {
        UsageCycle Current;
        CycleConfiguration Active;
        CycleConfiguration Pending;
    };

    /** @brief 周期账本唯一快照；异常占额独立于已经结清的实际使用量。 */
    struct UsageSnapshot final
    {
        std::string AccountKey;
        UsageCycle Cycle;
        std::uint64_t Revision{0};
        std::optional<std::uint64_t> LimitBytes;
        std::uint64_t SettledBytes{0};
        std::uint64_t ReservedBytes{0};
        std::uint64_t UncertainBytes{0};
        std::uint64_t AdditionalBytes{0};
        std::uint64_t RemainingBytes{0};
        std::uint64_t OverageBytes{0};
    };

    /** @brief 读取不会创建额度或重置账本；LimitBytes 是该次已发布有效策略。 */
    struct UsageReadRequest final
    {
        std::string AccountKey;
        UsageCycle Cycle;
        std::optional<std::uint64_t> LimitBytes;
    };

    /** @brief 同一 RequestKey 重试只能返回同一持久预约，不得重新发放信用。 */
    struct UsageReservationRequest final
    {
        UsageReadRequest Usage;
        std::string RequestKey;
        std::uint64_t Bytes{1024U * 1024U};
        std::uint64_t OutstandingLimit{2U * 1024U * 1024U};
    };

    /** @brief 只有持久事务提交成功才能交给数据面消费。 */
    struct UsageReservation final
    {
        std::string ReservationId;
        std::string RequestKey;
        std::string AccountKey;
        UsageCycle Cycle;
        std::uint64_t Bytes{0};
        std::uint64_t Revision{0};
    };

    /**
     * @brief 累计成功量结算；同一预约的 ConsumedBytes 只增不减。
     * @details Final=true 时归还未消耗部分并封止预约；重复完全相同的最终结算幂等，
     *          封止后增加消费或修改已结算值必须拒绝。没有显式结清的异常退出保留占额。
     */
    struct UsageSettlementRequest final
    {
        std::string ReservationId;
        std::uint64_t ConsumedBytes{0};
        bool Final{false};
    };

    enum class UsageAdjustmentKind : std::uint8_t { AddAllowance, ReleaseUncertain };

    /** @brief 有原因、有修订、有幂等键的人工调整，不能改写已经传输的用量。 */
    struct UsageAdjustmentRequest final
    {
        UsageReadRequest Usage;
        UsageAdjustmentKind Kind{UsageAdjustmentKind::AddAllowance};
        std::uint64_t Bytes{0};
        std::uint64_t ExpectedRevision{0};
        std::string RequestKey;
        std::string Reason;
    };
}
