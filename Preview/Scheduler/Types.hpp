/**
 * @file Types.hpp
 * @brief Preview worker-affine scheduler 的值契约
 * @details 调度器只在所属 worker executor 上访问可变状态；这些值类型不持有
 *          executor、锁或拥有型回调，因此可安全地跨请求边界传递。
 */
#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstddef>
#include <cstdint>

namespace Preview::Scheduler
{

    /** @brief 调度请求的处理结果。 */
    enum class ResultStatus : std::uint8_t
    {
        Accepted,
        Updated,
        Ready,
        Empty,
        QueueFull,
        Duplicate,
        Cancelled,
        RateBlocked,
        Completed,
        NotFound,
        WorkerMismatch,
        InvalidRequest,
    };

    using Status = ResultStatus;

    /** @brief PriorityScheduler 的四档服务带。 */
    enum class PriorityBand : std::uint8_t
    {
        Control,
        Interactive,
        Bulk,
        Background,
    };

    /**
     * @struct Budget
     * @brief worker 级调度容量、亲和性和服务参数
     * @note 所有数值均为值配置；零值表示采用请求值或最小可用默认值。
     */
    struct Budget final
    {
        Preview::WorkerId WorkerId{};
        std::size_t MaxQueueSize{256};
        std::size_t MaxAccounts{64};
        std::size_t MaxStreamsPerAccount{256};
        std::uint32_t AccountQuantumBytes{0};
        std::uint32_t QuantumBytes{0};
        std::uint32_t MaxBurstBytes{0};
        std::uint32_t MaxConsecutiveTurns{1};
        std::uint64_t AgingInterval{0};
        std::uint64_t StarvationDeadline{0};
        std::uint32_t MinimumServiceBytes{1};
    };

    /**
     * @struct Request
     * @brief 一个 worker 上待服务的账户流请求
     * @details Request 是 scheduler 的唯一入队输入。RemainingBytes 会在 Next
     *          产生服务结果时扣减，调用方通过 Requeue 以同一 RequestId 继续请求。
     */
    struct Request final
    {
        Preview::RequestId RequestId{};
        Preview::AccountId AccountId{};
        Preview::StreamId StreamId{};
        Preview::WorkerId WorkerId{};
        std::uint64_t Bytes{0};
        std::uint64_t RemainingBytes{0};
        std::uint32_t Weight{1};
        std::uint32_t QuantumBytes{0};
        std::uint32_t MaxBurstBytes{0};
        std::uint32_t MaxConsecutiveTurns{0};
        PriorityBand Priority{PriorityBand::Bulk};
        std::uint64_t EnqueuedAt{0};
        std::uint64_t StarvationDeadline{0};
        bool RateBlocked{false};
        bool Cancelled{false};
    };

    /**
     * @struct Result
     * @brief 调度器的可回收结果
     * @details Result 可原样传给 Requeue；RateBlocked 或 Cancelled 可由 worker
     *          在回收前置位，从而保证阻塞和取消都不会残留 ready 节点。
     */
    struct Result final
    {
        ResultStatus Status{ResultStatus::Empty};
        Preview::RequestId RequestId{};
        Preview::AccountId AccountId{};
        Preview::StreamId StreamId{};
        Preview::WorkerId WorkerId{};
        PriorityBand Priority{PriorityBand::Bulk};
        std::uint64_t GrantedBytes{0};
        std::uint64_t RemainingBytes{0};
        bool RateBlocked{false};
        bool Cancelled{false};
    };

} // namespace Preview::Scheduler
