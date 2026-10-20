/**
 * @file Statistics.hpp
 * @brief 数据面有界数值观察队列与应用控制 executor 的唯一流量计数 owner。
 * @details 冷路径按 worker 固定队列；Report 只提交值，不保存凭据或显示身份。
 *          Flush/Value/Finish 由同一控制 executor 串行调用；业务 producer drain 后最终封止。
 */
#pragma once

#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Statistics/SparseCounters.hpp>
#include <Prism/Statistics/TrafficHistory.hpp>
#include <Prism/Runtime/Statistics/RecognitionLatency.hpp>
#include <Prism/Runtime/Statistics/HistoryCollector.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/lockfree/queue.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <unordered_map>
#include <vector>

namespace Prism::Runtime
{
    namespace Net = boost::asio;

    /**
     * @class TrafficCounter
     * @brief 数据面非阻塞观察与控制 executor 上的唯一数值计数 owner。
     * @details 冷构造固定容量 worker 队列；Report 不分配、不抛出、不等待锁，
     *          满队列只记丢弃。Flush/Value 仅由同一应用控制 executor 调用，
     *          不保存 credential/display identity，不建立第二套统计镜像。
     */
    class TrafficCounter final : public Prism::Foundation::TrafficSink,
                                 public Prism::Foundation::RecognitionLatencySink
    {
    public:
        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::GenerationId Generation{};
            std::shared_ptr<GenerationPublication> Publication;
            std::size_t Workers{1};
            std::size_t MaxCounterEntries{65536};
        };

        /**
         * @brief 冷构造有界 producer 队列，并绑定应用唯一控制 executor。
         * @details ControlExecutor 由 Runtime 持有到所有关闭/退休回执完成；Flush、Value、Sample 和 Finish
         *          必须与 Retire 的控制工作串行在该 executor 上调用。
         * @param Configuration 固定 worker 队列和稀疏计数容量。
         * @param ControlExecutor 应用控制 executor 的借用副本；本 owner 不停止其 context。
         */
        explicit TrafficCounter(Options Configuration, Net::any_io_executor ControlExecutor);

        /** @brief 多 producer 按数值 worker 分槽提交；零 worker 使用真实控制槽，满或封止只丢弃。 */
        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override;

        /** @brief 只提交真实 admission 时长和数值身份；容量失败仅计观察丢弃。 */
        auto ReportRecognitionLatency(
            Prism::Foundation::RecognitionLatencySample Sample) noexcept -> void override;

        /**
         * @brief 在应用控制 executor 刷新队列后退休一个真实动态 owner。
         * @details 调用者先完成对应 owner 的真实关闭和 producer drain。取消、调度或目标聚合失败均返回 Failure，
         *          只增加相应类型失败计数并保留目标键；成功回执表示已处理该 owner 的全部已接受报告。
         */
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        /** @brief 控制 executor 消费当前拥有的 batch；每个 event 只 pop 一次，观察异常只累计 drop。 */
        auto Flush() noexcept -> void;

        /** @brief 调用方先等待所有业务 report producer drain，再封止并最终消费；不等待自身任务。 */
        auto Finish() noexcept -> void;

        /** @brief 只在控制 executor 读取同一数值计数器；输入不拥有外部数据，输出是值快照。 */
        [[nodiscard]] auto Value(Prism::Statistics::Scope Scope, std::uint64_t Id) const noexcept
            -> Prism::Statistics::TrafficValue;

        /** @brief wire stream ID 按真实父 session 查询，避免不同 mux root 的同号流混计。 */
        [[nodiscard]] auto StreamValue(Prism::SessionId Parent, Prism::StreamId Id) const noexcept
            -> Prism::Statistics::TrafficValue;

        /** @brief 配置实例下标仅在本代唯一，不混合热更新前后同号实例。 */
        [[nodiscard]] auto ProtocolInstanceValue(Prism::GenerationId Generation, std::uint64_t Instance) const noexcept
            -> Prism::Statistics::TrafficValue;

        [[nodiscard]] auto Accepted() const noexcept -> std::uint64_t
        { return Accepted_.load(std::memory_order_relaxed); }
        /** @brief 返回延迟样本入队拒绝数；其值是总 Dropped 的子集。 */
        [[nodiscard]] auto RecognitionLatencyQueueDrops() const noexcept -> std::uint64_t
        { return RecognitionLatencyQueueDrops_.load(std::memory_order_relaxed); }
        /** @brief 返回无法分配或归属代次槽的延迟样本数。 */
        [[nodiscard]] auto RecognitionLatencyAggregationFailures() const noexcept -> std::uint64_t
        { return RecognitionLatencyAggregationFailures_.load(std::memory_order_relaxed); }
        /** @brief 读取指定代次的已聚合实际样本；未聚合时返回真实空快照。 */
        [[nodiscard]] auto RecognitionLatency(Prism::GenerationId Generation) const
            -> Prism::Statistics::RecognitionLatencySnapshot
        { return RecognitionLatency_.Snapshot(Generation); }
        /** @brief 返回从有界观察队列真实取出的事件总数。 */
        [[nodiscard]] auto ConsumedObservations() const noexcept -> std::uint64_t
        { return ConsumedObservations_.load(std::memory_order_relaxed); }
        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t;
        /** @brief 指定真实 worker 的入口丢弃数；不把全局计数重复填进每个 worker。 */
        [[nodiscard]] auto Dropped(Prism::WorkerId Worker) const noexcept -> std::uint64_t
        {
            if (Worker.Value() >= Queues_.size()) return 0U;
            return Queues_[Worker.Value()]->Dropped.load(std::memory_order_relaxed);
        }
        /** @brief 已出队但计数容量或分配失败的事件数，与入口满队列丢弃分开观察。 */
        [[nodiscard]] auto AggregationFailures() const noexcept -> std::uint64_t;
        /** @brief 指定真实 worker 的计数容量/分配失败事件数，每个已出队事件至多记一次。 */
        [[nodiscard]] auto AggregationFailures(Prism::WorkerId Worker) const noexcept -> std::uint64_t
        {
            if (Worker.Value() >= Queues_.size()) return 0U;
            return Queues_[Worker.Value()]->AggregationFailures.load(std::memory_order_relaxed);
        }
        /** @brief Session 动态 scope 的统计退休失败次数；不改变业务关闭结果。 */
        [[nodiscard]] auto SessionRetirementFailures() const noexcept -> std::uint64_t
        { return SessionRetirementFailures_.load(std::memory_order_relaxed); }
        /** @brief Stream 动态 scope 的统计退休失败次数；不改变业务关闭结果。 */
        [[nodiscard]] auto StreamRetirementFailures() const noexcept -> std::uint64_t
        { return StreamRetirementFailures_.load(std::memory_order_relaxed); }
        /** @brief Task 动态 scope 的统计退休失败次数；不改变任务业务 Outcome。 */
        [[nodiscard]] auto TaskRetirementFailures() const noexcept -> std::uint64_t
        { return TaskRetirementFailures_.load(std::memory_order_relaxed); }
        /** @brief 所有类型统计退休失败次数；类型分项仍可独立读取。 */
        [[nodiscard]] auto RetirementFailures() const noexcept -> std::uint64_t
        {
            return SessionRetirementFailures() + StreamRetirementFailures() +
                TaskRetirementFailures();
        }
        [[nodiscard]] auto IsSealed() const noexcept -> bool
        { return Sealed_.load(std::memory_order_acquire); }

        /** @brief 唯一控制 timer 在真实 Flush 后记录实际累计事实，时间为 Unix 毫秒。 */
        auto Sample(std::uint64_t UnixMilliseconds) noexcept -> void;
        [[nodiscard]] auto History() const -> std::vector<Prism::Statistics::TrafficSample>;
        /** @brief 发布代次时冷配置持久归属；调用者与 Flush 同属控制执行域。 */
        auto ConfigureHistory(Prism::Statistics::HistoryCatalog Catalog) -> void;
        [[nodiscard]] auto HistorySnapshot(const Prism::Statistics::HistoryQuery &Request, std::uint64_t Now) const
            -> Prism::Statistics::HistoryResult;
        [[nodiscard]] auto TakeHistoryBatch() -> std::vector<Prism::Statistics::HistoryRecord>;
        auto RetireHistoryGeneration(std::uint64_t Generation) -> void;
    private:
        using CounterScope = Prism::Statistics::CounterScope;

        auto RecordRecognitionLatencyQueueDrop(const bool IsLatency) noexcept -> void;

        auto RecordRecognitionLatencyAggregationFailure(
            const Prism::Foundation::TrafficEvent &Event) noexcept -> void;

        [[nodiscard]] static auto ToCounterScope(
            const Prism::Foundation::SessionTrafficOwner &Owner) noexcept -> CounterScope;

        [[nodiscard]] static auto ToCounterScope(
            const Prism::Foundation::StreamTrafficOwner &Owner) noexcept -> CounterScope;

        [[nodiscard]] static auto ToCounterScope(
            const Prism::Foundation::TaskTrafficOwner &Owner) noexcept -> CounterScope;

        [[nodiscard]] static auto ToCounterScope(
            const Prism::Foundation::TrafficRetirement &Owner) noexcept -> CounterScope;

        /** @brief 按 typed owner 记录一次退休失败，不改写业务结果或 TrafficValue。 */
        auto RecordRetirementFailure(const Prism::Foundation::TrafficRetirement &Owner) noexcept -> void;

        /** @brief 判断一条报告是否属于本次退休 scope 与 worker。 */
        [[nodiscard]] static auto MatchesCounterScope(
            const Prism::Foundation::TrafficEvent &Event,
            CounterScope Scope,
            Prism::WorkerId Worker) noexcept -> bool;

        /** @brief 在控制 executor 消费有界队列，仅目标报告聚合失败会拒绝其退休。 */
        [[nodiscard]] auto FlushForRetirement(CounterScope Scope, Prism::WorkerId Worker) noexcept -> bool;

        /** @brief 控制 executor 上先完成目标范围 flush，再提交稀疏键退休。 */
        auto RetireOnControl(
            CounterScope Scope,
            Prism::WorkerId Worker,
            Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        struct WorkerQueue final
        {
            boost::lockfree::queue<Prism::Foundation::TrafficEvent,
                boost::lockfree::capacity<1024>> Events;
            std::atomic<std::uint64_t> Dropped{0};
            std::atomic<std::uint64_t> AggregationFailures{0};
        };

        [[nodiscard]] auto Accumulate(const Prism::Foundation::TrafficEvent &Event) noexcept -> bool;

        auto ObserveHistory(Prism::Foundation::TrafficEvent Event) noexcept -> void;

        struct ProtocolAssociation final
        {
            std::uint64_t Type{0};
            std::uint64_t Instance{0};
            std::uint64_t Ingress{0};
            Prism::Foundation::TrafficTransport Transport{Prism::Foundation::TrafficTransport::Unknown};
            Prism::AccountId Account{};
        };

        Prism::ProcessId Process_;
        Prism::GenerationId Generation_;
        std::shared_ptr<GenerationPublication> Publication_;
        Prism::Runtime::Detail::RecognitionLatencyStore RecognitionLatency_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> ControlReclaimer_;
        std::vector<std::unique_ptr<WorkerQueue>> Queues_;
        Prism::Statistics::SparseCounters Counters_;
        std::unordered_map<std::uint64_t, ProtocolAssociation> SessionProtocols_;
        Prism::Statistics::TrafficHistory History_;
        Prism::Runtime::Detail::HistoryCollector Analysis_;
        std::uint64_t PreviousHistoryDrops_{0}, PreviousHistoryFailures_{0};
        std::atomic<bool> Sealed_{false};
        std::atomic<std::uint64_t> Accepted_{0};
        std::atomic<std::uint64_t> ConsumedObservations_{0};
        std::atomic<std::uint64_t> UnassignedDrops_{0};
        std::atomic<std::uint64_t> RecognitionLatencyQueueDrops_{0};
        std::atomic<std::uint64_t> RecognitionLatencyAggregationFailures_{0};
        std::atomic<std::uint64_t> SessionRetirementFailures_{0};
        std::atomic<std::uint64_t> StreamRetirementFailures_{0};
        std::atomic<std::uint64_t> TaskRetirementFailures_{0};
    };

} // namespace Prism::Runtime
