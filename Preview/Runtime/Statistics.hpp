/**
 * @file Statistics.hpp
 * @brief 数据面有界数值观察队列与应用控制 executor 的唯一流量计数 owner。
 * @details 冷路径按 worker 固定队列；Report 只提交值，不保存凭据或显示身份。
 *          Flush/Value/Finish 由同一控制 executor 串行调用；业务 producer drain 后最终封止。
 */
#pragma once

#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Statistics/SparseCounters.hpp>
#include <Preview/Statistics/History.hpp>
#include <Preview/Runtime/Statistics/RecognitionLatency.hpp>
#include <Preview/Runtime/Statistics/HistoryCollector.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <unordered_map>
#include <vector>

namespace Preview::Runtime
{
    namespace Net = boost::asio;

    /**
     * @class TrafficCounter
     * @brief 数据面非阻塞观察与控制 executor 上的唯一数值计数 owner。
     * @details 冷构造固定容量 worker 队列；Report 不分配、不抛出、不等待锁，
     *          满队列只记丢弃。Flush/Value 仅由同一应用控制 executor 调用，
     *          不保存 credential/display identity，不建立第二套统计镜像。
     */
    class TrafficCounter final : public Preview::Foundation::TrafficSink,
                                 public Preview::Foundation::RecognitionLatencySink
    {
    public:
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::GenerationId Generation{};
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
        explicit TrafficCounter(Options Configuration, Net::any_io_executor ControlExecutor)
            : Process_(Configuration.Process),
              Generation_(Configuration.Generation),
              Publication_(std::move(Configuration.Publication)),
              RecognitionLatency_(Publication_),
              ControlReclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(
                  std::move(ControlExecutor))),
              Counters_(Preview::Statistics::SparseCounters::Options{Configuration.MaxCounterEntries})
        {
            Queues_.reserve(Configuration.Workers + 1U);
            for (std::size_t Index = 0; Index <= Configuration.Workers; ++Index)
                Queues_.push_back(std::make_unique<WorkerQueue>());
        }

        /** @brief 多 producer 按数值 worker 分槽提交；零 worker 使用真实控制槽，满或封止只丢弃。 */
        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            const auto IsRecognitionLatency =
                Event.Kind == Preview::Foundation::TrafficEventKind::RecognitionLatency;
            const auto Index = Event.Worker.Value();
            if (Index >= Queues_.size())
            {
                UnassignedDrops_.fetch_add(1U, std::memory_order_relaxed);
                RecordRecognitionLatencyQueueDrop(IsRecognitionLatency);
                return;
            }
            auto &Queue = *Queues_[Index];
            const auto GenerationRetained = Publication_
                ? Publication_->Contains(Event.Generation)
                : Event.Generation == Generation_;
            const auto WorkerOwnedStage = Event.Kind == Preview::Foundation::TrafficEventKind::NetworkLatency;
            if (Sealed_.load(std::memory_order_acquire) || (!GenerationRetained && !WorkerOwnedStage) ||
                !Queue.Events.bounded_push(Event))
            {
                Queue.Dropped.fetch_add(1U, std::memory_order_relaxed);
                RecordRecognitionLatencyQueueDrop(IsRecognitionLatency);
                return;
            }
            Accepted_.fetch_add(1U, std::memory_order_relaxed);
        }

        /** @brief 只提交真实 admission 时长和数值身份；容量失败仅计观察丢弃。 */
        auto ReportRecognitionLatency(
            Preview::Foundation::RecognitionLatencySample Sample) noexcept -> void override
        {
            Report(Preview::Foundation::TrafficEvent{
                .Generation = Sample.Generation,
                .Worker = Sample.Worker,
                .Session = Sample.Session,
                .Kind = Preview::Foundation::TrafficEventKind::RecognitionLatency,
                .DurationMicroseconds = Sample.DurationMicroseconds});
        }

        /**
         * @brief 在应用控制 executor 刷新队列后退休一个真实动态 owner。
         * @details 调用者先完成对应 owner 的真实关闭和 producer drain。取消、调度或目标聚合失败均返回 Failure，
         *          只增加相应类型失败计数并保留目标键；成功回执表示已处理该 owner 的全部已接受报告。
         */
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            using Failure = Preview::Fault::Failure;
            try
            {
                const auto Cancellation = co_await Net::this_coro::cancellation_state;
                if (Cancellation.cancelled() != Net::cancellation_type::none)
                {
                    RecordRetirementFailure(Owner);
                    co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
                }

                const auto Worker = std::visit([](const auto &Value) { return Value.Worker; }, Owner);
                const auto Scope = ToCounterScope(Owner);
                if (Scope.Id == 0U || Worker.Value() >= Queues_.size())
                {
                    RecordRetirementFailure(Owner);
                    co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
                }
                if (Scope.ScopeValue == Preview::Statistics::Scope::Stream &&
                    Scope.ParentSession.Value() == 0U)
                {
                    RecordRetirementFailure(Owner);
                    co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
                }
                if (Sealed_.load(std::memory_order_acquire) || !ControlReclaimer_->CanDispatch())
                {
                    RecordRetirementFailure(Owner);
                    co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
                }

                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                co_return co_await Net::co_spawn(
                    ControlReclaimer_->Executor(),
                    RetireOnControl(Scope, Worker, Owner),
                    Net::use_awaitable);
            }
            catch (const boost::system::system_error &Error)
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
        }

        /** @brief 控制 executor 消费当前拥有的 batch；每个 event 只 pop 一次，观察异常只累计 drop。 */
        auto Flush() noexcept -> void
        {
            for (const auto &Queue : Queues_)
            {
                Preview::Foundation::TrafficEvent Event;
                for (std::size_t Count = 0; Count < 1024U && Queue->Events.pop(Event); ++Count)
                {
                    if (!Accumulate(Event))
                    {
                        Queue->AggregationFailures.fetch_add(1U, std::memory_order_relaxed);
                        RecordRecognitionLatencyAggregationFailure(Event);
                    }
                    ConsumedObservations_.fetch_add(1U, std::memory_order_relaxed);
                }
            }
        }

        /** @brief 调用方先等待所有业务 report producer drain，再封止并最终消费；不等待自身任务。 */
        auto Finish() noexcept -> void
        {
            Sealed_.store(true, std::memory_order_release);
            Flush();
        }

        /** @brief 只在控制 executor 读取同一数值计数器；输入不拥有外部数据，输出是值快照。 */
        [[nodiscard]] auto Value(Preview::Statistics::Scope Scope, std::uint64_t Id) const noexcept
            -> Preview::Statistics::TrafficValue
        {
            using Metric = Preview::Statistics::Metric;
            return {Counters_.Get({Scope, Id, Metric::UpBytes}), Counters_.Get({Scope, Id, Metric::DownBytes}),
                Counters_.Get({Scope, Id, Metric::Events}), Counters_.Get({Scope, Id, Metric::Errors})};
        }

        /** @brief wire stream ID 按真实父 session 查询，避免不同 mux root 的同号流混计。 */
        [[nodiscard]] auto StreamValue(Preview::SessionId Parent, Preview::StreamId Id) const noexcept
            -> Preview::Statistics::TrafficValue
        {
            using Scope = Preview::Statistics::Scope;
            using Metric = Preview::Statistics::Metric;
            return {Counters_.Get({Scope::Stream, Id.Value(), Metric::UpBytes, Parent}),
                Counters_.Get({Scope::Stream, Id.Value(), Metric::DownBytes, Parent}),
                Counters_.Get({Scope::Stream, Id.Value(), Metric::Events, Parent}),
                Counters_.Get({Scope::Stream, Id.Value(), Metric::Errors, Parent})};
        }

        /** @brief 配置实例下标仅在本代唯一，不混合热更新前后同号实例。 */
        [[nodiscard]] auto ProtocolInstanceValue(Preview::GenerationId Generation, std::uint64_t Instance) const noexcept
            -> Preview::Statistics::TrafficValue
        {
            using Scope = Preview::Statistics::Scope;
            using Metric = Preview::Statistics::Metric;
            return {Counters_.Get({Scope::ProtocolInstance, Instance, Metric::UpBytes, {}, Generation}),
                Counters_.Get({Scope::ProtocolInstance, Instance, Metric::DownBytes, {}, Generation}),
                Counters_.Get({Scope::ProtocolInstance, Instance, Metric::Events, {}, Generation}),
                Counters_.Get({Scope::ProtocolInstance, Instance, Metric::Errors, {}, Generation})};
        }

        [[nodiscard]] auto Accepted() const noexcept -> std::uint64_t
        { return Accepted_.load(std::memory_order_relaxed); }
        /** @brief 返回延迟样本入队拒绝数；其值是总 Dropped 的子集。 */
        [[nodiscard]] auto RecognitionLatencyQueueDrops() const noexcept -> std::uint64_t
        { return RecognitionLatencyQueueDrops_.load(std::memory_order_relaxed); }
        /** @brief 返回无法分配或归属代次槽的延迟样本数。 */
        [[nodiscard]] auto RecognitionLatencyAggregationFailures() const noexcept -> std::uint64_t
        { return RecognitionLatencyAggregationFailures_.load(std::memory_order_relaxed); }
        /** @brief 读取指定代次的已聚合实际样本；未聚合时返回真实空快照。 */
        [[nodiscard]] auto RecognitionLatency(Preview::GenerationId Generation) const
            -> Preview::Statistics::RecognitionLatencySnapshot
        { return RecognitionLatency_.Snapshot(Generation); }
        /** @brief 返回从有界观察队列真实取出的事件总数。 */
        [[nodiscard]] auto ConsumedObservations() const noexcept -> std::uint64_t
        { return ConsumedObservations_.load(std::memory_order_relaxed); }
        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t
        {
            auto Result = UnassignedDrops_.load(std::memory_order_relaxed);
            for (const auto &Queue : Queues_)
                Result += Queue->Dropped.load(std::memory_order_relaxed);
            return Result;
        }
        /** @brief 指定真实 worker 的入口丢弃数；不把全局计数重复填进每个 worker。 */
        [[nodiscard]] auto Dropped(Preview::WorkerId Worker) const noexcept -> std::uint64_t
        {
            if (Worker.Value() >= Queues_.size()) return 0U;
            return Queues_[Worker.Value()]->Dropped.load(std::memory_order_relaxed);
        }
        /** @brief 已出队但计数容量或分配失败的事件数，与入口满队列丢弃分开观察。 */
        [[nodiscard]] auto AggregationFailures() const noexcept -> std::uint64_t
        {
            std::uint64_t Result = 0;
            for (const auto &Queue : Queues_)
                Result += Queue->AggregationFailures.load(std::memory_order_relaxed);
            return Result;
        }
        /** @brief 指定真实 worker 的计数容量/分配失败事件数，每个已出队事件至多记一次。 */
        [[nodiscard]] auto AggregationFailures(Preview::WorkerId Worker) const noexcept -> std::uint64_t
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
        auto Sample(std::uint64_t UnixMilliseconds) noexcept -> void
        {
            History_.Append({UnixMilliseconds, Value(Preview::Statistics::Scope::Process, Process_.Value())});
            const auto Drops = Dropped();
            const auto Failures = AggregationFailures();
            Analysis_.Sample(UnixMilliseconds, {Drops - PreviousHistoryDrops_,
                Failures - PreviousHistoryFailures_, false});
            PreviousHistoryDrops_ = Drops;
            PreviousHistoryFailures_ = Failures;
        }
        [[nodiscard]] auto History() const -> std::vector<Preview::Statistics::TrafficSample>
        { return History_.Snapshot(); }
        /** @brief 发布代次时冷配置持久归属；调用者与 Flush 同属控制执行域。 */
        auto ConfigureHistory(Preview::Statistics::HistoryCatalog Catalog) -> void
        { Analysis_.Configure(std::move(Catalog)); }
        [[nodiscard]] auto HistorySnapshot(const Preview::Statistics::HistoryQuery &Request, std::uint64_t Now) const
            -> Preview::Statistics::HistoryResult { return Analysis_.Query(Request, Now); }
        [[nodiscard]] auto TakeHistoryBatch() -> std::vector<Preview::Statistics::HistoryRecord>
        { return Analysis_.TakePersistenceBatch(); }
        auto RetireHistoryGeneration(std::uint64_t Generation) -> void { Analysis_.RetireGeneration(Generation); }
    private:
        using CounterScope = Preview::Statistics::CounterScope;

        auto RecordRecognitionLatencyQueueDrop(const bool IsLatency) noexcept -> void
        {
            if (IsLatency)
            {
                RecognitionLatencyQueueDrops_.fetch_add(1U, std::memory_order_relaxed);
            }
        }

        auto RecordRecognitionLatencyAggregationFailure(
            const Preview::Foundation::TrafficEvent &Event) noexcept -> void
        {
            if (Event.Kind == Preview::Foundation::TrafficEventKind::RecognitionLatency)
            {
                RecognitionLatencyAggregationFailures_.fetch_add(1U, std::memory_order_relaxed);
            }
        }

        [[nodiscard]] static auto ToCounterScope(
            const Preview::Foundation::SessionTrafficOwner &Owner) noexcept -> CounterScope
        {
            return {Preview::Statistics::Scope::Session, Owner.Session.Value(), {}};
        }

        [[nodiscard]] static auto ToCounterScope(
            const Preview::Foundation::StreamTrafficOwner &Owner) noexcept -> CounterScope
        {
            return {Preview::Statistics::Scope::Stream, Owner.Stream.Value(), Owner.ParentSession};
        }

        [[nodiscard]] static auto ToCounterScope(
            const Preview::Foundation::TaskTrafficOwner &Owner) noexcept -> CounterScope
        {
            return {Preview::Statistics::Scope::Task, Owner.Task.Value(), {}};
        }

        [[nodiscard]] static auto ToCounterScope(
            const Preview::Foundation::TrafficRetirement &Owner) noexcept -> CounterScope
        {
            return std::visit([](const auto &Value) { return ToCounterScope(Value); }, Owner);
        }

        /** @brief 按 typed owner 记录一次退休失败，不改写业务结果或 TrafficValue。 */
        auto RecordRetirementFailure(const Preview::Foundation::TrafficRetirement &Owner) noexcept -> void
        {
            if (std::holds_alternative<Preview::Foundation::SessionTrafficOwner>(Owner))
                SessionRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
            else if (std::holds_alternative<Preview::Foundation::StreamTrafficOwner>(Owner))
                StreamRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
            else
                TaskRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
        }

        /** @brief 判断一条报告是否属于本次退休 scope 与 worker。 */
        [[nodiscard]] static auto MatchesCounterScope(
            const Preview::Foundation::TrafficEvent &Event,
            CounterScope Scope,
            Preview::WorkerId Worker) noexcept -> bool
        {
            if (Event.Worker != Worker) return false;
            if (Scope.ScopeValue == Preview::Statistics::Scope::Session)
                return Event.Session.Value() == Scope.Id;
            if (Scope.ScopeValue == Preview::Statistics::Scope::Stream)
                return Event.Stream.Value() == Scope.Id && Event.Session == Scope.ParentSession;
            if (Scope.ScopeValue == Preview::Statistics::Scope::Task)
                return Event.Task.Value() == Scope.Id;
            return false;
        }

        /** @brief 在控制 executor 消费有界队列，仅目标报告聚合失败会拒绝其退休。 */
        [[nodiscard]] auto FlushForRetirement(CounterScope Scope, Preview::WorkerId Worker) noexcept -> bool
        {
            bool ScopeComplete = true;
            for (std::size_t Index = 0; Index < Queues_.size(); ++Index)
            {
                const auto &Queue = Queues_[Index];
                Preview::Foundation::TrafficEvent Event;
                for (std::size_t Count = 0; Count < 1024U && Queue->Events.pop(Event); ++Count)
                {
                    if (!Accumulate(Event))
                    {
                        Queue->AggregationFailures.fetch_add(1U, std::memory_order_relaxed);
                        RecordRecognitionLatencyAggregationFailure(Event);
                        if (Event.Kind != Preview::Foundation::TrafficEventKind::RecognitionLatency &&
                            Index == Worker.Value() && MatchesCounterScope(Event, Scope, Worker))
                            ScopeComplete = false;
                    }
                    ConsumedObservations_.fetch_add(1U, std::memory_order_relaxed);
                }
            }
            return ScopeComplete;
        }

        /** @brief 控制 executor 上先完成目标范围 flush，再提交稀疏键退休。 */
        auto RetireOnControl(
            CounterScope Scope,
            Preview::WorkerId Worker,
            Preview::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            using Failure = Preview::Fault::Failure;
            if (Sealed_.load(std::memory_order_acquire))
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            if (!FlushForRetirement(Scope, Worker))
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            if (Scope.ScopeValue == Preview::Statistics::Scope::Session)
                SessionProtocols_.erase(Scope.Id);
            Counters_.Retire(Scope);
            co_return std::expected<void, Failure>{};
        }

        struct WorkerQueue final
        {
            boost::lockfree::queue<Preview::Foundation::TrafficEvent,
                boost::lockfree::capacity<1024>> Events;
            std::atomic<std::uint64_t> Dropped{0};
            std::atomic<std::uint64_t> AggregationFailures{0};
        };

        [[nodiscard]] auto Accumulate(const Preview::Foundation::TrafficEvent &Event) noexcept -> bool
        {
            if (Event.Kind == Preview::Foundation::TrafficEventKind::NetworkLatency)
                return Analysis_.Record(Event);
            if (Event.Kind == Preview::Foundation::TrafficEventKind::ProtocolAssociated)
            {
                if (Event.Session.Value() == 0U || Event.Protocol == 0U) return false;
                try { SessionProtocols_.insert_or_assign(Event.Session.Value(),
                    ProtocolAssociation{Event.Protocol, Event.ProtocolInstance, Event.Ingress, Event.Transport, Event.Account}); }
                catch (...) { return false; }
                return true;
            }
            if (Event.Kind == Preview::Foundation::TrafficEventKind::RecognitionLatency)
            {
                const auto Accepted = RecognitionLatency_.Record(Event.Generation, Event.DurationMicroseconds);
                if (Accepted) ObserveHistory(Event);
                return Accepted;
            }
            using Scope = Preview::Statistics::Scope;
            using Metric = Preview::Statistics::Metric;
            auto Protocol = std::uint64_t{0};
            auto ProtocolInstance = std::uint64_t{0};
            if (const auto It = SessionProtocols_.find(Event.Session.Value()); It != SessionProtocols_.end())
            { Protocol = It->second.Type; ProtocolInstance = It->second.Instance; }
            if (Event.Protocol != 0) Protocol = Event.Protocol;
            if (Event.ProtocolInstance != 0) ProtocolInstance = Event.ProtocolInstance;
            const std::array Scopes{
                std::pair{Scope::Process, Process_.Value()}, std::pair{Scope::Worker, Event.Worker.Value()},
                std::pair{Scope::Account, Event.Account.Value()}, std::pair{Scope::Session, Event.Session.Value()},
                std::pair{Scope::Stream, Event.Stream.Value()}, std::pair{Scope::Task, Event.Task.Value()},
                std::pair{Scope::Protocol, Protocol}, std::pair{Scope::ProtocolInstance, ProtocolInstance}};
            std::array<Preview::Statistics::CounterKey, 32> Keys{};
            std::array<std::uint64_t, 32> Deltas{};
            std::size_t Size = 0;
            for (const auto &[ScopeValue, Id] : Scopes)
            {
                if (Id == 0U) continue;
                Preview::SessionId Parent;
                if (ScopeValue == Scope::Stream) Parent = Event.Session;
                const auto Generation = ScopeValue == Scope::ProtocolInstance ? Event.Generation : Preview::GenerationId{};
                Keys[Size++] = {ScopeValue, Id, Metric::UpBytes, Parent, Generation};
                Keys[Size++] = {ScopeValue, Id, Metric::DownBytes, Parent, Generation};
                Keys[Size++] = {ScopeValue, Id, Metric::Events, Parent, Generation};
                Keys[Size++] = {ScopeValue, Id, Metric::Errors, Parent, Generation};
            }
            if (!Counters_.Prepare(std::span{Keys.data(), Size})) return false;
            const auto Terminal = Event.Kind == Preview::Foundation::TrafficEventKind::Completed;
            const auto Failed = Terminal && Event.Failure.Failed() &&
                Event.Failure.Code != Preview::Fault::Code::Canceled &&
                Event.Failure.Code != Preview::Fault::Code::Eof;
            for (std::size_t Index = 0; Index < Size; Index += 4U)
            {
                Deltas[Index] = Event.Up;
                Deltas[Index + 1U] = Event.Down;
                if (Terminal) Deltas[Index + 2U] = 1U;
                if (Failed) Deltas[Index + 3U] = 1U;
            }
            for (std::size_t Index = 0; Index < Size; ++Index)
                if (!Counters_.CanAdd(Keys[Index], Deltas[Index])) return false;
            for (std::size_t Index = 0; Index < Size; ++Index)
                if (!Counters_.Add(Keys[Index], Deltas[Index])) return false;
            ObserveHistory(Event);
            return true;
        }

        auto ObserveHistory(Preview::Foundation::TrafficEvent Event) noexcept -> void
        {
            if (const auto It = SessionProtocols_.find(Event.Session.Value()); It != SessionProtocols_.end())
            {
                if (Event.Protocol == 0) Event.Protocol = It->second.Type;
                if (Event.ProtocolInstance == 0) Event.ProtocolInstance = It->second.Instance;
                if (Event.Ingress == 0) Event.Ingress = It->second.Ingress;
                if (Event.Transport == Preview::Foundation::TrafficTransport::Unknown) Event.Transport = It->second.Transport;
                if (!Event.Account) Event.Account = It->second.Account;
            }
            (void)Analysis_.Record(Event);
        }

        struct ProtocolAssociation final
        {
            std::uint64_t Type{0};
            std::uint64_t Instance{0};
            std::uint64_t Ingress{0};
            Preview::Foundation::TrafficTransport Transport{Preview::Foundation::TrafficTransport::Unknown};
            Preview::AccountId Account{};
        };

        Preview::ProcessId Process_;
        Preview::GenerationId Generation_;
        std::shared_ptr<GenerationPublication> Publication_;
        Preview::Runtime::Detail::RecognitionLatencyStore RecognitionLatency_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> ControlReclaimer_;
        std::vector<std::unique_ptr<WorkerQueue>> Queues_;
        Preview::Statistics::SparseCounters Counters_;
        std::unordered_map<std::uint64_t, ProtocolAssociation> SessionProtocols_;
        Preview::Statistics::TrafficHistory History_;
        Preview::Runtime::Detail::HistoryCollector Analysis_;
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

} // namespace Preview::Runtime
