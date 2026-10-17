/** @file HistoryCollector.hpp @brief 控制执行域的真实观察窗口与分辨率聚合 owner。 */
#pragma once
#include <Preview/Statistics/Analysis/HistoryCatalog.hpp>
#include <Preview/Statistics/Analysis/HistorySeries.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <tuple>
#include <utility>

namespace Preview::Runtime::Detail
{
    /** @brief 仅应用控制 executor 调用；归属以事件 Generation 对应的冻结配置为准。 */
    class HistoryCollector final
    {
    public:
        static constexpr std::size_t MaxPendingSeries{65'536U};
        static constexpr std::size_t MaxMemoryRecords{65'536U};
        static constexpr std::size_t MaxPersistenceRecords{65'536U};

        auto Configure(Preview::Statistics::HistoryCatalog Catalog) -> void
        {
            if (Catalog.Generation == 0 || Catalog.InstanceKey.empty() || Catalog.Incarnation.empty()) return;
            Catalogs_.insert_or_assign(Catalog.Generation, std::move(Catalog));
        }

        /** @brief owner 退休后才移除身份目录；已聚合历史仍拥有字符串值。 */
        auto RetireGeneration(std::uint64_t Generation) -> void { Catalogs_.erase(Generation); }

        /** @brief 成功消费的观察只聚合一次；失败不改变业务，下一窗口公开不完整标记。 */
        [[nodiscard]] auto Record(const Preview::Foundation::TrafficEvent &Event) noexcept -> bool
        {
            try
            {
                const auto Catalog = Event.Kind == Preview::Foundation::TrafficEventKind::NetworkLatency &&
                    !Catalogs_.empty() ? std::prev(Catalogs_.end()) : Catalogs_.find(Event.Generation.Value());
                if (Catalog == Catalogs_.end()) return false;
                const auto &Configuration = Catalog->second;
                Add(Configuration, {Preview::Statistics::HistoryScope::Process, "process"}, Event);
                Add(Configuration, {Preview::Statistics::HistoryScope::Worker, std::to_string(Event.Worker.Value())}, Event);
                if (Event.Kind == Preview::Foundation::TrafficEventKind::NetworkLatency) return true;
                const auto Account = std::find_if(Configuration.Accounts.begin(), Configuration.Accounts.end(),
                    [&Event](const auto &Value) { return Value.NumericId == Event.Account.Value(); });
                if (Account != Configuration.Accounts.end())
                {
                    Add(Configuration, {Preview::Statistics::HistoryScope::Account, Account->Key}, Event);
                    Add(Configuration, {Preview::Statistics::HistoryScope::Group,
                        Account->GroupKey.empty() ? "ungrouped" : Account->GroupKey}, Event);
                }
                const auto Protocol = std::find_if(Configuration.Protocols.begin(), Configuration.Protocols.end(),
                    [&Event](const auto &Value) { return Value.NumericId == Event.ProtocolInstance; });
                Add(Configuration, {Preview::Statistics::HistoryScope::ProtocolInstance,
                    Protocol != Configuration.Protocols.end() ? Protocol->Key : "unattributed"}, Event);
                const auto Type = Event.Protocol != 0 ? Event.Protocol :
                    Protocol != Configuration.Protocols.end() ? Protocol->Type : 0U;
                Add(Configuration, {Preview::Statistics::HistoryScope::ProtocolType,
                    Type != 0 ? std::to_string(Type) : "unattributed"}, Event);
                const auto Ingress = std::find_if(Configuration.Ingresses.begin(), Configuration.Ingresses.end(),
                    [&Event](const auto &Value) { return Value.NumericId == Event.Ingress &&
                        Value.Transport == static_cast<std::uint8_t>(Event.Transport); });
                Add(Configuration, {Preview::Statistics::HistoryScope::Ingress,
                    Ingress != Configuration.Ingresses.end() ? Ingress->Key : "unattributed"}, Event);
                return true;
            }
            catch (...) { PendingFailure_ = true; return false; }
        }

        /** @brief 当前 flush 后形成实际窗口；延迟队列仅有消费时间，覆盖文案明确这一边界。 */
        auto Sample(std::uint64_t Now, Preview::Statistics::HistoryQuality Quality) noexcept -> void
        {
            try { SampleOwned(Now, Quality); }
            catch (...) { PendingFailure_ = true; }
        }

        [[nodiscard]] auto TakePersistenceBatch() -> std::vector<Preview::Statistics::HistoryRecord>
        { auto Result = std::move(Persistence_); Persistence_.clear(); return Result; }

        [[nodiscard]] auto Query(const Preview::Statistics::HistoryQuery &Request, std::uint64_t Now) const
            -> Preview::Statistics::HistoryResult
        {
            Preview::Statistics::HistoryResult Result;
            Result.SampledAt = Now; Result.From = Request.From; Result.To = Request.To;
            Result.ResolutionMilliseconds = Preview::Statistics::HistoryResolution(Request, Now);
            Result.Coverage = "accepted_observations_at_control_flush; no_zero_fill; active_not_collected";
            if (!Preview::Statistics::ValidHistoryQuery(Request)) { Result.Failure = "invalid_history_query"; return Result; }
            for (const auto &Value : Memory_)
                if (Value.Scope == Request.Scope && Value.Key == Request.Key && Value.Metric == Request.Metric &&
                    Value.Timestamp >= Request.From && Value.Timestamp < Request.To) Result.Items.push_back(Value);
            Result.Items = Preview::Statistics::AggregateHistory(std::move(Result.Items), Result.ResolutionMilliseconds);
            Result.Available = !Result.Items.empty();
            Preview::Statistics::FindHistoryGaps(Result);
            return Result;
        }

    private:
        using Key = std::tuple<std::uint64_t, Preview::Statistics::HistoryScope, std::string,
            Preview::Statistics::HistoryMetric>;
        struct Series final { Preview::Statistics::HistoryScope Scope; std::string Key; };

        auto Add(const Preview::Statistics::HistoryCatalog &Catalog, Series IdentityValue,
            const Preview::Foundation::TrafficEvent &Event) -> void
        {
            using EventKind = Preview::Foundation::TrafficEventKind;
            using MetricType = Preview::Statistics::HistoryMetric;
            const auto Metric = Event.Kind == EventKind::RecognitionLatency ? MetricType::RecognitionAdmission :
                Event.Kind != EventKind::NetworkLatency ? MetricType::Traffic :
                Event.NetworkStage == Preview::Foundation::NetworkLatencyStage::DnsResolution ? MetricType::DnsResolution :
                MetricType::TcpConnect;
            const auto Generation = Event.Kind == EventKind::NetworkLatency ? 0U : Catalog.Generation;
            const Key Identity{Generation, IdentityValue.Scope, IdentityValue.Key, Metric};
            if (!Pending_.contains(Identity) && Pending_.size() >= MaxPendingSeries)
            { PendingFailure_ = true; return; }
            auto &Value = Pending_[Identity];
            Value.Scope = IdentityValue.Scope; Value.Key = std::move(IdentityValue.Key); Value.InstanceKey = Catalog.InstanceKey;
            Value.Incarnation = Catalog.Incarnation; Value.Generation = Generation; Value.Metric = Metric;
            if (Event.Kind == EventKind::RecognitionLatency || Event.Kind == EventKind::NetworkLatency)
            {
                Value.Latency.Record(Event.DurationMicroseconds);
                ++Value.Events;
                if (Event.Failure.Failed() && Event.Failure.Code != Preview::Fault::Code::Canceled &&
                    Event.Failure.Code != Preview::Fault::Code::Eof) ++Value.Errors;
            }
            else
            {
                Value.UpBytes += Event.Up; Value.DownBytes += Event.Down;
                if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed)
                {
                    ++Value.Events;
                    if (Event.Failure.Failed() && Event.Failure.Code != Preview::Fault::Code::Canceled &&
                        Event.Failure.Code != Preview::Fault::Code::Eof) ++Value.Errors;
                }
            }
        }

        auto SampleOwned(std::uint64_t Now, Preview::Statistics::HistoryQuality Quality) -> void
        {
            if (LastSample_ != 0 && Now <= LastSample_) { PendingFailure_ = true; return; }
            if (!Catalogs_.empty())
            {
                const auto &Current = Catalogs_.rbegin()->second;
                Preview::Foundation::TrafficEvent Heartbeat;
                Heartbeat.Kind = Preview::Foundation::TrafficEventKind::Bytes;
                Add(Current, {Preview::Statistics::HistoryScope::Process, "process"}, Heartbeat);
            }
            const auto Width = LastSample_ != 0 ? Now - LastSample_ : 1'000U;
            Quality.Incomplete = Quality.Incomplete || PendingFailure_ || Width > 2'000U;
            for (auto &[Identity, Value] : Pending_)
            {
                (void)Identity;
                Value.Timestamp = LastSample_ != 0 ? LastSample_ : Now - (std::min)(Now, Width);
                Value.ResolutionMilliseconds = Width;
                Value.Quality = Quality;
                Memory_.push_back(Value);
                for (const auto Resolution : {10'000ULL, 60'000ULL, 900'000ULL}) AddPersistent(Value, Resolution);
            }
            Pending_.clear(); PendingFailure_ = false; LastSample_ = Now;
            while (!Memory_.empty() && (Memory_.size() > MaxMemoryRecords ||
                (Now > Memory_.front().Timestamp && Now - Memory_.front().Timestamp >
                    Preview::Statistics::HistoryMemoryRetention))) Memory_.pop_front();
            ClosePersistent(Now);
        }

        auto AddPersistent(const Preview::Statistics::HistoryRecord &Value, std::uint64_t Resolution) -> void
        {
            auto Copy = Value;
            Copy.Timestamp -= Copy.Timestamp % Resolution; Copy.ResolutionMilliseconds = Resolution;
            const auto Identity = std::tuple{Resolution, Copy.Timestamp, Copy.Generation, Copy.Scope, Copy.Key, Copy.Metric};
            if (!PersistentWindows_.contains(Identity) && PersistentWindows_.size() >= MaxPendingSeries * 3U)
            { PendingFailure_ = true; return; }
            auto [It, Inserted] = PersistentWindows_.try_emplace(Identity, Copy);
            if (!Inserted) (void)Preview::Statistics::MergeHistoryRecord(It->second, Copy);
        }

        auto ClosePersistent(std::uint64_t Now) -> void
        {
            for (auto It = PersistentWindows_.begin(); It != PersistentWindows_.end();)
            {
                const auto &Value = It->second;
                if (Now < Value.Timestamp || Now - Value.Timestamp < Value.ResolutionMilliseconds) { ++It; continue; }
                if (Persistence_.size() < MaxPersistenceRecords) Persistence_.push_back(Value);
                else PendingFailure_ = true;
                It = PersistentWindows_.erase(It);
            }
        }

        std::map<std::uint64_t, Preview::Statistics::HistoryCatalog> Catalogs_;
        std::map<Key, Preview::Statistics::HistoryRecord> Pending_;
        std::deque<Preview::Statistics::HistoryRecord> Memory_;
        std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t,
            Preview::Statistics::HistoryScope, std::string, Preview::Statistics::HistoryMetric>,
            Preview::Statistics::HistoryRecord> PersistentWindows_;
        std::vector<Preview::Statistics::HistoryRecord> Persistence_;
        std::uint64_t LastSample_{0};
        bool PendingFailure_{false};
    };
}
