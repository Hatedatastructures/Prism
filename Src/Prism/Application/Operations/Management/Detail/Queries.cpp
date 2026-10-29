/** @file Queries.cpp @brief Operations 管理面查询快照构造实现。 */
#include <Prism/Application/Operations/Management/Detail/Queries.hpp>
#include <Prism/Application/Operations/Management/Detail/QuerySupport.hpp>
#include <Prism/Runtime/Session/Registry.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Application::OperationsManagementQueries
{

    [[nodiscard]] auto FindProtocol(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        const std::string_view Id) -> const Prism::Contract::ProtocolConfiguration *
    {
        const auto It = std::find_if(Configuration.Protocols.begin(), Configuration.Protocols.end(),
            [Id](const auto &Value) { return Value.Id == Id; });
        return It == Configuration.Protocols.end() ? nullptr : std::addressof(*It);
    }

    [[nodiscard]] auto FindCarrier(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        const std::string_view Id) -> const Prism::Contract::CarrierConfiguration *
    {
        const auto It = std::find_if(Configuration.Carriers.begin(), Configuration.Carriers.end(),
            [Id](const auto &Value) { return Value.Id == Id; });
        return It == Configuration.Carriers.end() ? nullptr : std::addressof(*It);
    }

    [[nodiscard]] auto BindingMatchesTransport(
        const Prism::Contract::ProtocolBindingConfiguration &Binding,
        const Prism::Contract::ProtocolConfiguration &Protocol,
        const std::string_view Transport) -> bool
    {
        if (Transport == "tcp") return Binding.TcpEnabled && !Protocol.Quic;
        if (Transport == "quic") return Binding.UdpEnabled && Protocol.Quic.has_value();
        return Binding.UdpEnabled && !Protocol.Quic;
    }

    [[nodiscard]] auto MakeEvents(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::EventsRead &Read,
        const Prism::RequestId Correlation) -> QueryResult
    {
        if (!State || !State->Events) return QueryResult::Unavailable(Correlation);
        const auto Counts = State->Events->Counts();
        auto Page = State->Events->Page(Read.Page.Cursor, (std::max)(Counts.Size, std::size_t{1}));
        std::vector<Prism::Statistics::DetailedEvent> Matches;
        for (auto Event : Page.Items)
        {
            if ((Read.Process && Event.Process != *Read.Process) ||
                (Read.Worker && Event.Worker != *Read.Worker) ||
                (Read.Account && Event.Account != *Read.Account) ||
                (Read.Session && Event.Session != *Read.Session) ||
                (Read.Severity && Event.Severity != *Read.Severity)) continue;
            if (!Read.IncludeDetails) Event.Detail.clear();
            Matches.push_back(std::move(Event));
        }
        Prism::Statistics::EventPage Result;
        Result.Dropped = Page.Dropped; Result.TerminalDropped = Page.TerminalDropped;
        Result.Overwritten = Page.Overwritten; Result.EarliestCursor = Page.EarliestCursor;
        Result.Lost = Page.Lost; Result.LostRanges = std::move(Page.LostRanges);
        const auto Limit = Read.Page.BoundedLimit();
        const auto Count = (std::min)(Limit, Matches.size());
        Result.Items.insert(Result.Items.end(), Matches.begin(), Matches.begin() + static_cast<std::ptrdiff_t>(Count));
        if (Matches.size() > Limit)
        {
            Result.HasMore = true;
            Result.NextCursor = Result.Items.empty() ? Read.Page.Cursor : Result.Items.back().Sequence;
        }
        else
        {
            Result.HasMore = Page.HasMore;
            Result.NextCursor = Page.NextCursor;
        }
        return QueryResult::Events(Correlation, std::move(Result));
    }

    [[nodiscard]] auto MakeTrace(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::SessionTraceRead &Read,
        const Prism::RequestId Correlation)
        -> QueryResult
    {
        if (!State || !State->Process || Read.Process != State->Process->Id())
            return QueryResult::Unavailable(Correlation);
        Prism::Runtime::SessionTraceQuery QueryValue;
        QueryValue.Process = Read.Process; QueryValue.Session = Read.Session;
        QueryValue.LimitPerWorker = Read.Page.BoundedLimit();
        for (const auto &Cursor : Read.Cursors)
            QueryValue.Cursors.push_back({Cursor.Worker, Cursor.Sequence});
        const auto Snapshot = State->Process->QuerySessionTrace(QueryValue);
        Prism::Operations::TracePageSnapshot Result;
        Result.Items.reserve(Snapshot.Records.size());
        for (const auto &Record : Snapshot.Records)
        {
            Prism::Operations::TraceSpanSnapshot Item;
            Item.SpanId = std::to_string(Record.Identity.Worker.Value()) + "-" + std::to_string(Record.Sequence);
            Item.Sequence = Record.Sequence; Item.Name = std::string(StageName(Record.Stage));
            Item.StartTimeUnixNanoseconds = Record.UtcUnixNanoseconds > 0
                ? static_cast<std::uint64_t>(Record.UtcUnixNanoseconds) : 0U;
            Item.DurationMilliseconds = std::nullopt;
            Item.Status = Record.Outcome == Prism::Runtime::SessionTraceOutcome::Succeeded ? "succeeded" :
                Record.Outcome == Prism::Runtime::SessionTraceOutcome::Failed ? "failed" : "event";
            Item.Process = Record.Identity.Process; Item.Generation = Record.Identity.Generation;
            Item.Session = Record.Identity.Session;
            if (Record.Identity.Worker) Item.Worker = Record.Identity.Worker;
            Item.Account = Record.Identity.Account; Item.Task = Record.Identity.Task;
            Item.ParentTask = Record.Identity.ParentTask; Item.Stream = Record.Identity.Stream;
            Item.Stage = std::string(StageName(Record.Stage));
            Item.Outcome = Record.Outcome == Prism::Runtime::SessionTraceOutcome::Succeeded ? "succeeded" :
                Record.Outcome == Prism::Runtime::SessionTraceOutcome::Failed ? "failed" : "none";
            if (Record.Failure != Prism::Fault::Code::Success)
                Item.FailureCode = static_cast<std::int32_t>(Record.Failure);
            Item.ElapsedNanoseconds = Record.ElapsedNanoseconds;
            Result.Items.push_back(std::move(Item));
        }
        for (const auto &Cursor : Snapshot.Cursors) Result.Cursors.push_back({Cursor.Worker, Cursor.Sequence});
        for (const auto &Loss : Snapshot.Loss)
            Result.Loss.push_back({Loss.Worker, Loss.OverwrittenRecords, Loss.LostSinceCursor,
                Loss.ConcurrentReadSkips});
        Result.HasMore = Snapshot.HasMore;
        for (const auto &Cursor : Result.Cursors)
        {
            if (!Result.NextCursor.empty()) Result.NextCursor.push_back(',');
            Result.NextCursor += std::to_string(Cursor.Worker.Value()) + ":" + std::to_string(Cursor.Sequence);
        }
        if (Result.NextCursor.empty()) Result.NextCursor = "0";
        return QueryResult{Correlation, Prism::Operations::QueryStatus::Ok,
            Prism::Operations::ManagementPayload{std::move(Result)}, {}};
    }

    [[nodiscard]] auto StageName(const Prism::Runtime::SessionTraceStage Stage) -> std::string_view
    {
        using StageType = Prism::Runtime::SessionTraceStage;
        switch (Stage)
        {
        case StageType::TcpAccepted: return "tcp.accepted";
        case StageType::WorkerDispatchAccepted: return "worker.dispatch.accepted";
        case StageType::SessionAdmissionStarted: return "session.admission.started";
        case StageType::SessionStarted: return "session.started";
        case StageType::CarrierProbeStarted: return "carrier.probe.started";
        case StageType::CarrierProbeCompleted: return "carrier.probe.completed";
        case StageType::RecognitionStarted: return "recognition.started";
        case StageType::RecognitionCompleted: return "recognition.completed";
        case StageType::ProtocolAcceptStarted: return "protocol.accept.started";
        case StageType::ProtocolAcceptCompleted: return "protocol.accept.completed";
        case StageType::AuthenticationConfirmed: return "authentication.confirmed";
        case StageType::OutboundResolveDialStarted: return "outbound.resolve_dial.started";
        case StageType::OutboundResolveDialCompleted: return "outbound.resolve_dial.completed";
        case StageType::RelayStarted: return "relay.started";
        case StageType::RelayFirstUploadByte: return "relay.first_upload_byte";
        case StageType::RelayFirstDownloadByte: return "relay.first_download_byte";
        case StageType::RelayCompleted: return "relay.completed";
        case StageType::SessionClosed: return "session.closed";
        }
        return "unknown";
    }

    [[nodiscard]] auto MakeOperations(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::OperationsRead &QueryValue,
        const Prism::RequestId Correlation)
        -> QueryResult
    {
        if (!State || !State->Events) return QueryResult::Unavailable(Correlation);
        std::map<std::uint64_t, Prism::Operations::OperationSnapshot> Items;
        for (const auto &Event : State->Events->Snapshot())
        {
            if (Event.Operation == 0U) continue;
            auto &Item = Items[Event.Operation];
            Item.Id = Event.Operation; Item.Correlation = Event.Correlation;
            Item.Generation = Event.Generation; Item.Process = Event.Process;
            Item.Worker = Event.Worker; Item.Account = Event.Account;
            Item.Session = Event.Session; Item.Stream = Event.Stream; Item.Task = Event.Task;
            if (Event.ScopeValue == Prism::Statistics::Scope::Worker) Item.Command = "worker_drain";
            else if (Event.ScopeValue == Prism::Statistics::Scope::Account) Item.Command = "account_revoke";
            else if (Event.ScopeValue == Prism::Statistics::Scope::Session) Item.Command = "session_cancel";
            else if (Event.ScopeValue == Prism::Statistics::Scope::Stream) Item.Command = "stream_reset";
            else if (Event.ScopeValue == Prism::Statistics::Scope::Task) Item.Command = "task_cancel";
            else Item.Command = "process_operation";
            if (Event.Kind == Prism::Statistics::EventKind::OperationAccepted)
            {
                Item.AcceptedAt = Event.Timestamp; Item.UpdatedAt = Event.Timestamp;
                Item.Status = "accepted";
            }
            else
            {
                Item.UpdatedAt = Event.Timestamp;
                Item.Status = Event.Kind == Prism::Statistics::EventKind::OperationCompleted
                    ? "completed" : "failed";
            }
        }
        std::vector<Prism::Operations::OperationSnapshot> Values;
        Values.reserve(Items.size());
        for (auto It = Items.rbegin(); It != Items.rend(); ++It) Values.push_back(It->second);
        auto Page = PageByOffset(Values, QueryValue.Page);
        return QueryResult{Correlation, Prism::Operations::QueryStatus::Ok,
            Prism::Operations::ManagementPayload{std::move(Page)}, {}};
    }

    [[nodiscard]] auto MakeIngresses(
        const std::shared_ptr<RuntimeState> &State,
        const IngressesQueryRequest &Request) -> QueryResult
    {
        const auto Generation = State ? State->ActiveGenerationSnapshot() : nullptr;
        if (!Generation) return QueryResult::Unavailable(Request.Correlation);
        const auto &Configuration = Generation->Generation->Configuration();
        std::vector<Prism::Operations::IngressSnapshot> Values;
        const IngressSnapshotBuilder Builder{Configuration, Values};
        const auto TcpBound = State->Listener
            ? std::optional<std::string>{EndpointText(State->Listener->LocalEndpoint())}
            : std::nullopt;
        Builder.Append(Configuration.Listeners.Tcp, IngressTransportSnapshot{
            "tcp", Request.Health.TcpReady, TcpBound,
            State->Listener ? std::optional<std::uint64_t>{State->Listener->Registry().Size()}
                            : std::nullopt});
        const auto UdpBound = State->DatagramListener
            ? std::optional<std::string>{EndpointText(State->DatagramListener->LocalEndpoint())} : std::nullopt;
        Builder.Append(Configuration.Listeners.Udp, IngressTransportSnapshot{
            "udp", Request.Health.UdpReady, UdpBound, std::nullopt});
        const auto QuicCount = State->QuicConnectionRegistry
            ? std::optional<std::uint64_t>{State->QuicConnectionRegistry->ActiveConnectionCount()} : std::nullopt;
        Builder.Append(Configuration.Listeners.Quic, IngressTransportSnapshot{
            "quic", Request.Health.QuicReady, UdpBound, QuicCount});
        const auto Page = PageByOffset(Values, Request.Query.Page);
        return QueryResult{Request.Correlation, Prism::Operations::QueryStatus::Ok,
            Prism::Operations::ManagementPayload{Page}, {}};
    }

    [[nodiscard]] auto MakeGroups(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::GroupsRead &QueryValue,
        const Prism::RequestId Correlation)
        -> QueryResult
    {
        const auto Generation = State ? State->ActiveGenerationSnapshot() : nullptr;
        if (!Generation) return QueryResult::Unavailable(Correlation);
        const auto &Configuration = Generation->Generation->Configuration();
        std::vector<Prism::Operations::GroupSnapshot> Values;
        Values.reserve(Configuration.AccountGroups.size());
        for (const auto &Group : Configuration.AccountGroups)
        {
            std::uint64_t ConfiguredCount = 0;
            for (const auto &Account : Configuration.Accounts)
                if (Account.GroupId && *Account.GroupId == Group.Id) ++ConfiguredCount;
            Values.push_back({Group.Id, Group.Name, ConfiguredCount, 0U, 0U,
                State->Traffic ? std::optional<Prism::Statistics::TrafficValue>{Prism::Statistics::TrafficValue{}}
                    : std::nullopt});
        }
        for (const auto &Account : MakeAccountValues(State))
        {
            if (!Account.GroupId) continue;
            const auto Group = std::find_if(Values.begin(), Values.end(), [&Account](const auto &Value)
                { return Value.Id == *Account.GroupId; });
            if (Group == Values.end()) continue;
            if (Account.ActiveSessions != 0U) ++Group->ActiveAccounts;
            if (Group->ActiveSessions) *Group->ActiveSessions += Account.ActiveSessions;
            if (Group->Traffic && Account.Traffic) *Group->Traffic += *Account.Traffic;
        }
        const auto Page = PageByOffset(Values, QueryValue.Page);
        return QueryResult{Correlation,
            Prism::Operations::QueryStatus::Ok, Prism::Operations::ManagementPayload{Page}, {}};
    }

    [[nodiscard]] auto MakeAccountValues(const std::shared_ptr<RuntimeState> &State)
        -> std::vector<Prism::Operations::AccountSnapshot>
    {
        std::vector<Prism::Operations::AccountSnapshot> Result;
        if (!State || !State->GenerationPublisher) return Result;
        const auto Publication = State->GenerationPublisher->Read();
        const auto Generation = std::dynamic_pointer_cast<const Prism::Application::RuntimeGenerationSnapshot>(
            Publication.Active);
        if (!Generation || !Generation->Accounts.Store || !Publication.Accounts) return Result;
        const ManagementAccountSnapshotContext Snapshot{State, Generation, Publication.Accounts};
        Generation->Accounts.Store->ForEach(AccountSnapshotCollector{Result, Snapshot});
        return Result;
    }

    [[nodiscard]] auto MakeOverview(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::RequestId Correlation,
        const Prism::Statistics::HealthSnapshot &Health) -> QueryResult
    {
        const auto Generation = State ? State->ActiveGenerationSnapshot() : nullptr;
        if (!State || !State->Process || !Generation)
            return QueryResult::Unavailable(Correlation);
        Prism::Operations::OverviewSnapshot Result;
        Result.Process = State->Process->Id();
        Result.Generation = Generation->Id();
        const auto Phase = State->Phase.load(std::memory_order_acquire);
        Result.Phase = Phase == RuntimePhase::Ready ? "ready" :
            Phase == RuntimePhase::Stopping ? "stopping" : Phase == RuntimePhase::Failed ? "failed" :
            Phase == RuntimePhase::Stopped ? "stopped" : "created";
        Result.SampledAt = UnixMilliseconds();
        Result.Health = Health;
        const auto &Configuration = Generation->Generation->Configuration();
        Result.ConfiguredAccounts = Configuration.Accounts.size();
        for (const auto &Account : Configuration.Accounts)
            if (!Account.GroupId) ++Result.UngroupedAccounts;
        const auto Workers = State->Process->Snapshot();
        Result.WorkersTotal = Workers.size();
        for (const auto &Worker : Workers)
            if (Worker.Accepting) ++Result.WorkersAccepting;
        Result.TcpSessions = State->Listener ? State->Listener->Registry().Size() : 0U;
        if (State->QuicConfigured && State->QuicConnectionRegistry)
            Result.QuicConnections = State->QuicConnectionRegistry->ActiveConnectionCount();
        else if (!State->QuicConfigured) Result.QuicConnections = 0U;
        Result.UdpConnections.reset();
        if (State->Traffic)
        {
            Result.Traffic = State->Traffic->Value(Prism::Statistics::Scope::Process,
                Result.Process.Value());
            Result.History = State->Traffic->History();
            Result.AcceptedObservations = State->Traffic->Accepted();
            Result.ConsumedObservations = State->Traffic->ConsumedObservations();
            Result.DroppedObservations = State->Traffic->Dropped();
            Result.AggregationFailures = State->Traffic->AggregationFailures();
            Result.SampleIntervalMilliseconds = static_cast<std::uint64_t>((std::max)(
                State->StatisticsFlushArmedIntervalMilliseconds.load(std::memory_order_acquire),
                std::int64_t{0}));
            if (Result.History.size() >= 2U)
            {
                const auto &Previous = Result.History[Result.History.size() - 2U];
                const auto &Last = Result.History.back();
                const auto Elapsed = Last.Timestamp - Previous.Timestamp;
                if (Elapsed != 0U && Last.Value.UpBytes >= Previous.Value.UpBytes &&
                    Last.Value.DownBytes >= Previous.Value.DownBytes)
                {
                    Result.UploadBytesPerSecond = ((Last.Value.UpBytes - Previous.Value.UpBytes) / Elapsed) * 1000U +
                        (((Last.Value.UpBytes - Previous.Value.UpBytes) % Elapsed) * 1000U) / Elapsed;
                    Result.DownloadBytesPerSecond =
                        ((Last.Value.DownBytes - Previous.Value.DownBytes) / Elapsed) * 1000U +
                        (((Last.Value.DownBytes - Previous.Value.DownBytes) % Elapsed) * 1000U) / Elapsed;
                }
            }
            const auto Latency = State->Traffic->RecognitionLatency(Result.Generation);
            Result.RecognitionAdmission.Name = "recognition_admission";
            Result.RecognitionAdmission.Available = Latency.SampleCount != 0U;
            Result.RecognitionAdmission.SampleCount = Latency.SampleCount;
            if (Latency.P50BucketLowerBoundMicroseconds)
                Result.RecognitionAdmission.P50Milliseconds = *Latency.P50BucketLowerBoundMicroseconds / 1000U;
            if (Latency.P95BucketLowerBoundMicroseconds)
                Result.RecognitionAdmission.P95Milliseconds = *Latency.P95BucketLowerBoundMicroseconds / 1000U;
            if (Latency.P99BucketLowerBoundMicroseconds)
                Result.RecognitionAdmission.P99Milliseconds = *Latency.P99BucketLowerBoundMicroseconds / 1000U;
            if (Latency.MaximumObservedMicroseconds)
                Result.RecognitionAdmission.MaximumMilliseconds = *Latency.MaximumObservedMicroseconds / 1000U;
        }
        PopulateMemorySnapshot(*State, Result.Memory);
        Result.Protocols = MakeProtocolSnapshots(*State, *Generation);
        for (const auto &Account : MakeAccountValues(State))
            if (Account.ActiveSessions != 0U) ++Result.ActiveAccounts;
        return QueryResult{Correlation, Prism::Operations::QueryStatus::Ok,
            Prism::Operations::ManagementPayload{std::move(Result)}, {}};
    }

    auto PopulateMemorySnapshot(
        const RuntimeState &State, Prism::Operations::MemorySnapshot &Result) -> void
    {
        if (const auto ProcessMemory = Prism::Memory::ReadProcessMemoryUsage())
        {
            Result.ProcessAvailable = true;
            Result.ResidentBytes = ProcessMemory->CurrentResidentBytes;
            Result.PeakResidentBytes = ProcessMemory->PeakResidentBytes;
        }
        if (!State.Process) return;
        const auto ProcessSnapshot = State.Process->Resources().MemorySnapshot();
        const auto &Pmr = ProcessSnapshot.Pmr;
        Result.ProcessAllocations = {true, Pmr.CurrentBytes, Pmr.PeakBytes,
            Pmr.AllocationCount, Pmr.DeallocationCount,
            "仅计通过 Prism ProcessResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配"};
        if (const auto &Pool = State.Process->Resources().Bytes)
        {
            const auto PoolMetrics = ProcessSnapshot.BytePool;
            Result.ProcessPool = {true, PoolMetrics.UsedBytes, PoolMetrics.CapacityBytes,
                Pool->AvailableBlocks(), Pool->BlockSize(), PoolMetrics.PeakUsedBytes,
                PoolMetrics.AllocationCount, PoolMetrics.ReleaseCount};
        }
        Result.WorkerAllocations.reserve(State.Process->Workers().Size());
        for (std::size_t Index = 0; Index < State.Process->Workers().Size(); ++Index)
        {
            const auto Id = Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto *Worker = State.Process->Workers().Find(Id);
            if (!Worker) continue;
            const auto Snapshot = Worker->Resources().MemorySnapshot();
            const auto &Allocation = Snapshot.Pmr;
            Result.WorkerAllocations.push_back({Id, {true, Allocation.CurrentBytes, Allocation.PeakBytes,
                Allocation.AllocationCount, Allocation.DeallocationCount,
                "仅计通过 WorkerResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配"}});
        }
    }

    [[nodiscard]] auto MakeProtocolSnapshots(
        const RuntimeState &State, const Prism::Application::RuntimeGenerationSnapshot &Generation)
        -> std::vector<Prism::Operations::ProtocolSnapshot>
    {
        const auto &Configuration = Generation.Generation->Configuration();
        std::vector<Prism::Operations::ProtocolSnapshot> Result;
        Result.reserve(Configuration.Protocols.size());
        for (const auto &Protocol : Configuration.Protocols)
        {
            Prism::Operations::ProtocolSnapshot Item;
            Item.Id = Protocol.Id;
            Item.Name = Protocol.Name;
            Item.ActiveSessions = Protocol.Quic ? std::nullopt : std::optional<std::uint64_t>{0U};
            Item.Coverage = Protocol.Quic
                ? "QUIC admission 尚未发布协议关联统计，活动 Session 与流量显示为不可用"
                : "活动数仅统计 TCP Session；流量按已接受 Session 的协议身份聚合";
            for (const auto &Binding : Configuration.ProtocolBindings)
                if (Binding.ProtocolId == Protocol.Id && (Binding.TcpEnabled || Binding.UdpEnabled))
                    ++Item.ConfiguredBindings;
            const auto Type = ProtocolTypeForName(Protocol.Name);
            if (Type && State.Traffic && !Protocol.Quic)
                Item.Traffic = State.Traffic->Value(Prism::Statistics::Scope::Protocol, *Type);
            Result.push_back(std::move(Item));
        }
        if (State.Listener)
        {
            for (const auto &[Id, Session] : *State.Listener->Registry().Snapshot())
            {
                (void)Id;
                for (auto &Protocol : Result)
                {
                    const auto Type = ProtocolTypeForName(Protocol.Name);
                    if (Type && *Type == Session.Protocol && Protocol.ActiveSessions)
                        ++*Protocol.ActiveSessions;
                }
            }
        }
        return Result;
    }

    [[nodiscard]] auto ProtocolTypeForName(const std::string_view Name)
        -> std::optional<std::uint64_t>
    {
        using Type = Prism::Contract::ProtocolType;
        for (const auto Value : {Type::Http, Type::Socks5, Type::Trojan, Type::Vless,
                Type::Shadowsocks, Type::Vmess, Type::Hysteria2, Type::Tuic, Type::Tls,
                Type::AnyTls, Type::TrustTunnel})
        {
            if (Prism::Contract::ToStringView(Value) == Name)
                return static_cast<std::uint64_t>(Value);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto UnixMilliseconds() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

}
