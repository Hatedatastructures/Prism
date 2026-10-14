/**
 * @file SessionRegistryCompareModelC.cpp
 * @brief executor-owned 可变注册表 C 模型。
 */

#include "SessionRegistryCompareModels.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <latch>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Runtime::Perf
{

    namespace
    {

        struct HookState final
        {
            std::atomic<std::uint64_t> Errors{0};
            std::atomic<std::uint64_t> Metrics{0};
            std::atomic<std::shared_ptr<HookGate>> Gate{std::shared_ptr<HookGate>{}};
        };

        struct CControl final
        {
            std::atomic<bool> Cancelled{false};
        };

        struct CEntry final
        {
            std::uint64_t Id{0};
            std::size_t Shard{0};
            std::atomic<bool> Removed{false};
            std::atomic<std::shared_ptr<CControl>> Control;
            std::atomic<bool> ErrorHookInstalled{false};
            std::atomic<bool> MetricsHookInstalled{false};
            std::shared_ptr<HookState> Hook;
        };

        struct CTokenState final : TokenState
        {
            explicit CTokenState(std::shared_ptr<CEntry> EntryValue)
                : Entry(std::move(EntryValue))
            {
            }

            std::shared_ptr<CEntry> Entry;
        };

        auto EmitCErrorHook(const std::shared_ptr<CEntry> &Entry,
                            const std::shared_ptr<HookState> &Hook) -> void
        {
            if (!Entry->Removed.load(std::memory_order_seq_cst) &&
                Entry->ErrorHookInstalled.load(std::memory_order_acquire))
            {
                if (const auto Gate = Hook->Gate.load(std::memory_order_acquire))
                {
                    Gate->PauseAfterCheck();
                }
                Hook->Errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        auto EmitCMetricsHook(const std::shared_ptr<CEntry> &Entry,
                              const std::shared_ptr<HookState> &Hook) -> void
        {
            if (!Entry->Removed.load(std::memory_order_seq_cst) &&
                Entry->MetricsHookInstalled.load(std::memory_order_acquire))
            {
                if (const auto Gate = Hook->Gate.load(std::memory_order_acquire))
                {
                    Gate->PauseAfterCheck();
                }
                Hook->Metrics.fetch_add(1, std::memory_order_relaxed);
            }
        }

        auto MakeCHooks(const std::shared_ptr<CEntry> &Entry) -> HookPair
        {
            const auto Hook = Entry->Hook;
            HookPair Result;
            Result.Error = [Entry, Hook] { EmitCErrorHook(Entry, Hook); };
            Result.Metrics = [Entry, Hook] { EmitCMetricsHook(Entry, Hook); };
            return Result;
        }

        /** @brief 冷路径故障注入记录；构造失败后仍由验证调用方持有。 */
        struct ExecutorStartupProbe final
        {
            std::size_t FailBefore{(std::numeric_limits<std::size_t>::max)()};
            std::atomic<std::size_t> Started{0};
            std::atomic<std::size_t> Exited{0};
            std::size_t Joined{0};
        };

        class ExecutorGroup final
        {
        private:
            struct Worker final
            {
                std::mutex Mutex;
                std::condition_variable Condition;
                std::deque<std::function<void()>> Queue;
                bool Stopping{false};
                std::thread Thread;
                std::thread::id Owner;
            };

        public:
            explicit ExecutorGroup(const std::size_t Count, ExecutorStartupProbe *Probe = nullptr)
                : Probe_(Probe)
            {
                Workers_.reserve(Count);
                try
                {
                    for (std::size_t Index = 0; Index < Count; ++Index)
                    {
                        Workers_.push_back(std::make_unique<Worker>());
                        auto *WorkerPointer = Workers_.back().get();
                        if (Probe_ && Probe_->FailBefore == Index)
                            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
                        WorkerPointer->Thread = std::thread([this, WorkerPointer]
                                                          { RunWorker(*WorkerPointer); });
                    }
                }
                catch (...)
                {
                    Stop();
                    throw;
                }
            }

            ~ExecutorGroup()
            {
                Stop();
            }

            template <typename Result, typename Function>
            auto Invoke(const std::size_t Index, Function FunctionValue) -> Result
            {
                auto &WorkerValue = *Workers_.at(Index % Workers_.size());
                if (IsOwner(WorkerValue))
                {
                    return FunctionValue();
                }
                auto Promise = std::make_shared<std::promise<Result>>();
                auto Future = Promise->get_future();
                Post(Index, [Promise, FunctionValue = std::move(FunctionValue)]() mutable
                { CompletePromise(Promise, std::move(FunctionValue)); });
                return Future.get();
            }

        private:
            template <typename Result, typename Function>
            static auto CompletePromise(const std::shared_ptr<std::promise<Result>> &Promise,
                                        Function FunctionValue) -> void
            {
                try
                {
                    Promise->set_value(FunctionValue());
                }
                catch (...)
                {
                    Promise->set_exception(std::current_exception());
                }
            }

            auto IsOwner(const Worker &WorkerValue) const -> bool
            {
                std::lock_guard Lock(OwnerMutex_);
                return WorkerValue.Owner == std::this_thread::get_id();
            }

            auto Post(const std::size_t Index, std::function<void()> Command) -> void
            {
                auto &WorkerValue = *Workers_.at(Index % Workers_.size());
                {
                    std::lock_guard Lock(WorkerValue.Mutex);
                    if (WorkerValue.Stopping)
                    {
                        throw std::runtime_error("executor stopped");
                    }
                    WorkerValue.Queue.push_back(std::move(Command));
                }
                WorkerValue.Condition.notify_one();
            }

            auto RunWorker(Worker &WorkerValue) -> void
            {
                if (Probe_) Probe_->Started.fetch_add(1, std::memory_order_relaxed);
                {
                    std::lock_guard Lock(OwnerMutex_);
                    WorkerValue.Owner = std::this_thread::get_id();
                }
                while (true)
                {
                    std::function<void()> Command;
                    {
                        std::unique_lock Lock(WorkerValue.Mutex);
                        WorkerValue.Condition.wait(
                            Lock, [&WorkerValue]
                            { return WorkerValue.Stopping || !WorkerValue.Queue.empty(); });
                        if (WorkerValue.Queue.empty() && WorkerValue.Stopping)
                        {
                            if (Probe_) Probe_->Exited.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }
                        Command = std::move(WorkerValue.Queue.front());
                        WorkerValue.Queue.pop_front();
                    }
                    Command();
                }
            }

            auto Stop() noexcept -> void
            {
                for (const auto &WorkerValue : Workers_)
                {
                    {
                        std::lock_guard Lock(WorkerValue->Mutex);
                        WorkerValue->Stopping = true;
                    }
                    WorkerValue->Condition.notify_one();
                }
                for (const auto &WorkerValue : Workers_)
                {
                    if (WorkerValue->Thread.joinable())
                    {
                        WorkerValue->Thread.join();
                        if (Probe_) ++Probe_->Joined;
                    }
                }
            }

            std::vector<std::unique_ptr<Worker>> Workers_;
            mutable std::mutex OwnerMutex_;
            ExecutorStartupProbe *Probe_{nullptr};
        };

        auto MakeConcurrentInfo(const std::uint64_t Id, const std::uint64_t Value)
            -> SessionInfo
        {
            SessionInfo Info;
            Info.Id = Id;
            Info.AccountId = Preview::AccountId{Id};
            Info.identity = "concurrent-" + std::to_string(Id);
            Info.peer = "peer-concurrent";
            Info.Target = "target-concurrent.example:443";
            Info.Protocol = 1;
            Info.StartedAt = Value;
            return Info;
        }

        auto SameConcurrentInfo(const SessionInfo &Left, const SessionInfo &Right) -> bool
        {
            return Left.Id == Right.Id && Left.AccountId == Right.AccountId &&
                   Left.identity == Right.identity && Left.peer == Right.peer &&
                   Left.Target == Right.Target && Left.Protocol == Right.Protocol &&
                   Left.StartedAt == Right.StartedAt;
        }

        auto RequireConcurrentContract(const bool Condition, const char *Message) -> void
        {
            if (!Condition)
            {
                throw std::runtime_error(Message);
            }
        }

    } // namespace

    class ExecutorTableModel final : public IModel
    {
    public:
        struct State;

        explicit ExecutorTableModel(std::size_t Executors);
        ~ExecutorTableModel() override;

        auto Register(const SessionInfo &Info) -> Token override;
        auto Find(std::uint64_t Id, SessionInfo &Output) -> bool override;
        auto Size() -> std::size_t override;
        auto Snapshot() -> SnapshotMap override;
        auto Cancel(std::uint64_t Id) -> bool override;
        auto Reset(const Token &Value) -> bool override;
        auto TokenActive(const Token &Value) const -> bool override;
        auto FailNextCompaction(std::uint64_t Id) -> void override;
        auto FailNextHookInstallation() -> void override;
        auto EmitFailedErrorHook() -> bool override;
        auto SetHookGate(std::shared_ptr<HookGate> Gate) -> void override;
        auto PendingRemovals() -> std::size_t override;
        auto Shutdown() -> void override;
        auto HookSnapshot() const -> HookCounts override;

    private:
        auto RegisterOnExecutor(std::size_t Index, const SessionInfo &Info,
                                const std::shared_ptr<CEntry> &Entry) -> bool;
        auto FindOnExecutor(std::size_t Index, std::uint64_t Id)
            -> std::optional<SessionInfo>;
        auto SizeOnExecutor(std::size_t Index) -> std::size_t;
        auto SnapshotOnExecutor(std::size_t Index) -> SnapshotMap;
        auto CancelOnExecutor(std::size_t Index, std::uint64_t Id) -> bool;
        auto ResetOnExecutor(const std::shared_ptr<CEntry> &Entry) -> bool;
        auto TokenActiveOnExecutor(std::size_t Index,
                                   const std::shared_ptr<CEntry> &Entry) const -> bool;
        auto PendingOnExecutor(std::size_t Index) -> std::size_t;
        auto ShutdownOnExecutor(std::size_t Index) -> std::size_t;
        std::unique_ptr<State> State_;
    };

    struct ExecutorTableModel::State final
    {
        struct Record final
        {
            SessionInfo Info;
            std::shared_ptr<CEntry> Entry;
        };

        struct Table final
        {
            std::unordered_map<std::uint64_t, Record> Records;
            std::size_t FailNext{0};
        };

        explicit State(const std::size_t Count)
            : Tables(Count), Executors(std::make_unique<ExecutorGroup>(Count)),
              Hook(std::make_shared<HookState>())
        {
            if (Count == 0)
            {
                throw std::invalid_argument("executor model requires an executor");
            }
        }

        std::vector<Table> Tables;
        std::unique_ptr<ExecutorGroup> Executors;
        std::shared_ptr<HookState> Hook;
        std::atomic<std::size_t> FailNextHook{0};
        std::atomic<std::shared_ptr<CEntry>> FailedEntry{std::shared_ptr<CEntry>{}};
        std::atomic<bool> ShuttingDown{false};
    };

    ExecutorTableModel::ExecutorTableModel(const std::size_t Executors)
        : State_(std::make_unique<State>(Executors))
    {
    }

    ExecutorTableModel::~ExecutorTableModel() = default;

    auto ExecutorTableModel::RegisterOnExecutor(
        const std::size_t Index, const SessionInfo &Info,
        const std::shared_ptr<CEntry> &Entry) -> bool
    {
        auto &Table = State_->Tables[Index];
        const auto It = Table.Records.find(Info.Id);
        if (It != Table.Records.end() &&
            !It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return false;
        }
        Table.Records.insert_or_assign(Info.Id, State::Record{Info, Entry});
        Entry->ErrorHookInstalled.store(true, std::memory_order_release);
        auto HookFailures = State_->FailNextHook.load(std::memory_order_acquire);
        while (HookFailures != 0 &&
               !State_->FailNextHook.compare_exchange_weak(
                   HookFailures, HookFailures - 1, std::memory_order_acq_rel,
                   std::memory_order_acquire))
        {
        }
        if (HookFailures != 0)
        {
            Entry->Removed.store(true, std::memory_order_seq_cst);
            Entry->Control.store(std::shared_ptr<CControl>{}, std::memory_order_seq_cst);
            Table.Records.erase(Info.Id);
            State_->FailedEntry.store(Entry, std::memory_order_release);
            return false;
        }
        Entry->MetricsHookInstalled.store(true, std::memory_order_release);
        return true;
    }

    auto ExecutorTableModel::FindOnExecutor(const std::size_t Index,
                                            const std::uint64_t Id)
        -> std::optional<SessionInfo>
    {
        const auto It = State_->Tables[Index].Records.find(Id);
        if (It == State_->Tables[Index].Records.end() ||
            It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return std::nullopt;
        }
        return It->second.Info;
    }

    auto ExecutorTableModel::SizeOnExecutor(const std::size_t Index) -> std::size_t
    {
        std::size_t Count = 0;
        for (const auto &[Id, RecordValue] : State_->Tables[Index].Records)
        {
            (void)Id;
            Count += RecordValue.Entry->Removed.load(std::memory_order_seq_cst) ? 0 : 1;
        }
        return Count;
    }

    auto ExecutorTableModel::SnapshotOnExecutor(const std::size_t Index) -> SnapshotMap
    {
        SnapshotMap Value;
        for (const auto &[Id, RecordValue] : State_->Tables[Index].Records)
        {
            if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
            {
                Value.insert_or_assign(Id, RecordValue.Info);
            }
        }
        return Value;
    }

    auto ExecutorTableModel::CancelOnExecutor(const std::size_t Index,
                                              const std::uint64_t Id) -> bool
    {
        const auto It = State_->Tables[Index].Records.find(Id);
        if (It == State_->Tables[Index].Records.end() ||
            It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return false;
        }
        const auto Control = It->second.Entry->Control.load(std::memory_order_seq_cst);
        if (!Control || It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return false;
        }
        Control->Cancelled.store(true, std::memory_order_release);
        return true;
    }

    auto ExecutorTableModel::ResetOnExecutor(const std::shared_ptr<CEntry> &Entry) -> bool
    {
        auto &Table = State_->Tables[Entry->Shard];
        const auto It = Table.Records.find(Entry->Id);
        if (It == Table.Records.end() || It->second.Entry != Entry)
        {
            return true;
        }
        if (Table.FailNext != 0)
        {
            --Table.FailNext;
            return true;
        }
        Table.Records.erase(It);
        return true;
    }

    auto ExecutorTableModel::TokenActiveOnExecutor(
        const std::size_t Index, const std::shared_ptr<CEntry> &Entry) const -> bool
    {
        const auto It = State_->Tables[Index].Records.find(Entry->Id);
        return It != State_->Tables[Index].Records.end() &&
               It->second.Entry == Entry &&
               !Entry->Removed.load(std::memory_order_seq_cst) &&
               static_cast<bool>(Entry->Control.load(std::memory_order_seq_cst));
    }

    auto ExecutorTableModel::PendingOnExecutor(const std::size_t Index) -> std::size_t
    {
        std::size_t Count = 0;
        for (const auto &[Id, RecordValue] : State_->Tables[Index].Records)
        {
            (void)Id;
            Count += RecordValue.Entry->Removed.load(std::memory_order_seq_cst) ? 1 : 0;
        }
        return Count;
    }

    auto ExecutorTableModel::ShutdownOnExecutor(const std::size_t Index) -> std::size_t
    {
        for (auto &[Id, RecordValue] : State_->Tables[Index].Records)
        {
            (void)Id;
            if (const auto Control = RecordValue.Entry->Control.load(std::memory_order_seq_cst))
            {
                Control->Cancelled.store(true, std::memory_order_release);
            }
        }
        return 0;
    }

    auto CIndex(const ExecutorTableModel::State &StateValue, const std::uint64_t Id)
        -> std::size_t
    {
        return static_cast<std::size_t>(Id % StateValue.Tables.size());
    }

    auto ExecutorTableModel::Register(const SessionInfo &Info) -> Token
    {
        if (State_->ShuttingDown.load(std::memory_order_acquire))
        {
            return {};
        }
        const auto Index = CIndex(*State_, Info.Id);
        auto Entry = std::make_shared<CEntry>();
        Entry->Id = Info.Id;
        Entry->Shard = Index;
        Entry->Hook = State_->Hook;
        Entry->Control.store(std::make_shared<CControl>(), std::memory_order_release);
        const auto Accepted = State_->Executors->Invoke<bool>(
            Index, [this, Index, Info, Entry] { return RegisterOnExecutor(Index, Info, Entry); });
        if (!Accepted)
        {
            return {};
        }
        auto Handle = std::make_shared<TokenHandle>();
        Handle->Id = Info.Id;
        Handle->State = std::make_shared<CTokenState>(Entry);
        Handle->Hooks = MakeCHooks(Entry);
        return Handle;
    }

    auto ExecutorTableModel::Find(const std::uint64_t Id, SessionInfo &Output) -> bool
    {
        const auto Index = CIndex(*State_, Id);
        const auto Result = State_->Executors->Invoke<std::optional<SessionInfo>>(
            Index, [this, Index, Id] { return FindOnExecutor(Index, Id); });
        if (!Result)
        {
            return false;
        }
        Output = *Result;
        return true;
    }

    auto ExecutorTableModel::Size() -> std::size_t
    {
        std::size_t Result = 0;
        for (std::size_t Index = 0; Index < State_->Tables.size(); ++Index)
        {
            Result += State_->Executors->Invoke<std::size_t>(
                Index, [this, Index] { return SizeOnExecutor(Index); });
        }
        return Result;
    }

    auto ExecutorTableModel::Snapshot() -> SnapshotMap
    {
        SnapshotMap Result;
        for (std::size_t Index = 0; Index < State_->Tables.size(); ++Index)
        {
            auto Part = State_->Executors->Invoke<SnapshotMap>(
                Index, [this, Index] { return SnapshotOnExecutor(Index); });
            Result.insert(Part.begin(), Part.end());
        }
        return Result;
    }

    auto ExecutorTableModel::Cancel(const std::uint64_t Id) -> bool
    {
        const auto Index = CIndex(*State_, Id);
        return State_->Executors->Invoke<bool>(
            Index, [this, Index, Id] { return CancelOnExecutor(Index, Id); });
    }

    auto ExecutorTableModel::Reset(const Token &Value) -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<CTokenState>(Value->State);
        if (!TokenValue || !TokenValue->Entry ||
            TokenValue->Entry->Removed.exchange(true, std::memory_order_seq_cst))
        {
            return false;
        }
        TokenValue->Entry->Control.store(std::shared_ptr<CControl>{},
                                         std::memory_order_seq_cst);
        const auto Entry = TokenValue->Entry;
        return State_->Executors->Invoke<bool>(
            Entry->Shard, [this, Entry] { return ResetOnExecutor(Entry); });
    }

    auto ExecutorTableModel::TokenActive(const Token &Value) const -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<CTokenState>(Value->State);
        if (!TokenValue || !TokenValue->Entry)
        {
            return false;
        }
        const auto Index = TokenValue->Entry->Shard;
        return State_->Executors->Invoke<bool>(
            Index, [this, Index, Entry = TokenValue->Entry]
            { return TokenActiveOnExecutor(Index, Entry); });
    }

    auto ExecutorTableModel::FailNextCompaction(const std::uint64_t Id) -> void
    {
        const auto Index = CIndex(*State_, Id);
        (void)State_->Executors->Invoke<std::size_t>(
            Index, [this, Index]
            {
                return ++State_->Tables[Index].FailNext;
            });
    }

    auto ExecutorTableModel::FailNextHookInstallation() -> void
    {
        State_->FailNextHook.fetch_add(1, std::memory_order_release);
    }

    auto ExecutorTableModel::EmitFailedErrorHook() -> bool
    {
        const auto Entry = State_->FailedEntry.exchange({}, std::memory_order_acq_rel);
        if (!Entry)
        {
            return false;
        }
        MakeCHooks(Entry).Error();
        return true;
    }

    auto ExecutorTableModel::SetHookGate(std::shared_ptr<HookGate> Gate) -> void
    {
        State_->Hook->Gate.store(std::move(Gate), std::memory_order_release);
    }

    auto ExecutorTableModel::PendingRemovals() -> std::size_t
    {
        std::size_t Result = 0;
        for (std::size_t Index = 0; Index < State_->Tables.size(); ++Index)
        {
            Result += State_->Executors->Invoke<std::size_t>(
                Index, [this, Index] { return PendingOnExecutor(Index); });
        }
        return Result;
    }

    auto ExecutorTableModel::Shutdown() -> void
    {
        State_->ShuttingDown.store(true, std::memory_order_release);
        for (std::size_t Index = 0; Index < State_->Tables.size(); ++Index)
        {
            (void)State_->Executors->Invoke<std::size_t>(
                Index, [this, Index] { return ShutdownOnExecutor(Index); });
        }
    }

    auto ExecutorTableModel::HookSnapshot() const -> HookCounts
    {
        return HookCounts{State_->Hook->Errors.load(std::memory_order_relaxed),
                          State_->Hook->Metrics.load(std::memory_order_relaxed)};
    }

    auto MakeExecutorTableModel(const std::size_t Executors) -> std::unique_ptr<IModel>
    {
        return std::make_unique<ExecutorTableModel>(Executors);
    }

    /** @brief 注入每个部分启动位置的失败，严格核对已启动线程全部退出并 join。 */
    auto ValidateExecutorStartupRollback() -> void
    {
        for (std::size_t Failure = 0; Failure < 4; ++Failure)
        {
            ExecutorStartupProbe Probe;
            Probe.FailBefore = Failure;
            bool Rejected = false;
            try { ExecutorGroup Group(4, &Probe); }
            catch (const std::system_error &Error)
            {
                Rejected = Error.code() == std::make_error_code(std::errc::resource_unavailable_try_again);
            }
            if (!Rejected || Probe.Started.load() != Failure || Probe.Exited.load() != Failure ||
                Probe.Joined != Failure)
                throw std::runtime_error("executor startup rollback contract failed");
        }
        ExecutorStartupProbe Probe;
        {
            ExecutorGroup Group(2, &Probe);
            if (Group.Invoke<int>(0, [] { return 11; }) != 11 ||
                Group.Invoke<int>(1, [] { return 13; }) != 13)
                throw std::runtime_error("executor command delivery contract failed");
        }
        if (Probe.Started.load() != 2 || Probe.Exited.load() != 2 || Probe.Joined != 2)
            throw std::runtime_error("executor normal shutdown contract failed");
    }

    /** @brief 核对 executor 模型在并发成功注册后保留失败 hook，并严格一次消费。 */
    auto ValidateExecutorTableFailureConcurrency() -> void
    {
        auto Model = MakeExecutorTableModel(ConcurrentRegistryCount);
        Model->FailNextHookInstallation();
        const auto Failed = Model->Register(MakeConcurrentInfo(2001, 1));
        RequireConcurrentContract(!Failed && Model->Size() == 0 &&
                                      Model->PendingRemovals() == 0,
                                  "executor failure entry was published");

        const std::array<SessionInfo, ConcurrentRegistryCount> Infos{
            MakeConcurrentInfo(2101, 11), MakeConcurrentInfo(2102, 12),
            MakeConcurrentInfo(2103, 13), MakeConcurrentInfo(2104, 14)};
        auto Tokens = RunConcurrentRegistrations(*Model, Infos);
        std::array<std::weak_ptr<TokenHandle>, ConcurrentRegistryCount> WeakTokens;
        for (std::size_t Index = 0; Index < ConcurrentRegistryCount; ++Index)
        {
            RequireConcurrentContract(
                Tokens[Index] && Tokens[Index]->Id == Infos[Index].Id &&
                    Model->TokenActive(Tokens[Index]),
                "executor concurrent registration did not return active token");
            WeakTokens[Index] = Tokens[Index];
        }

        const auto Snapshot = Model->Snapshot();
        RequireConcurrentContract(Snapshot.size() == ConcurrentRegistryCount &&
                                      Model->Size() == ConcurrentRegistryCount &&
                                      Model->PendingRemovals() == 0,
                                  "executor concurrent registration state differs");
        for (const auto &Info : Infos)
        {
            const auto It = Snapshot.find(Info.Id);
            RequireConcurrentContract(It != Snapshot.end() && SameConcurrentInfo(It->second, Info),
                                      "executor concurrent snapshot differs");
        }

        const auto BeforeHooks = Model->HookSnapshot();
        const auto EmitResults = RunConcurrentFailedHookEmits(*Model);
        std::size_t Emitted = 0;
        for (const auto Result : EmitResults)
        {
            Emitted += Result ? 1U : 0U;
        }
        RequireConcurrentContract(Emitted == 1 && !Model->EmitFailedErrorHook(),
                                  "executor failed hook was not consumed exactly once");
        const auto AfterHooks = Model->HookSnapshot();
        RequireConcurrentContract(AfterHooks.Errors == BeforeHooks.Errors &&
                                      AfterHooks.Metrics == BeforeHooks.Metrics,
                                  "executor failed hook changed hook counters");

        for (auto &TokenValue : Tokens)
        {
            RequireConcurrentContract(Model->Reset(TokenValue),
                                      "executor successful token reset failed");
            RequireConcurrentContract(!Model->TokenActive(TokenValue),
                                      "executor reset token remains active");
        }
        RequireConcurrentContract(Model->Snapshot().empty() && Model->Size() == 0 &&
                                      Model->PendingRemovals() == 0,
                                  "executor final state retained entries");
        for (auto &TokenValue : Tokens)
        {
            TokenValue.reset();
        }
        for (const auto &WeakToken : WeakTokens)
        {
            RequireConcurrentContract(WeakToken.expired(),
                                      "executor token owner was not released");
        }
        Model->Shutdown();
    }

} // namespace Preview::Runtime::Perf
