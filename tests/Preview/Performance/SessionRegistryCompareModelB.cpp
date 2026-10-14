/**
 * @file SessionRegistryCompareModelB.cpp
 * @brief 分片 COW 注册表 B 模型。
 */

#include "SessionRegistryCompareModels.hpp"

#include <array>
#include <atomic>
#include <exception>
#include <functional>
#include <latch>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <stdexcept>
#include <thread>
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

        struct BControl final
        {
            std::atomic<bool> Cancelled{false};
        };

        struct BEntry final
        {
            BEntry(std::shared_ptr<HookState> HookValue,
                   std::shared_ptr<BControl> ControlValue)
                : Hook(std::move(HookValue)), Control(std::move(ControlValue))
            {
            }

            std::atomic<bool> Removed{false};
            std::atomic<std::shared_ptr<BControl>> Control;
            std::atomic<bool> ErrorHookInstalled{false};
            std::atomic<bool> MetricsHookInstalled{false};
            std::shared_ptr<HookState> Hook;
        };

        struct BTokenState final : TokenState
        {
            BTokenState(const std::uint64_t IdValue, std::shared_ptr<BEntry> EntryValue)
                : Id(IdValue), Entry(std::move(EntryValue))
            {
            }

            std::uint64_t Id{0};
            std::shared_ptr<BEntry> Entry;
        };

        auto EmitBErrorHook(const std::shared_ptr<BEntry> &Entry,
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

        auto EmitBMetricsHook(const std::shared_ptr<BEntry> &Entry,
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

        auto MakeBHooks(const std::shared_ptr<BEntry> &Entry) -> HookPair
        {
            const auto Hook = Entry->Hook;
            HookPair Result;
            Result.Error = [Entry, Hook] { EmitBErrorHook(Entry, Hook); };
            Result.Metrics = [Entry, Hook] { EmitBMetricsHook(Entry, Hook); };
            return Result;
        }

        auto ConsumeFailure(std::atomic<std::size_t> &Failures) -> bool
        {
            auto Current = Failures.load(std::memory_order_acquire);
            while (Current != 0)
            {
                if (Failures.compare_exchange_weak(Current, Current - 1,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

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

    class ShardedCowModel final : public IModel
    {
    public:
        struct State;

        explicit ShardedCowModel(std::size_t Shards);
        ~ShardedCowModel() override;

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
        std::unique_ptr<State> State_;
    };

    struct ShardedCowModel::State final
    {
        struct Record final
        {
            SessionInfo Info;
            std::shared_ptr<BEntry> Entry;
        };

        using RecordMap = std::map<std::uint64_t, Record>;

        struct Shard final
        {
            std::atomic<std::shared_ptr<const RecordMap>> Records{
                std::make_shared<const RecordMap>()};
            std::atomic<std::size_t> FailNext{0};
        };

        explicit State(const std::size_t Count) : Hook(std::make_shared<HookState>())
        {
            Shards.reserve(Count);
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                Shards.push_back(std::make_unique<Shard>());
            }
        }

        std::vector<std::unique_ptr<Shard>> Shards;
        std::shared_ptr<HookState> Hook;
        std::atomic<std::size_t> FailNextHook{0};
        std::atomic<std::shared_ptr<BEntry>> FailedEntry{std::shared_ptr<BEntry>{}};
        std::atomic<bool> ShuttingDown{false};
    };

    ShardedCowModel::ShardedCowModel(const std::size_t Shards)
        : State_(std::make_unique<State>(Shards))
    {
        if (Shards == 0)
        {
            throw std::invalid_argument("sharded model requires a shard");
        }
    }

    ShardedCowModel::~ShardedCowModel() = default;

    auto ShardIndex(const ShardedCowModel::State &StateValue, const std::uint64_t Id)
        -> std::size_t
    {
        return static_cast<std::size_t>(Id % StateValue.Shards.size());
    }

    auto CopyActive(const ShardedCowModel::State::RecordMap &Current)
        -> std::shared_ptr<ShardedCowModel::State::RecordMap>
    {
        auto Result = std::make_shared<ShardedCowModel::State::RecordMap>();
        for (const auto &[Id, RecordValue] : Current)
        {
            if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
            {
                Result->emplace(Id, RecordValue);
            }
        }
        return Result;
    }

    auto Compact(ShardedCowModel::State &StateValue, const std::size_t Index) noexcept -> void;

    auto ShardedCowModel::Register(const SessionInfo &Info) -> Token
    {
        if (State_->ShuttingDown.load(std::memory_order_acquire))
        {
            return {};
        }
        const auto Index = ShardIndex(*State_, Info.Id);
        auto Entry = std::make_shared<BEntry>(State_->Hook, std::make_shared<BControl>());
        while (true)
        {
            auto Current = State_->Shards[Index]->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Info.Id);
            if (It != Current->end() &&
                !It->second.Entry->Removed.load(std::memory_order_seq_cst))
            {
                return {};
            }
            auto Next = CopyActive(*Current);
            Next->insert_or_assign(Info.Id,
                                   ShardedCowModel::State::Record{Info, Entry});
            std::shared_ptr<const ShardedCowModel::State::RecordMap> Published(
                std::move(Next));
            if (State_->Shards[Index]->Records.compare_exchange_weak(
                    Current, Published, std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                Entry->ErrorHookInstalled.store(true, std::memory_order_release);
                if (ConsumeFailure(State_->FailNextHook))
                {
                    Entry->Removed.store(true, std::memory_order_seq_cst);
                    Entry->Control.store(std::shared_ptr<BControl>{},
                                         std::memory_order_seq_cst);
                    Compact(*State_, Index);
                    State_->FailedEntry.store(Entry, std::memory_order_release);
                    return {};
                }
                Entry->MetricsHookInstalled.store(true, std::memory_order_release);
                auto Handle = std::make_shared<TokenHandle>();
                Handle->Id = Info.Id;
                Handle->State = std::make_shared<BTokenState>(Info.Id, Entry);
                Handle->Hooks = MakeBHooks(Entry);
                return Handle;
            }
        }
    }

    auto ShardedCowModel::Find(const std::uint64_t Id, SessionInfo &Output) -> bool
    {
        const auto Current = State_->Shards[ShardIndex(*State_, Id)]->Records.load(
            std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return false;
        }
        Output = It->second.Info;
        return true;
    }

    auto ShardedCowModel::Size() -> std::size_t
    {
        std::size_t Result = 0;
        for (const auto &Shard : State_->Shards)
        {
            const auto Current = Shard->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                Result += RecordValue.Entry->Removed.load(std::memory_order_seq_cst) ? 0 : 1;
            }
        }
        return Result;
    }

    auto ShardedCowModel::Snapshot() -> SnapshotMap
    {
        SnapshotMap Result;
        for (const auto &Shard : State_->Shards)
        {
            const auto Current = Shard->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    Result.insert_or_assign(Id, RecordValue.Info);
                }
            }
        }
        return Result;
    }

    auto ShardedCowModel::Cancel(const std::uint64_t Id) -> bool
    {
        const auto Current = State_->Shards[ShardIndex(*State_, Id)]->Records.load(
            std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
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

    auto Compact(ShardedCowModel::State &StateValue, const std::size_t Index) noexcept -> void
    {
        try
        {
            while (true)
            {
                auto Current = StateValue.Shards[Index]->Records.load(std::memory_order_acquire);
                bool HasRemoved = false;
                for (const auto &[Id, RecordValue] : *Current)
                {
                    (void)Id;
                    HasRemoved = HasRemoved ||
                                 RecordValue.Entry->Removed.load(std::memory_order_seq_cst);
                }
                if (!HasRemoved)
                {
                    return;
                }
                auto Failures = StateValue.Shards[Index]->FailNext.load(std::memory_order_acquire);
                while (Failures != 0)
                {
                    if (StateValue.Shards[Index]->FailNext.compare_exchange_weak(
                            Failures, Failures - 1, std::memory_order_acq_rel,
                            std::memory_order_acquire))
                    {
                        throw std::bad_alloc{};
                    }
                }
                auto Next = CopyActive(*Current);
                std::shared_ptr<const ShardedCowModel::State::RecordMap> Published(
                    std::move(Next));
                if (StateValue.Shards[Index]->Records.compare_exchange_weak(
                        Current, Published, std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    continue;
                }
            }
        }
        catch (...)
        {
        }
    }

    auto ShardedCowModel::Reset(const Token &Value) -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<BTokenState>(Value->State);
        if (!TokenValue || !TokenValue->Entry ||
            TokenValue->Entry->Removed.exchange(true, std::memory_order_seq_cst))
        {
            return false;
        }
        TokenValue->Entry->Control.store(std::shared_ptr<BControl>{},
                                         std::memory_order_seq_cst);
        Compact(*State_, ShardIndex(*State_, TokenValue->Id));
        return true;
    }

    auto ShardedCowModel::TokenActive(const Token &Value) const -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<BTokenState>(Value->State);
        return TokenValue && TokenValue->Entry &&
               !TokenValue->Entry->Removed.load(std::memory_order_seq_cst) &&
               static_cast<bool>(TokenValue->Entry->Control.load(std::memory_order_seq_cst));
    }

    auto ShardedCowModel::FailNextCompaction(const std::uint64_t Id) -> void
    {
        State_->Shards[ShardIndex(*State_, Id)]->FailNext.fetch_add(1,
                                                                    std::memory_order_release);
    }

    auto ShardedCowModel::FailNextHookInstallation() -> void
    {
        State_->FailNextHook.fetch_add(1, std::memory_order_release);
    }

    auto ShardedCowModel::EmitFailedErrorHook() -> bool
    {
        const auto Entry = State_->FailedEntry.exchange({}, std::memory_order_acq_rel);
        if (!Entry)
        {
            return false;
        }
        MakeBHooks(Entry).Error();
        return true;
    }

    auto ShardedCowModel::SetHookGate(std::shared_ptr<HookGate> Gate) -> void
    {
        State_->Hook->Gate.store(std::move(Gate), std::memory_order_release);
    }

    auto ShardedCowModel::PendingRemovals() -> std::size_t
    {
        std::size_t Result = 0;
        for (const auto &Shard : State_->Shards)
        {
            const auto Current = Shard->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                Result += RecordValue.Entry->Removed.load(std::memory_order_seq_cst) ? 1 : 0;
            }
        }
        return Result;
    }

    auto ShardedCowModel::Shutdown() -> void
    {
        State_->ShuttingDown.store(true, std::memory_order_release);
        for (const auto &Shard : State_->Shards)
        {
            const auto Current = Shard->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (const auto Control =
                        RecordValue.Entry->Control.load(std::memory_order_seq_cst))
                {
                    Control->Cancelled.store(true, std::memory_order_release);
                }
            }
        }
    }

    auto ShardedCowModel::HookSnapshot() const -> HookCounts
    {
        return HookCounts{State_->Hook->Errors.load(std::memory_order_relaxed),
                          State_->Hook->Metrics.load(std::memory_order_relaxed)};
    }

    auto MakeShardedCowModel(const std::size_t Shards) -> std::unique_ptr<IModel>
    {
        return std::make_unique<ShardedCowModel>(Shards);
    }

    /** @brief 核对分片模型在并发成功注册后保留失败 hook，并严格一次消费。 */
    auto ValidateShardedCowFailureConcurrency() -> void
    {
        auto Model = MakeShardedCowModel(ConcurrentRegistryCount);
        Model->FailNextHookInstallation();
        const auto Failed = Model->Register(MakeConcurrentInfo(1001, 1));
        RequireConcurrentContract(!Failed && Model->Size() == 0 &&
                                      Model->PendingRemovals() == 0,
                                  "sharded failure entry was published");

        const std::array<SessionInfo, ConcurrentRegistryCount> Infos{
            MakeConcurrentInfo(1101, 11), MakeConcurrentInfo(1102, 12),
            MakeConcurrentInfo(1103, 13), MakeConcurrentInfo(1104, 14)};
        auto Tokens = RunConcurrentRegistrations(*Model, Infos);
        std::array<std::weak_ptr<TokenHandle>, ConcurrentRegistryCount> WeakTokens;
        for (std::size_t Index = 0; Index < ConcurrentRegistryCount; ++Index)
        {
            RequireConcurrentContract(
                Tokens[Index] && Tokens[Index]->Id == Infos[Index].Id &&
                    Model->TokenActive(Tokens[Index]),
                "sharded concurrent registration did not return active token");
            WeakTokens[Index] = Tokens[Index];
        }

        const auto Snapshot = Model->Snapshot();
        RequireConcurrentContract(Snapshot.size() == ConcurrentRegistryCount &&
                                      Model->Size() == ConcurrentRegistryCount &&
                                      Model->PendingRemovals() == 0,
                                  "sharded concurrent registration state differs");
        for (const auto &Info : Infos)
        {
            const auto It = Snapshot.find(Info.Id);
            RequireConcurrentContract(It != Snapshot.end() && SameConcurrentInfo(It->second, Info),
                                      "sharded concurrent snapshot differs");
        }

        const auto BeforeHooks = Model->HookSnapshot();
        const auto EmitResults = RunConcurrentFailedHookEmits(*Model);
        std::size_t Emitted = 0;
        for (const auto Result : EmitResults)
        {
            Emitted += Result ? 1U : 0U;
        }
        RequireConcurrentContract(Emitted == 1 && !Model->EmitFailedErrorHook(),
                                  "sharded failed hook was not consumed exactly once");
        const auto AfterHooks = Model->HookSnapshot();
        RequireConcurrentContract(AfterHooks.Errors == BeforeHooks.Errors &&
                                      AfterHooks.Metrics == BeforeHooks.Metrics,
                                  "sharded failed hook changed hook counters");

        for (auto &TokenValue : Tokens)
        {
            RequireConcurrentContract(Model->Reset(TokenValue),
                                      "sharded successful token reset failed");
            RequireConcurrentContract(!Model->TokenActive(TokenValue),
                                      "sharded reset token remains active");
        }
        RequireConcurrentContract(Model->Snapshot().empty() && Model->Size() == 0 &&
                                      Model->PendingRemovals() == 0,
                                  "sharded final state retained entries");
        for (auto &TokenValue : Tokens)
        {
            TokenValue.reset();
        }
        for (const auto &WeakToken : WeakTokens)
        {
            RequireConcurrentContract(WeakToken.expired(),
                                      "sharded token owner was not released");
        }
        Model->Shutdown();
    }

} // namespace Preview::Runtime::Perf
