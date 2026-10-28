/**
 * @file ModelATest.cpp
 * @brief 当前 SessionRegistry 的 A 模型适配。
 */

#include "CompareModels.hpp"

#include <Prism/Runtime/Session/Control.hpp>

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <utility>

namespace Prism::Runtime
{

    class SessionRegistryTestAccess final
    {
    public:
        static auto CaptureError(SessionRegistry &Registry, std::uint64_t Id)
            -> std::function<void()>;
        static auto CaptureMetrics(SessionRegistry &Registry, std::uint64_t Id)
            -> std::function<void()>;
        static auto FailNextRemovalCompaction(SessionRegistry &Registry) -> void;
        static auto FailNextMetricsHookInstallation(SessionRegistry &Registry) -> void;
    };

    auto SessionRegistryTestAccess::CaptureError(SessionRegistry &Registry,
                                                 const std::uint64_t Id)
        -> std::function<void()>
    {
        const auto State = Registry.State_;
        const auto Current = State->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end())
        {
            return {};
        }
        const auto Entry = It->second.Entry;
        return [State, Entry, Id]
        {
            const Prism::Runtime::Detail::SessionRegistryHookContext Context{State, Entry, Id};
            Prism::Runtime::Detail::SessionRegistryStorage::DispatchError(
                Context, Prism::Fault::Code::IoError, {});
        };
    }

    auto SessionRegistryTestAccess::CaptureMetrics(SessionRegistry &Registry,
                                                   const std::uint64_t Id)
        -> std::function<void()>
    {
        const auto State = Registry.State_;
        const auto Current = State->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end())
        {
            return {};
        }
        const auto Entry = It->second.Entry;
        return [State, Entry, Id]
        {
            const Prism::Runtime::Detail::SessionRegistryHookContext Context{State, Entry, Id};
            Prism::Runtime::Detail::SessionRegistryStorage::DispatchMetrics(Context, SessionMetrics{});
        };
    }

    auto SessionRegistryTestAccess::FailNextRemovalCompaction(SessionRegistry &Registry) -> void
    {
        Registry.State_->FailNextRemovalCompaction.store(1, std::memory_order_release);
    }

    auto SessionRegistryTestAccess::FailNextMetricsHookInstallation(
        SessionRegistry &Registry) -> void
    {
        Registry.State_->FailNextMetricsHookInstallation.store(1, std::memory_order_release);
    }

} // namespace Prism::Runtime

namespace Prism::Runtime::Perf
{

    namespace
    {

        struct HookState final
        {
            std::atomic<std::uint64_t> Errors{0};
            std::atomic<std::uint64_t> Metrics{0};
            std::atomic<std::shared_ptr<HookGate>> Gate{std::shared_ptr<HookGate>{}};
        };

        struct ATokenState final : TokenState
        {
            explicit ATokenState(SessionRegistry::Registration RegistrationValue)
                : Registration(std::move(RegistrationValue))
            {
            }

            SessionRegistry::Registration Registration;
        };

    } // namespace

    class CurrentCowModel final : public IModel
    {
    public:
        explicit CurrentCowModel(std::size_t Executors = 1);
        ~CurrentCowModel() override;

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
        struct State;
        std::unique_ptr<State> State_;
    };

    struct CurrentCowModel::State final
    {
        boost::asio::io_context Io;
        SessionRegistry Registry;
        std::shared_ptr<SessionControl> FailedControl;
        std::shared_ptr<HookState> Hook{std::make_shared<HookState>()};
        std::atomic<bool> HookFailureArmed{false};
    };

    CurrentCowModel::CurrentCowModel(const std::size_t Executors)
        : State_(std::make_unique<State>())
    {
        (void)Executors;
        State_->Registry.SetErrorHook(
            [Hook = State_->Hook](std::uint64_t, Prism::Fault::Code, std::exception_ptr)
            {
                if (const auto Gate = Hook->Gate.load(std::memory_order_acquire))
                {
                    Gate->PauseAfterCheck();
                }
                Hook->Errors.fetch_add(1, std::memory_order_relaxed);
            });
        State_->Registry.SetMetricsHook(
            [Hook = State_->Hook](std::uint64_t, const SessionMetrics &)
            {
                if (const auto Gate = Hook->Gate.load(std::memory_order_acquire))
                {
                    Gate->PauseAfterCheck();
                }
                Hook->Metrics.fetch_add(1, std::memory_order_relaxed);
            });
    }

    CurrentCowModel::~CurrentCowModel() = default;

    auto CurrentCowModel::Register(const SessionInfo &Info) -> Token
    {
        const auto HookFailure = State_->HookFailureArmed.exchange(
            false, std::memory_order_acq_rel);
        auto Control = HookFailure
                           ? std::make_shared<SessionControl>(State_->Io.get_executor())
                           : std::make_shared<SessionControl>();
        SessionRegistry::Registration Registration;
        try
        {
            Registration = State_->Registry.Register(Info, Control);
        }
        catch (const std::bad_alloc &)
        {
            if (HookFailure)
            {
                State_->FailedControl = std::move(Control);
            }
            return {};
        }
        if (!Registration)
        {
            return {};
        }
        auto Hooks = HookPair{
            SessionRegistryTestAccess::CaptureError(State_->Registry, Info.Id),
            SessionRegistryTestAccess::CaptureMetrics(State_->Registry, Info.Id)};
        auto Handle = std::make_shared<TokenHandle>();
        Handle->Id = Info.Id;
        Handle->State = std::make_shared<ATokenState>(std::move(Registration));
        Handle->Hooks = std::move(Hooks);
        return Handle;
    }

    auto CurrentCowModel::Find(const std::uint64_t Id, SessionInfo &Output) -> bool
    {
        return State_->Registry.Find(Id, Output);
    }

    auto CurrentCowModel::Size() -> std::size_t
    {
        return State_->Registry.Size();
    }

    auto CurrentCowModel::Snapshot() -> SnapshotMap
    {
        return *State_->Registry.Snapshot();
    }

    auto CurrentCowModel::Cancel(const std::uint64_t Id) -> bool
    {
        return State_->Registry.Cancel(Id);
    }

    auto CurrentCowModel::Reset(const Token &Value) -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<ATokenState>(Value->State);
        if (!TokenValue || !TokenValue->Registration)
        {
            return false;
        }
        TokenValue->Registration.Reset();
        return true;
    }

    auto CurrentCowModel::TokenActive(const Token &Value) const -> bool
    {
        if (!Value || !Value->State)
        {
            return false;
        }
        const auto TokenValue = std::dynamic_pointer_cast<ATokenState>(Value->State);
        return TokenValue && static_cast<bool>(TokenValue->Registration);
    }

    auto CurrentCowModel::FailNextCompaction(const std::uint64_t) -> void
    {
        SessionRegistryTestAccess::FailNextRemovalCompaction(State_->Registry);
    }

    auto CurrentCowModel::FailNextHookInstallation() -> void
    {
        State_->FailedControl.reset();
        State_->HookFailureArmed.store(true, std::memory_order_release);
        SessionRegistryTestAccess::FailNextMetricsHookInstallation(State_->Registry);
    }

    auto CurrentCowModel::EmitFailedErrorHook() -> bool
    {
        if (!State_->FailedControl)
        {
            return false;
        }
        State_->Io.restart();
        State_->FailedControl->ReportError(Prism::Fault::Code::IoError);
        State_->Io.run();
        State_->FailedControl.reset();
        return true;
    }

    auto CurrentCowModel::SetHookGate(std::shared_ptr<HookGate> Gate) -> void
    {
        State_->Hook->Gate.store(std::move(Gate), std::memory_order_release);
    }

    auto CurrentCowModel::PendingRemovals() -> std::size_t
    {
        return State_->Registry.PendingRemovals();
    }

    auto CurrentCowModel::Shutdown() -> void
    {
        State_->Registry.BeginShutdown();
    }

    auto CurrentCowModel::HookSnapshot() const -> HookCounts
    {
        return HookCounts{State_->Hook->Errors.load(std::memory_order_relaxed),
                          State_->Hook->Metrics.load(std::memory_order_relaxed)};
    }

    auto MakeCurrentCowModel(const std::size_t Executors) -> std::unique_ptr<IModel>
    {
        return std::make_unique<CurrentCowModel>(Executors);
    }

} // namespace Prism::Runtime::Perf
