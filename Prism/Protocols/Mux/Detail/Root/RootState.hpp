/** @file RootState.hpp @brief generic mux 根持真实 lease、子流与独立 frame/child scopes。 */
#pragma once
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Protocols/Mux/RootOptions.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <exception>
#include <unordered_map>
#include <optional>
#include <functional>
#include <string_view>
#include <cstdint>
#include <vector>
#include <expected>
#include <system_error>
#include <utility>

namespace Prism::Mux::Detail
{
    namespace Net = boost::asio;
    class RootRetirementOwner
    {
    public:
        virtual ~RootRetirementOwner() = default;
        virtual auto Retire(Prism::Fault::Failure Failure) noexcept -> void = 0;
    };
    class RootSession;
    /** @brief RootSession 冷创建时预留、Register 时转交到 registry 的强 owner 节点。 */
    struct RootRegistryNode final
    {
        std::shared_ptr<RootSession> Owner;
        std::atomic<std::shared_ptr<RootRegistryNode>> Next;
        std::atomic_bool Registered{false};
    };
    struct RootState;
    /**
     * @brief RootState 对当前类型化 mux 引擎的唯一关闭持有者。
     * @details 具体 owner 以 shared_ptr 持有 Server。RequestClose 只启动协议拆除与任务取消，
     *          不等待 Run 或 stream completion；RootSession::Run 负责等待 Children 和 Loops 的真实 drain。
     *          该操作没有半关闭，也不取代具体 Server 的最终关闭职责。
     * @return void。停止失败由后续 task drain 的真实结果表示，不伪造任务完成。
     * @note 调用发生在 RootState executor；具体 Server 可在其协议 executor 上派发关闭。
     */
    class RootEngineControl
    {
    public:
        virtual ~RootEngineControl() = default;
        [[nodiscard]] virtual auto RequestClose() noexcept
            -> std::expected<void, Prism::Fault::Failure> = 0;
        [[nodiscard]] virtual auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;
    };
    struct ChildState final : std::enable_shared_from_this<ChildState>
    {
        std::shared_ptr<RootState> Root;
        Prism::SharedTransmission Inbound, Outbound;
        Prism::Account::StreamLease Lease;
        std::optional<std::size_t> RetirementSlot;
        Prism::Lifecycle::TaskIdentity Identity;
        Prism::Network::Target Target;
        Net::cancellation_signal Cancellation;
        std::atomic_bool NormalCloseCancellation{false};
        std::function<void()> Reject;
        std::function<std::expected<void, Prism::Fault::Failure>()> Reset;
        std::function<Net::awaitable<std::expected<void, Prism::Fault::Failure>>()> Finish;
        std::shared_ptr<Prism::Fault::FailureState> ControlFailure;
        bool Admitted{true};
        auto Cancel() noexcept -> void;
    };
    struct RootState final : std::enable_shared_from_this<RootState>
    {
        enum class RunPhase : std::uint8_t
        {
            AcceptingCancellation,
            CancellationRequested,
            OutcomePublished,
            ResourcesRetired
        };

        struct ChildRetirementSlot final
        {
            std::shared_ptr<ChildState> Retained;
            std::optional<std::size_t> NextFree;
            bool Reserved{false};
        };
        RootState(Prism::SharedTransmission Transport, RootOptions Value)
            : Inbound(std::move(Transport)), Options(std::move(Value)),
              ChildRetirementSlots(Options.MaxStreams),
              Executor(Net::make_strand(Inbound->Executor())),
              Children(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor)),
              Loops(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor)),
              Lifetime(Loops->Reclaimer())
        {
            for (std::size_t Index = 0; Index < ChildRetirementSlots.size(); ++Index)
            {
                if (Index + 1U < ChildRetirementSlots.size())
                    ChildRetirementSlots[Index].NextFree = Index + 1U;
            }
            if (!ChildRetirementSlots.empty()) FreeChildRetirementSlot = 0U;
        }
        [[nodiscard]] auto ReserveChildRetirementSlot() noexcept
            -> std::optional<std::size_t>
        {
            if (!FreeChildRetirementSlot) return {};
            const auto Index = *FreeChildRetirementSlot;
            FreeChildRetirementSlot = ChildRetirementSlots[Index].NextFree;
            ChildRetirementSlots[Index].NextFree.reset();
            ChildRetirementSlots[Index].Reserved = true;
            return Index;
        }
        auto ReleaseChildRetirementSlot(std::size_t Index) noexcept -> void
        {
            if (Index >= ChildRetirementSlots.size()) return;
            auto &Slot = ChildRetirementSlots[Index];
            if (!Slot.Reserved) return;
            Slot.Retained.reset();
            Slot.Reserved = false;
            Slot.NextFree = FreeChildRetirementSlot;
            FreeChildRetirementSlot = Index;
        }
        [[nodiscard]] auto HasOutstandingChildRetirement() const noexcept -> bool
        {
            for (const auto &Slot : ChildRetirementSlots)
                if (Slot.Reserved) return true;
            return false;
        }
        auto RetainChildUntilRootRetired(std::shared_ptr<ChildState> Child) noexcept -> void
        {
            if (!Child || !Child->RetirementSlot ||
                *Child->RetirementSlot >= ChildRetirementSlots.size()) return;
            const auto Index = *Child->RetirementSlot;
            auto &Slot = ChildRetirementSlots[Index];
            if (!Slot.Reserved || Slot.Retained) return;
            Child->RetirementSlot.reset();
            Child->Root.reset();
            Slot.Retained = std::move(Child);
        }
        /** @brief 仅在取消阶段设置或补齐终态；结果发布或退休后不覆盖。 */
        auto RequestCancel() noexcept -> void
        {
            auto Expected = RunPhase::AcceptingCancellation;
            if (!Phase.compare_exchange_strong(Expected, RunPhase::CancellationRequested,
                    std::memory_order_acq_rel) &&
                Expected != RunPhase::CancellationRequested) return;
            ExitStatus.store(Prism::Fault::Code::Canceled);
            if (Started.load(std::memory_order_acquire))
            {
                RecordTerminalFailure(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            Stop();
        }
        [[nodiscard]] auto IsClosingNormally() const noexcept -> bool
        {
            const auto Current = Phase.load(std::memory_order_acquire);
            return Stopping.load(std::memory_order_acquire) &&
                Current != RunPhase::CancellationRequested &&
                Current != RunPhase::ResourcesRetired;
        }
        [[nodiscard]] auto IsExpectedRetirementCancellation(
            const Prism::Fault::Failure &Failure, bool Retired) const noexcept -> bool
        {
            return IsClosingNormally() && Retired &&
                Failure.Code == Prism::Fault::Code::Canceled;
        }
        /** @brief 原子发布 Run 结果；返回 true 表示此前取消请求已胜出。 */
        [[nodiscard]] auto PublishRunOutcome() noexcept -> bool
        {
            auto Expected = RunPhase::AcceptingCancellation;
            if (Phase.compare_exchange_strong(Expected, RunPhase::OutcomePublished,
                std::memory_order_acq_rel)) return false;
            return Expected == RunPhase::CancellationRequested;
        }
        /** @brief 保存根 Run 子任务最先返回的 typed 首因及 Native。 */
        auto RecordTerminalFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            const auto Stored = TerminalFailure.TrySet(Failure);
            (void)Stored;
        }
        [[nodiscard]] static auto FailureFromException(std::exception_ptr Failure) noexcept
            -> Prism::Fault::Failure
        {
            try
            {
                if (Failure) std::rethrow_exception(Failure);
            }
            catch (const boost::system::system_error &Error)
            {
                return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                return Prism::Fault::FromNative(Error.code());
            }
            catch (...) { return {Prism::Fault::Code::IoError}; }
            return {Prism::Fault::Code::IoError};
        }
        [[nodiscard]] auto DrainTaskScope(
            const std::shared_ptr<Prism::Lifecycle::TaskRegistry> &Scope)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::expected<void, Prism::Fault::Failure> Drained;
            try { Drained = co_await Scope->Drain(); }
            catch (...) { Drained = std::unexpected(FailureFromException(std::current_exception())); }
            const auto Stats = Scope->Stats();
            const bool PhysicallyRetired = Stats.Active == 0U && !Stats.DrainBlocked;
            const bool ExpectedCancellation = IsClosingNormally() && !Drained &&
                Drained.error().Code == Prism::Fault::Code::Canceled && PhysicallyRetired;
            if (!Drained && !ExpectedCancellation)
                RecordTerminalFailure(Drained.error());
            if (PhysicallyRetired)
                co_return std::expected<void, Prism::Fault::Failure>{};
            if (!Drained) co_return std::unexpected(Drained.error());
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        auto ReleaseResources() -> bool
        {
            if (ResourcesRetired.load()) return true;
            if (Lifetime.Active() != 0U || Lifetime.IsBlocked() ||
                HasOutstandingChildRetirement()) return false;
            Phase.store(RunPhase::ResourcesRetired, std::memory_order_release);
            Admission = {};
            Lease.Release();
            ParentStreamLease.Release();
            for (auto &Slot : ChildRetirementSlots)
            {
                if (Slot.Retained && StreamCatalogOwner && StreamCatalogOwner->IsAvailable())
                {
                    const Prism::Contract::Ingress::StreamIdentity Identity{
                        Metadata.TaskIdentity.SessionId,
                        Metadata.TaskIdentity.WorkerId,
                        Metadata.TaskIdentity.Generation,
                        Slot.Retained->Identity.StreamId};
                    if (!StreamCatalogOwner->Retire(Identity)) StreamCatalogOwner->Disable();
                }
                if (Slot.Retained) Slot.Retained->Lease.Release();
                Slot.Retained.reset();
                Slot.Reserved = false;
            }
            Options.Services = {};
            Options.Admission = {};
            Options.GenerationUseState.reset();
            Options.Observe = {};
            StreamCatalogOwner.reset();
            StreamResetOwners.clear();
            EngineControl.reset();
            Inbound.reset();
            GenerationLease = {};
            ResourcesRetired.store(true, std::memory_order_release);
            ResourcesReadyForFinalization.store(false, std::memory_order_release);
            if (const auto Owner = RetirementOwner.lock())
                Owner->Retire(TerminalFailure.Load());
            return true;
        }
        auto Stop() noexcept -> void
        {
            if (Stopping.exchange(true)) return;
            auto Self = shared_from_this();
            try { Net::dispatch(Executor, [Self] { Self->StopOnExecutor(); }); }
            catch (const boost::system::system_error &Error)
            {
                RecordTerminalFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            { RecordTerminalFailure(Prism::Fault::FromNative(Error.code())); }
            catch (...) { RecordTerminalFailure(Prism::Fault::Failure{Prism::Fault::Code::IoError}); }
        }
        auto StopOnExecutor() noexcept -> void
        {
            Stopping.store(true);
            const bool H2Closing = EngineControl && SelectedWire == Mode::H2Mux;
            if (H2Closing)
            {
                const auto Closed = EngineControl->RequestClose();
                if (!Closed) RecordTerminalFailure(Closed.error());
            }
            (void)Children->Cancel();
            if (EngineControl && !H2Closing)
            {
                const auto Closed = EngineControl->RequestClose();
                if (!Closed) RecordTerminalFailure(Closed.error());
            }
            else if (!EngineControl)
            {
                try
                {
                    const auto Canceled = Inbound->Cancel();
                    if (!Canceled) RecordTerminalFailure(Canceled.error());
                    const auto Closed = Inbound->Close();
                    if (!Closed) RecordTerminalFailure(Closed.error());
                }
                catch (const boost::system::system_error &Error)
                {
                    RecordTerminalFailure(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error.code())));
                }
                catch (const std::system_error &Error)
                { RecordTerminalFailure(Prism::Fault::FromNative(Error.code())); }
                catch (...)
                {
                    RecordTerminalFailure(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
            }
        }
        Prism::SharedTransmission Inbound;
        RootOptions Options;
        std::vector<ChildRetirementSlot> ChildRetirementSlots;
        std::optional<std::size_t> FreeChildRetirementSlot;
        Net::strand<Net::any_io_executor> Executor;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Children, Loops;
        Prism::Lifecycle::DrainBarrier Lifetime;
        Prism::Fault::FailureState TerminalFailure;
        std::shared_ptr<RootEngineControl> EngineControl;
        Prism::Account::AccountLease Lease;
        Prism::Account::StreamLease ParentStreamLease;
        Prism::Foundation::GenerationUseLease GenerationLease;
        std::weak_ptr<RootRetirementOwner> RetirementOwner;
        Prism::Account::StreamAdmission Admission;
        Prism::Contract::RequestMetadata Metadata;
        std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> StreamCatalogOwner;
        std::unordered_map<std::uint64_t,
            std::shared_ptr<Prism::Contract::Ingress::StreamResetOwner>> StreamResetOwners;
        Mode SelectedWire{Mode::Auto};
        std::atomic_bool Started{false}, Stopping{false};
        std::atomic<RunPhase> Phase{RunPhase::AcceptingCancellation};
        std::atomic_bool ResourcesRetired{false};
        std::atomic_bool ResourcesReadyForFinalization{false};
        std::atomic<Prism::Fault::Code> ExitStatus{Prism::Fault::Code::Success};
    };

    [[nodiscard]] inline auto ControlFailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }

    inline auto RecordControlResult(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        const std::expected<void, Prism::Fault::Failure> &Result,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        if (Result) return;
        if (Root && !(Root->IsClosingNormally() &&
            Result.error().Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Result.error());
        if (Owner) (void)Owner->TrySet(Result.error());
    }

    inline auto RecordControlException(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        std::exception_ptr Exception,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        if (!Exception) return;
        const auto Failure = ControlFailureFromException(std::move(Exception));
        if (Root && !(Root->IsClosingNormally() &&
            Failure.Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Failure);
        if (Owner) (void)Owner->TrySet(Failure);
    }

    template<class Transport>
    inline auto CancelAndClose(
        const std::shared_ptr<Transport> &Value,
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        if (!Value) return;
        try { RecordControlResult(Owner, Value->Cancel(), Root); }
        catch (...) { RecordControlException(Owner, std::current_exception(), Root); }
        try { RecordControlResult(Owner, Value->Close(), Root); }
        catch (...) { RecordControlException(Owner, std::current_exception(), Root); }
    }

    inline auto ChildState::Cancel() noexcept -> void
    {
        if (Root && Root->IsClosingNormally())
            NormalCloseCancellation.store(true, std::memory_order_release);
        Cancellation.emit(Net::cancellation_type::all);
        if (Root && Root->StreamCatalogOwner)
        {
            const Prism::Contract::Ingress::StreamIdentity StreamIdentity{
                Root->Metadata.TaskIdentity.SessionId,
                Root->Metadata.TaskIdentity.WorkerId,
                Root->Metadata.TaskIdentity.Generation,
                Identity.StreamId};
            if (!Root->StreamCatalogOwner->MarkDraining(StreamIdentity))
                Root->StreamCatalogOwner->Disable();
        }
        if (Reset && ControlFailure)
        {
            try { RecordControlResult(ControlFailure, Reset(), Root); }
            catch (...) { RecordControlException(ControlFailure, std::current_exception(), Root); }
        }
        CancelAndClose(Inbound, ControlFailure, Root);
        CancelAndClose(Outbound, ControlFailure, Root);
    }
}
