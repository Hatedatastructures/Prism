/** @file State.hpp @brief XUDP 根与每 id 私有 socket、目标、期限和真实 StreamLease。 */
#pragma once
#include <Prism/Protocols/Vless/Xudp/Writer.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include <atomic>
#include <optional>

namespace Prism::Vless::Xudp
{
    [[nodiscard]] inline auto TaskScopePhysicallyRetired(
        const Prism::Lifecycle::TaskStats& Stats) noexcept -> bool
    {
        return Stats.Active == 0U && !Stats.DrainBlocked;
    }

    [[nodiscard]] inline auto TaskScopePhysicallyRetired(
        const std::shared_ptr<Prism::Lifecycle::TaskRegistry>& Scope) noexcept -> bool
    {
        return Scope && TaskScopePhysicallyRetired(Scope->Stats());
    }

    struct Association final : std::enable_shared_from_this<Association>
    {
        using Queue = Net::experimental::channel<void(boost::system::error_code, Frame)>;
        Association(Net::any_io_executor Ex, std::shared_ptr<Prism::Lifecycle::TaskRegistry> Scope)
            : Socket(Ex), Incoming(Ex, 32), Ready(Ex, 1), Deadline(Ex), Tasks(std::move(Scope)) {}
        /** @brief 仅取消本 id 的排队、DNS/UDP/期限任务，不触碰根 transport 或兄弟 socket。 */
        auto Cancel() noexcept -> void
        {
            const bool First = !Closed.exchange(true);
            if (First)
            {
                Cancellation.emit(Net::cancellation_type::all);
                Incoming.close(); Ready.close(); Deadline.cancel();
            }
            boost::system::error_code Error;
            Socket.cancel(Error); Socket.close(Error);
            (void)Tasks->Cancel();
        }
        Net::ip::udp::socket Socket;
        Queue Incoming;
        Net::experimental::channel<void(boost::system::error_code)> Ready;
        Net::steady_timer Deadline;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks;
        std::shared_ptr<Association> RetiringNext;
        Net::cancellation_signal Cancellation;
        Prism::Account::StreamLease Lease;
        Prism::Lifecycle::TaskIdentity Identity;
        std::uint16_t Id{0};
        Prism::Network::Target Target;
        bool HasTarget{false};
        std::optional<Net::ip::udp::endpoint> ExpectedSource;
        std::uint64_t SocketEpoch{0};
        std::chrono::steady_clock::time_point Activity{std::chrono::steady_clock::now()};
        std::atomic_bool Closed{false};
        bool CompletionReported{false};
        std::uint64_t Up{0}, Down{0}, Datagrams{0};
    };
    struct State final : std::enable_shared_from_this<State>
    {
        State(Prism::SharedTransmission Value, Prism::Protocols::DatagramBinding Binding,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Inbound(std::move(Value)), Services(std::move(Binding.Services)), Observation(std::move(Binding.Observation)),
              Executor(Net::make_strand(Inbound->Executor())),
              FrameFinished(Executor, 1),
              DrainChanged(Executor),
              Failure(std::make_shared<RunFailureState>()),
              Loops(std::make_shared<Prism::Lifecycle::TaskRegistry>(
                  Executor, MakeRunFailureHandler(Failure))),
              Children(std::make_shared<Prism::Lifecycle::TaskRegistry>(
                  Executor, MakeRunFailureHandler(Failure))),
              Writes(std::make_shared<Prism::Lifecycle::TaskRegistry>(
                  Executor, MakeRunFailureHandler(Failure))),
              Lifetime(Loops->Reclaimer()),
              RequiredGenerationUseState(std::move(UseState)),
              Output(std::make_shared<Writer>(Inbound, Writes, Failure)) {}
        auto Stop() noexcept -> void
        {
            if (Stopping.exchange(true)) return;
            const auto Self = shared_from_this();
            Net::dispatch(Executor, [Self] { Self->StopOnExecutor(); });
        }
        auto Cancel() noexcept -> void
        {
            Cancelled.store(true, std::memory_order_release);
            Stop();
        }
        auto RecordFailure(Prism::Fault::Failure Value) noexcept -> void
        {
            Failure->Record(std::move(Value));
        }
        [[nodiscard]] auto PhysicalRetirementReady() const noexcept -> bool
        {
            return TaskScopePhysicallyRetired(Children) &&
                TaskScopePhysicallyRetired(Loops) &&
                TaskScopePhysicallyRetired(Writes) &&
                Lifetime.Active() == 0U && !Lifetime.IsBlocked() &&
                Associations.empty() && !RetiringAssociations &&
                CarrierRetired.load(std::memory_order_acquire);
        }
        /** @brief 已取得全部独立物理回执后才释放协议资源和 generation lease。 */
        [[nodiscard]] auto ReleaseResources() -> Net::awaitable<bool>
        {
            co_await Net::dispatch(Executor, Net::use_awaitable);
            if (ResourcesReleased.load(std::memory_order_acquire)) co_return true;
            if (!PhysicalRetirementReady()) co_return false;
            Output.reset();
            Inbound.reset();
            Services = {};
            Observation = {};
            Metadata = {};
            Admission = {};
            Lease.Release();
            GenerationLease = {};
            RequiredGenerationUseState.reset();
            ResourcesReleased.store(true, std::memory_order_release);
            co_return true;
        }
        auto StopOnExecutor() noexcept -> void
        {
            Stopping.store(true);
            if (Output) Output->Close();
            CancelAssociationsOnExecutor();
            (void)Loops->Cancel(); (void)Children->Cancel(); (void)Writes->Cancel();
        }
        auto CancelAssociationsOnExecutor() noexcept -> void
        {
            for (const auto& [Id, Value] : Associations) { (void)Id; Value->Cancel(); }
            for (auto Value = RetiringAssociations; Value; Value = Value->RetiringNext)
                Value->Cancel();
        }
        Prism::SharedTransmission Inbound;
        Prism::Contract::DatagramServices Services;
        Prism::Protocols::DatagramObservation Observation;
        Net::strand<Net::any_io_executor> Executor;
        Net::experimental::channel<void(boost::system::error_code)> FrameFinished;
        Net::steady_timer DrainChanged;
        std::shared_ptr<RunFailureState> Failure;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Loops, Children, Writes;
        Prism::Lifecycle::DrainBarrier Lifetime;
        std::shared_ptr<Prism::Foundation::GenerationUseState> RequiredGenerationUseState;
        std::shared_ptr<Writer> Output;
        std::unordered_map<std::uint16_t, std::shared_ptr<Association>> Associations;
        std::shared_ptr<Association> RetiringAssociations;
        Prism::Account::AccountLease Lease;
        /** @brief 本 XUDP 根唯一代次预约，所有实体操作退栈前不得释放。 */
        Prism::Foundation::GenerationUseLease GenerationLease;
        Prism::Account::StreamAdmission Admission;
        Prism::Contract::RequestMetadata Metadata;
        std::atomic_bool Started{false}, Stopping{false}, Cancelled{false};
        bool DrainInProgress{false};
        /** @brief 底层 CarrierActivity 独立 IsRetired 回执；Drain error 与此事实分开保存。 */
        std::atomic_bool CarrierRetired{false};
        /** @brief 仅在全部任务域与底层载体排空成功、代次预约释放后置位。 */
        std::atomic_bool ResourcesReleased{false};
    };
}
