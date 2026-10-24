/** @file State.hpp @brief XUDP 根与每 id 私有 socket、目标、期限和真实 StreamLease。 */
#pragma once
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Vless/Xudp/Writer.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <optional>
#include <chrono>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <utility>

namespace Prism::Vless::Xudp
{
    [[nodiscard]] auto TaskScopePhysicallyRetired(
        const Prism::Lifecycle::TaskStats& Stats) noexcept -> bool;

    [[nodiscard]] auto TaskScopePhysicallyRetired(
        const std::shared_ptr<Prism::Lifecycle::TaskRegistry>& Scope) noexcept -> bool;

    struct Association final : std::enable_shared_from_this<Association>
    {
        using Queue = Net::experimental::channel<void(boost::system::error_code, Frame)>;
        Association(Net::any_io_executor Ex, std::shared_ptr<Prism::Lifecycle::TaskRegistry> Scope);
        /** @brief 仅取消本 id 的排队、DNS/UDP/期限任务，不触碰根 transport 或兄弟 socket。 */
        auto Cancel() noexcept -> void;
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
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);
        auto Stop() noexcept -> void;
        auto Cancel() noexcept -> void;
        auto RecordFailure(Prism::Fault::Failure Value) noexcept -> void;
        [[nodiscard]] auto PhysicalRetirementReady() const noexcept -> bool;
        /** @brief 已取得全部独立物理回执后才释放协议资源和 generation lease。 */
        [[nodiscard]] auto ReleaseResources() -> Net::awaitable<bool>;
        auto StopOnExecutor() noexcept -> void;
        auto CancelAssociationsOnExecutor() noexcept -> void;
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
