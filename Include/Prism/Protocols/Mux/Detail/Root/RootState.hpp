/** @file RootState.hpp @brief generic mux 根持真实 lease、子流与独立 frame/child scopes。 */
#pragma once
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Protocols/Mux/RootOptions.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
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
#include <cstddef>
#include <memory>

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
        using StartSignal =
            Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        std::shared_ptr<RootState> Root;
        Prism::SharedTransmission Inbound, Outbound;
        Prism::Account::StreamLease Lease;
        std::optional<std::size_t> RetirementSlot;
        Prism::Lifecycle::TaskIdentity Identity;
        Prism::Network::Target Target;
        Net::cancellation_signal Cancellation;
        /** @brief 区分显式 child 取消与根 owner 的正常 close，两者都仍需完成物理退休。 */
        std::atomic_bool NormalCloseCancellation{false}, ExplicitCancellation{false};
        std::atomic_bool CancelIssued{false};
        std::function<void()> Reject;
        std::function<std::expected<void, Prism::Fault::Failure>()> Reset;
        std::function<Net::awaitable<std::expected<void, Prism::Fault::Failure>>()> Finish;
        std::shared_ptr<Prism::Fault::FailureState> ControlFailure;
        /** @brief H2 在 catalog 注册完成并提交 200 之前阻止 child 数据面启动。 */
        std::shared_ptr<StartSignal> StartGate;
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
        RootState(Prism::SharedTransmission Transport, RootOptions Value);
        [[nodiscard]] auto ReserveChildRetirementSlot() noexcept
            -> std::optional<std::size_t>;
        auto ReleaseChildRetirementSlot(std::size_t Index) noexcept -> void;
        [[nodiscard]] auto HasOutstandingChildRetirement() const noexcept -> bool;
        auto RetainChildUntilRootRetired(std::shared_ptr<ChildState> Child) noexcept -> void;
        /** @brief 仅在取消阶段设置或补齐终态；结果发布或退休后不覆盖。 */
        auto RequestCancel() noexcept -> void;
        [[nodiscard]] auto IsClosingNormally() const noexcept -> bool;
        /** @brief 是否已请求根级显式取消；用于保留历史取消而不伪造正常 close。 */
        [[nodiscard]] auto IsExplicitlyCanceled() const noexcept -> bool;
        [[nodiscard]] auto IsExpectedRetirementCancellation(
            const Prism::Fault::Failure &Failure, bool Retired) const noexcept -> bool;
        /** @brief 原子发布 Run 结果；返回 true 表示此前取消请求已胜出。 */
        [[nodiscard]] auto PublishRunOutcome() noexcept -> bool;
        /** @brief 保存根 Run 子任务最先返回的 typed 首因及 Native。 */
        auto RecordTerminalFailure(Prism::Fault::Failure Failure) noexcept -> void;
        [[nodiscard]] static auto FailureFromException(std::exception_ptr Failure) noexcept
            -> Prism::Fault::Failure;
        [[nodiscard]] auto DrainTaskScope(
            const std::shared_ptr<Prism::Lifecycle::TaskRegistry> &Scope)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        auto ReleaseResources() -> bool;
        auto Stop() noexcept -> void;
        auto StopOnExecutor() noexcept -> void;
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
        std::weak_ptr<Prism::Contract::MuxRootCreateOwner> CreateOwner;
        std::unordered_map<std::uint64_t,
            std::shared_ptr<Prism::Contract::Ingress::StreamResetOwner>> StreamResetOwners;
        Mode SelectedWire{Mode::Auto};
        std::atomic_bool Started{false}, Stopping{false};
        /** @brief 串行化 Run 与 Activity::Drain 的最终资源回收，保证只释放一次。 */
        std::shared_ptr<Net::experimental::concurrent_channel<void(boost::system::error_code)>>
            DrainGate;
        std::atomic_bool ReleaseInProgress{false};
        std::atomic<RunPhase> Phase{RunPhase::AcceptingCancellation};
        std::atomic_bool ResourcesRetired{false};
        std::atomic_bool ResourcesReadyForFinalization{false};
        std::atomic<Prism::Fault::Code> ExitStatus{Prism::Fault::Code::Success};
    };

    [[nodiscard]] auto ControlFailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure;

    auto RecordControlResult(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        const std::expected<void, Prism::Fault::Failure> &Result,
        const std::shared_ptr<RootState> &Root) noexcept -> void;

    auto RecordControlException(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        std::exception_ptr Exception,
        const std::shared_ptr<RootState> &Root) noexcept -> void;

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

}
