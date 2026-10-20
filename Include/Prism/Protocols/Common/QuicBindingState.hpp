/** @file QuicBindingState.hpp @brief 实际 QUIC 连接集合、原 executor 回收与 typed 排空失败。 */
#pragma once
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>
#include <cstddef>
#include <expected>
namespace Prism::Protocols
{
    /** @brief owner 集合持有真实实物及独立 context；通知只 weak 联系本对象，无 Runtime 强 pin。 */
    class QuicBindingState final : public Prism::Executor::ClosingResource,
        public std::enable_shared_from_this<QuicBindingState>
    {
    public:
        explicit QuicBindingState(boost::asio::any_io_executor Executor);
        /** @brief listener executor 上登记完整 native owner；失败不发布连接，预约只计真实最终完成。 */
        [[nodiscard]] auto Track(
            std::shared_ptr<Prism::Contract::QuicConnectionOwner> Owner) -> bool;
        auto Finished(const Prism::Contract::QuicConnectionOwner* Owner) noexcept -> void;
        [[nodiscard]] auto Closed() const noexcept -> bool {return Closed_.load();}
        [[nodiscard]] auto PendingCloseFailure() const noexcept
            ->std::optional<Prism::Fault::Failure>;
        [[nodiscard]] auto CanDispatch() const noexcept -> bool;
        [[nodiscard]] auto CanAdmit() const noexcept -> bool;
        /** @brief 任意线程封止接入并投递弱通知；真实 owner 集合保活 context 和协议材料。 */
        auto Close() noexcept -> void;
        auto Failed(Prism::Fault::Failure Reason={Prism::Fault::Code::Blocked}) noexcept -> void;
        /** @brief 只有真实 owner 尚未 finalize 时接管至 L1；不创建第二回收队列。 */
        auto HoldPending() noexcept -> void;
        /** @brief 保留单连接关闭拒收首因，并让活动 owner 留在关闭存储中等待同 executor 重试。 */
        auto RetainRejectedCloseRequest(Prism::Fault::Failure Reason) noexcept -> void;
        auto RequestRetirement() noexcept -> void override;
        /** @brief 物理退休只在关闭已封口且 Native/协议 finalizer 全部归还后成立。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {return Closed_.load(std::memory_order_acquire) && Active_.load(std::memory_order_acquire)==0 && Barrier_.Active()==0;}
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override {return DispatchFailed_.load();}
        /** @brief 等待实际 I/O 与 finalizer completion；不可调度和关闭失败返回原类型化失败。 */
        [[nodiscard]] auto Drain()
            ->boost::asio::awaitable<std::expected<void,Prism::Fault::Failure>>;
    private:
        [[nodiscard]] auto CloseOnExecutor()
            ->std::expected<void,Prism::Fault::Failure>;
        auto SaveCloseFailure(Prism::Fault::Failure Failure) noexcept -> void;
        [[nodiscard]] auto LoadCloseFailure() const noexcept
            ->std::optional<Prism::Fault::Failure>;
        auto ClearCloseFailure() noexcept -> void;
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Lifecycle::DrainBarrier Barrier_;
        std::vector<std::shared_ptr<Prism::Contract::QuicConnectionOwner>> Connections_;
        std::atomic<std::size_t> Active_{0};
        std::atomic<bool> Closed_{false},DispatchFailed_{false};
        Prism::Fault::FailureState Failure_;
        std::atomic<std::shared_ptr<const Prism::Fault::Failure>> CloseFailure_{};
    };
}
