/** @file Io.hpp @brief 冷建操作槽通知，完成退栈只归还已预约通知，原域释放真实owner。 */
#pragma once
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Io/Completion.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
namespace Prism::Transport::Detail
{
    /**
     * @brief 冷建操作槽通知的实际 owner：64 个数据槽与 65 个控制槽在真实完成退栈后归还预约。
     * @details 输入所有权：State 固定原 executor，并预建 carrier、completion 与 retirement 槽；TryAcquire
     *          把传入的共享 carrier 保存在槽中。move-only Operation 持有一次预约，只有真实用户 completion
     *          返回并且 handler 退栈后，Retirement 才清除 carrier、标记槽空闲并归还 DrainBarrier 计数。
     *          输出与错误：空 carrier 返回 InvalidArgument，封止准入返回 Canceled，槽耗尽返回
     *          ResourceUnavailable；已知控制命令失败的 Drain 返回保存的首因，但保留预约和 owner，
     *          未知 completion 丢失或原 executor 不可用则保留真实计数并阻止退休。
     *          取消：本类型没有 Cancel 门面；Seal 后拒绝新准入。协程采用取消值结果，不把取消伪装成完成。
     *          半关闭：本类型不执行写半关闭；该行为由 WriteDriver 的 WriteShutdown 处理。
     *          最终关闭者：本类型不关闭 socket；ClosingStorage 只在已确认 close、completion 槽退栈且预约归零后
     *          收集 State。已知控制失败可由同一原 executor 上的显式 Retry 恢复，未知失败保持保留。
     *          executor：Executor 与槽通知、DrainChanges channel 共用构造时固定的原 executor；通知许可在
     *          channel 构造后注册，调用方必须保活执行域。该类型不创建 strand，调用方负责串行化要求。
     * @note IsIdle 只读 DrainBarrier 与失败状态，不证明并发发起已停止，也不替代 Drain。
     */    class IoActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        /** @brief 关闭 owner 需真实回执；操作型仍等待已明确受理的关闭交付。 */
        enum class RetirementPolicy : std::uint8_t
        {
            CloseReceiptRequired,
            OperationsDrained,
        };

    private:
        static constexpr std::size_t Capacity = 64, ControlCapacity = 65;
        using Signal = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;
        struct Slot final
        {
            std::atomic<bool> Used{false};
            std::atomic<std::shared_ptr<void>> Carrier;
            std::unique_ptr<Signal> Returned;
            IoCompletion Abandoned;
        };
        struct State final : Prism::Executor::ClosingResource, std::enable_shared_from_this<State>
        {
            explicit State(boost::asio::any_io_executor Executor, RetirementPolicy Policy);
            const bool RequiresCloseReceipt;
            std::shared_ptr<Prism::Executor::ContextOwner> Context;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            Prism::Lifecycle::DrainBarrier Barrier;
            Signal DrainChanges;
            std::shared_ptr<const std::atomic<bool>> DrainNotificationAvailable;
            std::array<Slot, Capacity + ControlCapacity> Slots;
            /** @brief 原域回收的独立分配材料，不借用用户erased handler的raw impl代理。 */
            std::allocator<std::byte> CleanupMemory;
            std::atomic<bool> Blocked{false}, Unrecoverable{false};
            std::atomic<std::size_t> KnownControlFailures{0}, KnownCloseControlFailures{0};
            std::atomic<std::size_t> ControlRetriesInFlight{0};
            std::atomic<bool> CloseAccepted{false}, CloseDelivered{false};
            std::atomic<std::size_t> DrainWaiters{0};
            Prism::Fault::FailureState Failure;
            [[nodiscard]] auto ClosePending() const noexcept -> bool;
            [[nodiscard]] auto HasReportableControlFailure() const noexcept -> bool;
            auto NotifyDrainState() noexcept -> void;
            auto Fail(Prism::Fault::Failure Error = {Prism::Fault::Code::Blocked}) noexcept -> void;
            /** @brief 记录一个命令的首次正式失败；重复失败不重复计算预约。 */
            auto RecordControlFailure(Prism::Fault::Failure Error, bool NewForCommand,
                bool IsClose) noexcept -> void;
            /** @brief 仅真实成功的同一命令重试可解除其失败预约。 */
            auto ResolveControlFailure(bool IsClose) noexcept -> void;
            /** @brief 实际关闭处理器已成功；Drain 仍等待所有槽位和用户 completion 退栈。 */
            auto RecordCloseDelivered() noexcept -> void;
            /** @brief 关闭已受理但尚未在原域交付时，Drain 不得提前返回成功。 */
            /** @brief 关闭已明确受理；即使操作型活动也必须等该命令实际交付。 */
            auto RecordCloseAccepted() noexcept -> void;
            /** @brief 登记同一控制命令的重试飞行，Drain 等待其真实 handler 回执。 */
            auto BeginControlRetry() noexcept -> void;
            /** @brief 消费重试 handler 回执并唤醒等待 Drain 的协程。 */
            auto EndControlRetry() noexcept -> void;
            /** @brief handler 丢失、执行域失效或其他未知失败必须永久保留真实 owner。 */
            auto RequestRetirement() -> void override;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override;
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;
            [[nodiscard]] auto HasNoUsedSlots() const noexcept -> bool;
        };
        /** @brief cleanup等待在原生initiate前登记；用户handler全部退出后才触发，无新析构投递。 */
        struct Retirement final
        {
            std::shared_ptr<State> Owner;
            std::size_t Index;
            bool Executed{false};
            Retirement(std::shared_ptr<State> Value, std::size_t SlotIndex);
            Retirement(Retirement&& Other) noexcept;
            ~Retirement();
            auto operator()(boost::system::error_code Error) -> void;
        };
    public:
        class Operation final
        {
        public:
            Operation(const Operation&) = delete;
            auto operator=(const Operation&) -> Operation& = delete;
            Operation(Operation&& Other) noexcept;
            ~Operation();
            /** @brief 只能在真实用户completion返回后标记，handler成员随后销毁才发送通知。 */
            auto Returned() noexcept -> void;
            /** @brief handler丢弃时连同其buffer/frame拥有保存在预建槽，不先析构再标失败。 */
            auto RetainHandler(IoCompletion Handler) noexcept -> void;
        private:
            friend class IoActivity;
            Operation(std::shared_ptr<State> Owner, std::size_t Index);
            std::shared_ptr<State> Owner_;
            std::size_t Index_;
            bool Returned_{false};
        };
        explicit IoActivity(boost::asio::any_io_executor Executor,
            RetirementPolicy Policy = RetirementPolicy::CloseReceiptRequired);
        /** @brief 实际载体/TLS引擎owner一次接入；回收独立于用户allocator，数据槽严格限制64。 */
        [[nodiscard]] auto TryAcquire(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>;
        /** @brief 关闭与取消独立预留65槽，不争用64个数据槽或数据字节。 */
        [[nodiscard]] auto TryAcquireControl(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>;
        /** @brief 已知可重试控制失败后仍允许独立最终关闭预约。 */
        [[nodiscard]] auto TryAcquireCloseControl(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>;
        auto Block(Prism::Fault::Failure Failure = {Prism::Fault::Code::Blocked}) noexcept -> void;
        /** @brief 保留实际控制 handler 的正式失败；调用方为同一命令只登记首次失败。 */
        auto RecordControlFailure(Prism::Fault::Failure Failure, bool NewForCommand,
            bool IsClose) noexcept -> void;
        /** @brief 仅实际成功的同命令重试解除失败预约，不影响其他控制命令。 */
        auto ResolveControlFailure(bool IsClose) noexcept -> void;
        /** @brief 登记同一控制 owner 正在重试。 */
        auto BeginControlRetry() noexcept -> void;
        /** @brief 重试 handler 退栈后发布完成通知。 */
        auto EndControlRetry() noexcept -> void;
        /** @brief 确认关闭已在原 executor 成功交付；资源仍须等实际 I/O 与 completion 全部退栈。 */
        auto RecordCloseDelivered() noexcept -> void;
        auto RecordCloseAccepted() noexcept -> void;
        /** @brief 仅供原域排他冷移交判定，不替代Drain或允许并发发起新操作。 */
        [[nodiscard]] auto IsIdle() const noexcept -> bool;
        /** @brief 所有原域控制、数据预约和槽位真实归还后的独立关闭回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        auto Seal() noexcept -> void override;
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override;
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;
    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        struct Range final { std::size_t Begin, End; };
        [[nodiscard]] auto Acquire(
            std::shared_ptr<void> Carrier, Range Slots,
            bool AllowKnownControlFailure = false)
            -> std::expected<Operation, Prism::Fault::Failure>;
        std::shared_ptr<State> State_;
    };
}
