/** @file IoActivity.hpp @brief 冷建操作槽通知，完成退栈只归还已预约通知，原域释放真实owner。 */
#pragma once
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Lifecycle/Detail/DrainNotification.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <atomic>
#include <cstdint>
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
            explicit State(boost::asio::any_io_executor Executor, RetirementPolicy Policy)
                : RequiresCloseReceipt(Policy != RetirementPolicy::OperationsDrained),
                  Context(Prism::Executor::ContextOwner::Find(Executor)),
                  Storage(Prism::Executor::ContextOwner::Storage(Executor)),
                  Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor))),
                  Barrier(Reclaimer), DrainChanges(Reclaimer->Executor(), 1),
                  DrainNotificationAvailable(Prism::Lifecycle::Detail::DrainNotification::Bind(Reclaimer->Executor()))
            { for (auto& Entry : Slots) Entry.Returned = std::make_unique<Signal>(Reclaimer->Executor(), 1); }
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
            [[nodiscard]] auto ClosePending() const noexcept -> bool
            {
                return CloseAccepted.load(std::memory_order_acquire) &&
                    !CloseDelivered.load(std::memory_order_acquire);
            }
            [[nodiscard]] auto HasReportableControlFailure() const noexcept -> bool
            {
                return KnownControlFailures.load(std::memory_order_acquire) != 0 &&
                    (!ClosePending() ||
                     KnownCloseControlFailures.load(std::memory_order_acquire) != 0);
            }
            auto NotifyDrainState() noexcept -> void
            {
                if (DrainWaiters.load(std::memory_order_acquire) == 0 ||
                    !DrainNotificationAvailable->load(std::memory_order_acquire)) return;
                (void)DrainChanges.try_send(boost::system::error_code{});
            }
            auto Fail(Prism::Fault::Failure Error = {Prism::Fault::Code::Blocked}) noexcept -> void
            {
                (void)Failure.TrySet(Error);
                Unrecoverable.store(true, std::memory_order_release);
                Blocked.store(true, std::memory_order_release);
                Barrier.Block();
                Storage->Retain(shared_from_this());
                NotifyDrainState();
            }
            /** @brief 记录一个命令的首次正式失败；重复失败不重复计算预约。 */
            auto RecordControlFailure(Prism::Fault::Failure Error, bool NewForCommand,
                bool IsClose) noexcept -> void
            {
                if (NewForCommand)
                {
                    KnownControlFailures.fetch_add(1, std::memory_order_acq_rel);
                    if (IsClose)
                        KnownCloseControlFailures.fetch_add(1, std::memory_order_acq_rel);
                }
                if (Unrecoverable.load(std::memory_order_acquire))
                {
                    Fail(Error);
                    return;
                }
                (void)Failure.TrySet(Error);
                Blocked.store(true, std::memory_order_release);
                Storage->Retain(shared_from_this());
                NotifyDrainState();
            }
            /** @brief 仅真实成功的同一命令重试可解除其失败预约。 */
            auto ResolveControlFailure(bool IsClose) noexcept -> void
            {
                auto Count = KnownControlFailures.load(std::memory_order_acquire);
                while (Count != 0 && !KnownControlFailures.compare_exchange_weak(
                    Count, Count - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
                if (IsClose)
                {
                    auto CloseCount = KnownCloseControlFailures.load(std::memory_order_acquire);
                    while (CloseCount != 0 && !KnownCloseControlFailures.compare_exchange_weak(
                        CloseCount, CloseCount - 1, std::memory_order_acq_rel,
                        std::memory_order_acquire)) {}
                }
                NotifyDrainState();
                if (CloseDelivered.load(std::memory_order_acquire) &&
                    KnownControlFailures.load(std::memory_order_acquire) == 0)
                    Storage->Collect();
            }
            /** @brief 实际关闭处理器已成功；Drain 仍等待所有槽位和用户 completion 退栈。 */
            auto RecordCloseDelivered() noexcept -> void
            {
                CloseDelivered.store(true, std::memory_order_release);
                NotifyDrainState();
            }
            /** @brief 关闭已受理但尚未在原域交付时，Drain 不得提前返回成功。 */
            /** @brief 关闭已明确受理；即使操作型活动也必须等该命令实际交付。 */
            auto RecordCloseAccepted() noexcept -> void
            {
                CloseAccepted.store(true, std::memory_order_release);
                NotifyDrainState();
            }
            /** @brief 登记同一控制命令的重试飞行，Drain 等待其真实 handler 回执。 */
            auto BeginControlRetry() noexcept -> void
            { ControlRetriesInFlight.fetch_add(1, std::memory_order_acq_rel); }
            /** @brief 消费重试 handler 回执并唤醒等待 Drain 的协程。 */
            auto EndControlRetry() noexcept -> void
            {
                auto Count = ControlRetriesInFlight.load(std::memory_order_acquire);
                while (Count != 0 && !ControlRetriesInFlight.compare_exchange_weak(
                    Count, Count - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
                if (Count == 1 && CloseDelivered.load(std::memory_order_acquire) &&
                    KnownControlFailures.load(std::memory_order_acquire) == 0) Storage->Collect();
                NotifyDrainState();
            }
            /** @brief handler 丢失、执行域失效或其他未知失败必须永久保留真实 owner。 */
            auto RequestRetirement() -> void override {}
            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return (!RequiresCloseReceipt || CloseDelivered.load(std::memory_order_acquire)) &&
                    !ClosePending() &&
                    !Unrecoverable.load(std::memory_order_acquire) &&
                    ControlRetriesInFlight.load(std::memory_order_acquire) == 0 &&
                    Barrier.Active() == 0 && HasNoUsedSlots();
            }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            {
                if (!Unrecoverable.load(std::memory_order_acquire) &&
                    KnownControlFailures.load(std::memory_order_acquire) != 0 && Reclaimer->CanDispatch()) return false;
                return Unrecoverable.load(std::memory_order_acquire) ||
                    (Blocked.load(std::memory_order_acquire) && !Reclaimer->CanDispatch());
            }
            [[nodiscard]] auto HasNoUsedSlots() const noexcept -> bool
            {
                for (const auto& Entry : Slots) if (Entry.Used.load(std::memory_order_acquire)) return false;
                return true;
            }
        };
        /** @brief cleanup等待在原生initiate前登记；用户handler全部退出后才触发，无新析构投递。 */
        struct Retirement final
        {
            std::shared_ptr<State> Owner;
            std::size_t Index;
            bool Executed{false};
            Retirement(std::shared_ptr<State> Value, std::size_t SlotIndex) : Owner(std::move(Value)), Index(SlotIndex) {}
            Retirement(Retirement&& Other) noexcept : Owner(std::move(Other.Owner)), Index(Other.Index) {}
            ~Retirement() { if (Owner && !Executed) Owner->Fail(); }
            auto operator()(boost::system::error_code Error) -> void
            {
                if (Error) { Owner->Fail(Prism::Fault::FromNative(static_cast<std::error_code>(Error))); Executed = true; return; }
                Owner->Slots[Index].Carrier.store({});
                Owner->Slots[Index].Used.store(false, std::memory_order_release);
                Owner->Barrier.Leave();
                Owner->NotifyDrainState();
                Executed = true;
                if (Owner->CloseDelivered.load(std::memory_order_acquire)) Owner->Storage->Collect();
            }
        };
    public:
        class Operation final
        {
        public:
            Operation(const Operation&) = delete;
            auto operator=(const Operation&) -> Operation& = delete;
            Operation(Operation&& Other) noexcept
                : Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_) {}
            ~Operation()
            {
                if (!Owner_) return;
                if (!Returned_) { Owner_->Fail(); return; }
                if (!Owner_->Slots[Index_].Returned->try_send(boost::system::error_code{})) Owner_->Fail();
            }
            /** @brief 只能在真实用户completion返回后标记，handler成员随后销毁才发送通知。 */
            auto Returned() noexcept -> void { Returned_ = true; }
            /** @brief handler丢弃时连同其buffer/frame拥有保存在预建槽，不先析构再标失败。 */
            auto RetainHandler(IoCompletion Handler) noexcept -> void
            { if (Owner_) Owner_->Slots[Index_].Abandoned = std::move(Handler); }
        private:
            friend class IoActivity;
            Operation(std::shared_ptr<State> Owner, std::size_t Index) : Owner_(std::move(Owner)), Index_(Index) {}
            std::shared_ptr<State> Owner_;
            std::size_t Index_;
            bool Returned_{false};
        };
        explicit IoActivity(boost::asio::any_io_executor Executor,
            RetirementPolicy Policy = RetirementPolicy::CloseReceiptRequired)
            : State_(std::make_shared<State>(std::move(Executor), Policy)) {}
        /** @brief 实际载体/TLS引擎owner一次接入；回收独立于用户allocator，数据槽严格限制64。 */
        [[nodiscard]] auto TryAcquire(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>
        { return Acquire(std::move(Carrier), Range{0, Capacity}); }
        /** @brief 关闭与取消独立预留65槽，不争用64个数据槽或数据字节。 */
        [[nodiscard]] auto TryAcquireControl(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>
        { return Acquire(std::move(Carrier), Range{Capacity, Capacity + ControlCapacity}); }
        /** @brief 已知可重试控制失败后仍允许独立最终关闭预约。 */
        [[nodiscard]] auto TryAcquireCloseControl(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Prism::Fault::Failure>
        { return Acquire(std::move(Carrier), Range{Capacity, Capacity + ControlCapacity}, true); }
        auto Block(Prism::Fault::Failure Failure = {Prism::Fault::Code::Blocked}) noexcept -> void { State_->Fail(Failure); }
        /** @brief 保留实际控制 handler 的正式失败；调用方为同一命令只登记首次失败。 */
        auto RecordControlFailure(Prism::Fault::Failure Failure, bool NewForCommand,
            bool IsClose) noexcept -> void
        { State_->RecordControlFailure(Failure, NewForCommand, IsClose); }
        /** @brief 仅实际成功的同命令重试解除失败预约，不影响其他控制命令。 */
        auto ResolveControlFailure(bool IsClose) noexcept -> void
        { State_->ResolveControlFailure(IsClose); }
        /** @brief 登记同一控制 owner 正在重试。 */
        auto BeginControlRetry() noexcept -> void { State_->BeginControlRetry(); }
        /** @brief 重试 handler 退栈后发布完成通知。 */
        auto EndControlRetry() noexcept -> void { State_->EndControlRetry(); }
        /** @brief 确认关闭已在原 executor 成功交付；资源仍须等实际 I/O 与 completion 全部退栈。 */
        auto RecordCloseDelivered() noexcept -> void { State_->RecordCloseDelivered(); }
        auto RecordCloseAccepted() noexcept -> void { State_->RecordCloseAccepted(); }
        /** @brief 仅供原域排他冷移交判定，不替代Drain或允许并发发起新操作。 */
        [[nodiscard]] auto IsIdle() const noexcept -> bool
        { return State_->Barrier.Active() == 0 && !State_->Barrier.IsBlocked() &&
            !State_->Blocked.load(std::memory_order_acquire); }
        /** @brief 所有原域控制、数据预约和槽位真实归还后的独立关闭回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return State_->Barrier.IsSealed() && State_->IsRetired(); }
        auto Seal() noexcept -> void override { State_->Barrier.Seal(); }
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override { return State_->Reclaimer->Executor(); }
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { Seal(); return DrainState(State_); }
    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = std::expected<void, Prism::Fault::Failure>{};
            for (;;)
            {
                const auto Failure = Owner->Failure.Load();
                const auto RetryInFlight = Owner->ControlRetriesInFlight.load(std::memory_order_acquire) != 0;
                if (Owner->Unrecoverable.load(std::memory_order_acquire) ||
                    (!RetryInFlight && Owner->HasReportableControlFailure()))
                {
                    if (Failure.Failed()) Result = std::unexpected(Failure);
                    else Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    break;
                }
                if (!RetryInFlight && Owner->Barrier.Active() == 0 && !Owner->ClosePending())
                {
                    if (!Owner->CloseDelivered.load(std::memory_order_acquire) && Failure.Failed())
                        Result = std::unexpected(Failure);
                    break;
                }
                if (!Owner->Reclaimer->CanDispatch())
                {
                    if (Failure.Failed()) Result = std::unexpected(Failure);
                    else Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    break;
                }
                struct DrainWaiter final
                {
                    explicit DrainWaiter(std::shared_ptr<State> Value) : Owner(std::move(Value))
                    { Owner->DrainWaiters.fetch_add(1, std::memory_order_acq_rel); }
                    ~DrainWaiter() { Owner->DrainWaiters.fetch_sub(1, std::memory_order_acq_rel); }
                    std::shared_ptr<State> Owner;
                } Waiter(Owner);
                const bool RetryPending =
                    Owner->ControlRetriesInFlight.load(std::memory_order_acquire) != 0;
                if (Owner->Unrecoverable.load(std::memory_order_acquire) ||
                    (!RetryPending && Owner->HasReportableControlFailure()) ||
                    (!RetryPending && Owner->Barrier.Active() == 0 && !Owner->ClosePending()))
                    continue;
                if (!Owner->Reclaimer->CanDispatch()) continue;
                boost::system::error_code Error;
                co_await Owner->DrainChanges.async_receive(
                    boost::asio::redirect_error(boost::asio::use_awaitable, Error));
                if (Error)
                {
                    const auto RecordedFailure = Owner->Failure.Load();
                    if (RecordedFailure.Failed()) Result = std::unexpected(RecordedFailure);
                    else Result = std::unexpected(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
                    break;
                }
            }
            Owner->NotifyDrainState();
            co_return Result;
        }
        struct Range final { std::size_t Begin, End; };
        [[nodiscard]] auto Acquire(
            std::shared_ptr<void> Carrier, Range Slots,
            const bool AllowKnownControlFailure = false)
            -> std::expected<Operation, Prism::Fault::Failure>
        {
            if (!Carrier) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            const auto CanPassKnownFailure = AllowKnownControlFailure &&
                !State_->Unrecoverable.load(std::memory_order_acquire);
            if (State_->Blocked.load(std::memory_order_acquire) && !CanPassKnownFailure)
                return std::unexpected(State_->Failure.Load());
            if (!State_->Barrier.Enter())
            {
                State_->NotifyDrainState();
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            if (State_->Blocked.load(std::memory_order_acquire) &&
                (State_->Unrecoverable.load(std::memory_order_acquire) || !AllowKnownControlFailure))
            {
                State_->Barrier.Leave();
                State_->NotifyDrainState();
                return std::unexpected(State_->Failure.Load());
            }
            for (std::size_t Index = Slots.Begin; Index < Slots.End; ++Index)
            {
                if (State_->Slots[Index].Used.exchange(true, std::memory_order_acq_rel)) continue;
                State_->Slots[Index].Carrier.store(std::move(Carrier));
                Operation Result(State_, Index);
                State_->Slots[Index].Returned->async_receive(boost::asio::bind_allocator(State_->CleanupMemory,
                    boost::asio::bind_executor(State_->Reclaimer->Executor(), Retirement(State_, Index))));
                return Result;
            }
            State_->Barrier.Leave();
            State_->NotifyDrainState();
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        std::shared_ptr<State> State_;
    };
}
