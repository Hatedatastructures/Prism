/** @file BindingLifetime.hpp @brief 协议绑定的实际退栈屏障、原 executor 退休及失败实物所有权。 */
#pragma once
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/strand.hpp>
#include <atomic>
#include <expected>
#include <exception>
#include <vector>
namespace Preview::Protocols
{
    namespace Net = boost::asio;
    class BindingLifetime final
    {
        struct CloseState final
        {
            CloseState(Net::any_io_executor Executor, Preview::Foundation::GenerationPin Pin)
                : Generation(std::move(Pin)), Context(Preview::Executor::ContextOwner::Find(Executor)),
                  Storage(Preview::Executor::ContextOwner::Storage(Executor)),
                  Barrier(std::make_shared<Preview::Executor::ExecutorReclaimer>(Net::make_strand(std::move(Executor)))) {}
            Preview::Foundation::GenerationPin Generation;
            std::shared_ptr<Preview::Executor::ContextOwner> Context;
            std::weak_ptr<Preview::Executor::ClosingStorage> Storage;
            Preview::Lifecycle::DrainBarrier Barrier;
            Preview::Fault::FailureState Failure;
        };
    public:
        class Activity;
    private:
        struct ClosingSlot final : Preview::Executor::ClosingResource
        {
            auto RequestRetirement() noexcept -> void override;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override { return !Failed.load(); }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override { return DispatchFailed.load(); }
            std::weak_ptr<Activity> Active;
            std::atomic<std::shared_ptr<Activity>> Failed;
            std::weak_ptr<Preview::Executor::ClosingStorage> Storage;
            std::atomic<bool> BindingOwned{true};
            std::atomic<bool> Activated{false}, PhysicallyRetired{false};
            std::atomic<bool> DispatchFailed{false}, RetryPending{false};
        };
    public:
        /** @brief 拥有载体、实际 executor context/allocator 和关闭状态；只 weak 联系预构造槽位。 */
        class Activity final : public std::enable_shared_from_this<Activity>
        {
        public:
            Activity(std::shared_ptr<CloseState> State, Preview::SharedTransmission Carrier)
                : State_(std::move(State)), Carrier_(std::move(Carrier)),
                  Executor_(Carrier_.load()->Executor()),
                  Context_(Preview::Executor::ContextOwner::Find(Executor_)), Reclaimer_(Executor_) {}
            ~Activity() { State_->Barrier.Leave(); }
            auto Attach(std::shared_ptr<ClosingSlot> Slot) -> void
            {
                Slot_ = Slot;
                Slot->Storage = Preview::Executor::ContextOwner::Storage(Executor_);
            }
            /** @brief 冷接入独立传输控制回执；关闭期间不借用 wrapper 的生存期。 */
            auto AttachCloseReceipt(std::shared_ptr<Preview::Contract::CarrierCloseReceipt> Receipt) noexcept -> void
            {
                CloseReceipt_.store(std::move(Receipt), std::memory_order_release);
                if (const auto Slot = Slot_.lock()) Slot->Activated.store(true, std::memory_order_release);
            }
            /** @brief 任意线程只提交关闭请求，载体检查/取消/最终释放均在原 executor。
             * @details 永久虚关闭失败由 typed Drain 报告；真正不可投递才隔离至 L1。
             */
            [[nodiscard]] auto RequestClose() noexcept
                -> Preview::Transmission::ControlResult
            {
                if (Retired_.load(std::memory_order_acquire)) return {};
                if (CloseRequested_.exchange(true, std::memory_order_acq_rel))
                {
                    const auto Failure = State_->Failure.Load();
                    if (Failure.Failed()) return std::unexpected(Failure);
                    return {};
                }
                return DispatchClose(Slot_.lock());
            }
            [[nodiscard]] auto Carrier() const noexcept -> Preview::SharedTransmission { return Carrier_.load(); }
            [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Executor_; }
            /** @brief 关闭已请求或实物已退休后，拒绝新数据面 I/O。 */
            [[nodiscard]] auto IsCloseRequested() const noexcept -> bool
            { return CloseRequested_.load(std::memory_order_acquire) || Retired_.load(std::memory_order_acquire); }
            /** @brief 保留实际 I/O 计数；调用者必须在载体 executor 执行并在退栈时 EndIo。 */
            auto BeginIo() noexcept -> void { IoActive_.fetch_add(1); }
            auto EndIo() noexcept -> void
            {
                if (IoActive_.fetch_sub(1) == 1)
                {
                    if(Retired_.load())Carrier_.store({});
                    ReleaseFailedSlot(Slot_.lock());
                }
            }
            /** @brief L1 仅重试失败关闭 owner；普通 Close/析构保持唯一一次提交。 */
            auto RequestRetirement() noexcept -> void
            {
                if (Retired_.load(std::memory_order_acquire)) return;
                const auto Slot = Slot_.lock();
                if (!Slot) return;
                const bool DispatchFailed = Slot->DispatchFailed.load(std::memory_order_acquire);
                const bool RetryPending = Slot->RetryPending.exchange(false, std::memory_order_acq_rel);
                if (!DispatchFailed && !RetryPending) return;
                (void)DispatchClose(Slot);
            }
            /** @brief binding 最后释放时接管尚未执行的关闭请求，覆盖已投递后 executor 停止。 */
            auto ReleaseBinding() noexcept -> void
            {
                const auto Slot = Slot_.lock();
                if (!Slot || (Retired_.load() && IoActive_.load() == 0)) return;
                Slot->Failed.store(shared_from_this());
                if (auto Storage = Slot->Storage.lock()) Storage->Retain(Slot);
                (void)RequestClose();
            }
        private:
            [[nodiscard]] auto DispatchClose(const std::shared_ptr<ClosingSlot>& Slot) noexcept
                -> Preview::Transmission::ControlResult
            {
                if (Retired_.load(std::memory_order_acquire)) return {};
                if (CloseInFlight_.exchange(true, std::memory_order_acq_rel))
                {
                    const auto Failure = State_->Failure.Load();
                    if (Failure.Failed()) return std::unexpected(Failure);
                    return {};
                }
                if(!CanDispatch())
                {
                    const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
                    CloseInFlight_.store(false, std::memory_order_release);
                    if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
                    HoldFailure(Failure,Slot);
                    return std::unexpected(Failure);
                }
                try
                {
                    if (Slot) Slot->DispatchFailed.store(false, std::memory_order_release);
                    const auto Self=shared_from_this();
                    const auto Posted=Reclaimer_.Post([Self,Slot]{Self->StartCloseOnExecutor(Slot);});
                    if(!Posted)
                    {
                        CloseInFlight_.store(false, std::memory_order_release);
                        if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
                        HoldFailure(Posted.error(),Slot);
                        return std::unexpected(Posted.error());
                    }
                    return {};
                }
                catch(...)
                {
                    CloseInFlight_.store(false, std::memory_order_release);
                    if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
                    PublishFatal(std::current_exception(),Slot);
                    return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
            }
            [[nodiscard]] auto CanDispatch() const noexcept -> bool { return !Context_ || Context_->CanDispatch(); }
            auto HoldFailure(Preview::Fault::Failure Reason, const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                if(Reason.Succeeded())Reason={Preview::Fault::Code::Blocked};
                State_->Failure.TrySet(Reason);
                if (!Slot)
                {
                    State_->Barrier.Block();
                    return;
                }
                Slot->RetryPending.store(true, std::memory_order_release);
                Slot->Failed.store(shared_from_this());
                if (auto Storage = Slot->Storage.lock()) Storage->Retain(Slot);
                State_->Barrier.Block();
            }
            auto StartCloseOnExecutor(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                try
                {
                    const auto Self=shared_from_this();
                    Net::co_spawn(Executor_,Self->CloseAndDrain(),
                        [Self,Slot](std::exception_ptr Error,Preview::Transmission::ControlResult Result)
                        { Self->CompleteClose(std::move(Error), std::move(Result), Slot); });
                }
                catch(...)
                {
                    CloseInFlight_.store(false, std::memory_order_release);
                    if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
                    PublishFatal(std::current_exception(),Slot);
                }
            }
            auto CompleteClose(
                std::exception_ptr Error,
                Preview::Transmission::ControlResult Result,
                const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                if (Error)
                {
                    CloseInFlight_.store(false, std::memory_order_release);
                    PublishFatal(std::move(Error), Slot);
                    return;
                }
                if (!Result)
                {
                    CloseInFlight_.store(false, std::memory_order_release);
                    HoldFailure(Result.error(), Slot);
                    return;
                }
                FinishClose(Slot);
            }
            [[nodiscard]] auto CloseAndDrain()
                -> Net::awaitable<Preview::Transmission::ControlResult>
            {
                const auto Value=Carrier_.load();
                if(!Value)co_return Preview::Transmission::ControlResult{};
                auto FirstFailure=Preview::Transmission::ControlResult{};
                const auto Cancelled=Value->Cancel();
                if(!Cancelled)FirstFailure=std::unexpected(Cancelled.error());
                const auto Closed=Value->Close();
                if(!Closed && FirstFailure)FirstFailure=std::unexpected(Closed.error());
                const auto Activity=Value->Activity();
                if(!Activity)
                {
                    if(!FirstFailure)co_return std::unexpected(FirstFailure.error());
                    co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                }
                Activity->Seal();
                const auto Drained=co_await Activity->Drain();
                if(!Drained && FirstFailure)FirstFailure=std::unexpected(Drained.error());
                const auto ActivityRetired = Activity->IsRetired();
                if (!ActivityRetired)
                {
                    if (FirstFailure)
                    {
                        FirstFailure = std::unexpected(
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    }
                    (void)State_->Failure.TrySet(FirstFailure.error());
                    co_return std::unexpected(FirstFailure.error());
                }

                if (auto Receipt = CloseReceipt_.load(std::memory_order_acquire))
                {
                    Receipt->ConfirmExternalClose();
                    const auto WrapperDrained = co_await Receipt->Drain();
                    const auto WrapperActivity = Value->Activity();
                    const bool WrapperRetired = WrapperActivity && WrapperActivity->IsRetired();
                    if (!WrapperDrained && FirstFailure)
                    {
                        FirstFailure = std::unexpected(WrapperDrained.error());
                    }
                    if (!WrapperRetired)
                    {
                        if (FirstFailure)
                        {
                            FirstFailure = std::unexpected(
                                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                        }
                        (void)State_->Failure.TrySet(FirstFailure.error());
                        co_return std::unexpected(FirstFailure.error());
                    }
                }

                if (!FirstFailure)
                {
                    (void)State_->Failure.TrySet(FirstFailure.error());
                }
                // 成功只表示实物与包装层真实退休；历史故障由 BindingLifetime::Drain 保留返回。
                co_return Preview::Transmission::ControlResult{};
            }
            auto PublishFatal(std::exception_ptr Error,const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                if(Context_ && Context_->Fatal)Context_->Fatal->Publish(std::move(Error));
                HoldFailure({Preview::Fault::Code::Blocked},Slot);
            }
            auto FinishClose(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                Retired_.store(true, std::memory_order_release);
                CloseInFlight_.store(false, std::memory_order_release);
                if (Slot) Slot->RetryPending.store(false, std::memory_order_release);
                Carrier_.store({});
                CloseReceipt_.store({});
                ReleaseFailedSlot(Slot);
            }
            auto ReleaseFailedSlot(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
            {
                if (!Slot || !Retired_.load() || IoActive_.load() != 0) return;
                Slot->PhysicallyRetired.store(true, std::memory_order_release);
                if (!Slot->Failed.exchange({})) return;
                if (auto Storage = Slot->Storage.lock()) Storage->Collect();
            }
            std::shared_ptr<CloseState> State_;
            std::atomic<Preview::SharedTransmission> Carrier_;
            Net::any_io_executor Executor_;
            std::shared_ptr<Preview::Executor::ContextOwner> Context_;
            Preview::Executor::ExecutorReclaimer Reclaimer_;
            std::weak_ptr<ClosingSlot> Slot_;
            std::atomic<std::size_t> IoActive_{0};
            std::atomic<std::shared_ptr<Preview::Contract::CarrierCloseReceipt>> CloseReceipt_;
            std::atomic<bool> CloseRequested_{false}, CloseInFlight_{false}, Retired_{false};
        };
        using SharedActivity = std::shared_ptr<Activity>;
        BindingLifetime(Net::any_io_executor Executor, Preview::Foundation::GenerationPin Generation)
            : State_(std::make_shared<CloseState>(std::move(Executor), std::move(Generation))) {}
        ~BindingLifetime() noexcept
        {
            Close();
            for (const auto& Slot : *Entries_.load())
            {
                Slot->BindingOwned.store(false);
                if (auto Entry = Slot->Active.lock()) Entry->ReleaseBinding();
            }
        }
        /** @brief 接管载体与一次预约；预构造失败槽位，构造/登记异常由 RAII 精确退计数。 */
        [[nodiscard]] auto Enter(Preview::SharedTransmission Carrier) -> SharedActivity
        {
            if (!Carrier) return {};
            auto Slot = std::make_shared<ClosingSlot>();
            if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed()) return {};
            if (!State_->Barrier.Enter()) return {};
            Preview::Lifecycle::DrainReservation Reservation(State_->Barrier);
            auto Entry = std::make_shared<Activity>(State_, std::move(Carrier));
            Reservation.Transfer(); Slot->Active = Entry; Entry->Attach(Slot);
            for (;;)
            {
                auto Current = Entries_.load(); auto Next = std::make_shared<Entries>();
                for (const auto& Value : *Current) if (!Value->Active.expired() || Value->Failed.load()) Next->push_back(Value);
                Next->push_back(Slot);
                if (Entries_.compare_exchange_weak(Current, Next)) break;
            }
            if (Closed_.load()) (void)Entry->RequestClose();
            return Entry;
        }
        /** @brief 封止接入并请求实际 owner 关闭；不访问载体状态。 */
        auto Close() noexcept -> void
        {
            if (Closed_.exchange(true)) return;
            State_->Barrier.Seal();
            for (const auto& Slot : *Entries_.load())
                if (auto Entry = Slot->Active.lock()) (void)Entry->RequestClose();
        }
        [[nodiscard]] auto Closed() const noexcept -> bool { return Closed_.load(); }
        /** @brief 只观察已激活载体真实退休及全部 activity 退栈；业务首因仍由 Drain 返回。
         * @details 冷 Enter 后未完成 wrapper 构造的预约不转移载体关闭权；原 caller 仍拥有它。
         *          激活槽仅由底层和 wrapper Drain 成功且 IoActive 归零的 FinishClose 发布终态。
         */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            if (!Closed_.load(std::memory_order_acquire) || State_->Barrier.Active() != 0) return false;
            for (const auto& Slot : *Entries_.load(std::memory_order_acquire))
            {
                if (Slot->Failed.load(std::memory_order_acquire)) return false;
                if (Slot->Activated.load(std::memory_order_acquire) &&
                    !Slot->PhysicallyRetired.load(std::memory_order_acquire)) return false;
            }
            return true;
        }
        /** @brief 等待载体关闭控制、Activity completion 和 wrapper 退栈；失败保留真实 owner。 */
        auto Drain() -> Net::awaitable<std::expected<void,Preview::Fault::Failure>>
        {
            Close();
            if (State_->Context && !State_->Context->CanDispatch())
            {
                State_->Failure.TrySet({Preview::Fault::Code::Blocked});
                State_->Barrier.Block();
            }
            const auto Drained=co_await State_->Barrier.Drain();
            if(!Drained)
            {
                const auto Failure=State_->Failure.Load();
                if (IsRetired()) State_->Generation.reset();
                if(Failure.Failed())co_return std::unexpected(Failure);
                co_return std::unexpected(Drained.error());
            }
            const auto Failure = State_->Failure.Load();
            State_->Generation.reset();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
    private:
        using Entries = std::vector<std::shared_ptr<ClosingSlot>>;
        std::shared_ptr<CloseState> State_;
        std::atomic<bool> Closed_{false};
        std::atomic<std::shared_ptr<const Entries>> Entries_{std::make_shared<const Entries>()};
    };
    inline auto BindingLifetime::ClosingSlot::RequestRetirement() noexcept -> void
    { if (auto Value = Failed.load()) Value->RequestRetirement(); }
    /** @brief 真实传输 owner；异步调用保留 activity/carrier，结果沿正式前门恰好交付一次。 */
    class BoundTransmission final : public Preview::Transmission
    {
        struct IoReservation final
        {
            explicit IoReservation(BindingLifetime::SharedActivity Value) : Activity(std::move(Value)) { Activity->BeginIo(); }
            ~IoReservation() { Activity->EndIo(); }
            BindingLifetime::SharedActivity Activity;
        };
        struct ReadInput final { std::shared_ptr<BoundTransmission> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<BoundTransmission> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<BoundTransmission> Owner; };
        /** @brief 载体已退休时的确定失败；保留协议私有 NotOpen 的原生 category/value。 */
        static auto NotOpen() -> Preview::IoResult
        { return Preview::IoResult{0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::NotOpen))}; }
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                co_return std::tuple{co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->ReadSome(Input.Buffer), Net::deferred)};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                co_return std::tuple{co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->WriteSome(Input.Buffer), Net::deferred)};
            }
        };
        struct ShutdownWork final
        {
            template<class State>
            auto operator()(State Operation, ShutdownInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                const auto Result = co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->WriteShutdown(), Net::deferred);
                if (!Result) co_return std::tuple{Preview::IoResult{0, Result.error()}};
                co_return std::tuple{Preview::IoResult{0, {}}};
            }
        };
    public:
        explicit BoundTransmission(BindingLifetime::SharedActivity Activity)
            : Preview::Transmission(Activity->Executor()), Activity_(std::move(Activity))
        { Activity_->AttachCloseReceipt(CloseReceipt()); }
        ~BoundTransmission() noexcept override { (void)Activity_->RequestClose(); }
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Activity_->Executor(); }
        /** @brief 部分读取；真实 I/O 预约保持到完成交付后才归还。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler)); }
        /** @brief 部分写入；保留底层短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler)); }
        /** @brief 真实写半关闭转交真实载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        { Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler)); }
        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override { return true; }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            (void)Owner();
            return Activity_->RequestClose();
        }
        /** @brief 可重复取消真实载体的挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)Owner();
            auto Value = Activity_->Carrier();
            if (!Value) return {};
            return Value->Cancel();
        }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { if (auto Value = Activity_->Carrier()) Value->SetTimeout(Timeout); }
        [[nodiscard]] auto IsOpen() const -> bool override { auto Value = Activity_->Carrier(); return Value && Value->IsOpen(); }
        /** @brief 仅原 executor 的同步借用；不得跨 co_await 或与最终退休并发，退休后为 null。 */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Activity_->Carrier().get(); }
        /** @brief 仅原 executor 的同步借用；调用者保留外层 owner，禁止跨挂起和并发退休。 */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Activity_->Carrier().get(); }
    private:
        /** @brief 完成交付前的真实 owner 借用；存活由外层 shared_ptr 与本次预约共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<BoundTransmission>
        {
            auto Value = std::static_pointer_cast<BoundTransmission>(Transmission::shared_from_this());
            return Value;
        }
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }
        BindingLifetime::SharedActivity Activity_;
    };
}
