/** @file ActiveTransports.hpp @brief 载体观察 pin、真实完成源与原 executor 退休。 */
#pragma once
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Contract/Ingress/DatagramSession.hpp>
#include <Preview/Contract/Ingress/MuxSession.hpp>
#include <Preview/Runtime/CarrierDomain.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <array>
#include <functional>
#include <optional>
#include <type_traits>
namespace Preview::Runtime
{
    struct ActiveTransportSnapshot final
    {
        Preview::SharedTransmission Inbound, Outbound;
        std::shared_ptr<Preview::Contract::DatagramSession> Datagram;
        std::shared_ptr<Preview::Contract::MuxSession> Mux;
    };
    /** @brief 每个物理 Identity/Domain 只登记一个 owner；各类型槽只选择可加载的 view。
     * @details Store/Clear 槽切换不封止共享 CarrierActivity；Finalize 才关闭并排空唯一 owner。
     * 生产方必须把返回的别名 owner 放进实际协程/handler，不能另外留下未计数 native owner。
     */
    class ActiveTransports final
    {
        using Failure = Preview::Fault::Failure;
        enum class Kind { Inbound, Outbound, Datagram, Mux };
        enum class OwnerKind { Stream, Datagram, Mux };
        [[nodiscard]] static auto OwnerKindOf(const ActiveTransportSnapshot& Value) noexcept
            -> OwnerKind
        {
            if (Value.Mux) return OwnerKind::Mux;
            if (Value.Datagram) return OwnerKind::Datagram;
            return OwnerKind::Stream;
        }
        struct Resource final : Preview::Executor::ClosingResource, std::enable_shared_from_this<Resource>
        {
            Resource(CarrierDomain Domain, ActiveTransportSnapshot Value)
                : DomainExecutor(Domain.Executor()),
                  Context(Preview::Executor::ContextOwner::Find(DomainExecutor)),
                  Storage(Preview::Executor::ContextOwner::Storage(DomainExecutor)),
                  Reclaimer(std::make_shared<Preview::Executor::ExecutorReclaimer>(Net::make_strand(DomainExecutor))),
                  Activity(Domain.Activity()), OwnerType(OwnerKindOf(Value)),
                  Views(Reclaimer), Completion(Reclaimer), Value(std::move(Value))
            {
                if (Completion.Enter()) CompletionReservation.emplace(Completion);
                if (this->Value.Inbound) Identity = this->Value.Inbound.get();
                if (this->Value.Outbound) Identity = this->Value.Outbound.get();
                if (this->Value.Datagram) Identity = this->Value.Datagram.get();
                if (this->Value.Mux) Identity = this->Value.Mux.get();
            }
            /** @brief 别名控制块的唯一预约；shared view 的副本共享它，最后一份退出才 Leave。 */
            struct ViewPin final
            {
                std::shared_ptr<Resource> Owner;
                Preview::Lifecycle::DrainReservation Reservation;
                ViewPin(std::shared_ptr<Resource> Resource, Preview::Lifecycle::DrainReservation Lease)
                    : Owner(std::move(Resource)), Reservation(std::move(Lease)) {}
            };
            struct Delivery final
            {
                std::shared_ptr<Resource> Owner;
                bool Invoked{false};
                explicit Delivery(std::shared_ptr<Resource> Value) : Owner(std::move(Value)) {}
                Delivery(Delivery&& Other) noexcept : Owner(std::move(Other.Owner)) {}
                ~Delivery()
                {
                    if (!Owner || Invoked) return;
                    Owner->Queued.store(false);
                    Owner->Fail({Preview::Fault::Code::Blocked}, true);
                }
                auto operator()() -> void { Invoked = true; Owner->Queued.store(false); Owner->Execute(); }
            };
            struct RetirementCompletion final
            {
                std::shared_ptr<Resource> Owner;
                bool Invoked{false};
                explicit RetirementCompletion(std::shared_ptr<Resource> Value) : Owner(std::move(Value)) {}
                RetirementCompletion(RetirementCompletion&& Other) noexcept : Owner(std::move(Other.Owner)) {}
                ~RetirementCompletion()
                {
                    if (!Owner) return;
                    Owner->Retiring.store(false);
                    if (!Invoked) Owner->Fail({Preview::Fault::Code::Blocked}, true);
                    else if (Owner->ContentsReleased.load()) Owner->FinishRetirement();
                }
                auto operator()(std::exception_ptr Fatal) -> void
                {
                    Invoked = true;
                    if (Fatal) { Owner->Fail({Preview::Fault::Code::IoError}); std::rethrow_exception(Fatal); }
                }
            };
            /** @brief 在读取 carrier 字段前即成立 view 预约，避免 Seal/clear 并发空窗。 */
            template<class Carrier>
            [[nodiscard]] auto View(Kind Type) -> std::expected<std::shared_ptr<Carrier>, Failure>
            {
                if (!Views.Enter()) return std::unexpected(Failure{Preview::Fault::Code::Canceled});
                Preview::Lifecycle::DrainReservation Reservation(Views);
                std::shared_ptr<Carrier> Native;
                if constexpr (std::is_same_v<Carrier, Preview::Transmission>)
                {
                    if (Type == Kind::Inbound)
                    {
                        if (Value.Inbound) Native = Value.Inbound;
                        else Native = Value.Outbound;
                    }
                    else
                    {
                        if (Value.Outbound) Native = Value.Outbound;
                        else Native = Value.Inbound;
                    }
                }
                else if constexpr (std::is_same_v<Carrier, Preview::Contract::DatagramSession>) Native = Value.Datagram;
                else Native = Value.Mux;
                auto Pin = std::make_shared<ViewPin>(shared_from_this(), std::move(Reservation));
                return std::shared_ptr<Carrier>(std::move(Pin), Native.get());
            }
            /** @brief 验证候选是否指向同一物理 Identity 与真实执行域。 */
            [[nodiscard]] auto Matches(const Resource& Other) const -> bool
            {
                return Identity == Other.Identity && OwnerType == Other.OwnerType &&
                       DomainExecutor == Other.DomainExecutor && Activity == Other.Activity;
            }
            /** @brief 拒绝已关闭、已退休或已有终态失败的 owner view。 */
            [[nodiscard]] auto CanAcceptView() const noexcept -> bool
            {
                return !Closing.load() && !Releasing.load() && !Retired.load() && !Error().Failed();
            }
            auto RequestRetirement() -> void override
            {
                if (ExecutionProhibited.load() || Retired.load() || Queued.exchange(true)) return;
                Storage->Retain(shared_from_this());
                const auto Posted = Reclaimer->Post(Delivery(shared_from_this()));
                if (!Posted) Fail(Posted.error(), true);
            }
            auto Fail(Failure Error, const bool DispatchUnavailable = false) noexcept -> void
            {
                if (DispatchUnavailable) this->DispatchUnavailable.store(true, std::memory_order_release);
                if (FailureState.TrySet(Error)) Completion.Block();
                Storage->Retain(shared_from_this());
            }
            [[nodiscard]] auto Error() const noexcept -> Failure
            {
                return FailureState.Load();
            }
            auto Close() -> void { Closing.store(true); Views.Seal(); RequestRetirement(); }
            /** @brief 新输入被拒绝时必须取消既有操作；与仍供 outer 使用的旧 inner 释放不同。 */
            auto Reject() -> void
            { Closing.store(true); Releasing.store(true); Views.Seal(); RequestRetirement(); }
            /** @brief 保留全部已借出的 view；这里只撤销准入，不声明 carrier 或 I/O 退休。 */
            auto Release() -> void { Releasing.store(true); Views.Seal(); RequestRetirement(); }
            auto Execute() -> void
            {
                if (Retired.load()) return;
                if (Closing.load())
                {
                    const auto Closed = CloseValue();
                    if (!Closed)
                    {
                        const bool DispatchUnavailable = !Reclaimer->CanDispatch();
                        Fail(Closed.error(), DispatchUnavailable);
                        return;
                    }
                }
                if (!Releasing.load() || Retiring.exchange(true)) return;
                RetirementCompletion Completion(shared_from_this());
                try
                {
                    auto Operation = Retire(shared_from_this());
                    Net::co_spawn(Reclaimer->Executor(), std::move(Operation), std::move(Completion));
                }
                catch (const std::system_error &Error)
                {
                    Completion.Invoked = true;
                    Retiring.store(false, std::memory_order_release);
                    Fail(Preview::Fault::FromNative(Error.code()), !Reclaimer->CanDispatch());
                }
                catch (...)
                {
                    Completion.Invoked = true;
                    Retiring.store(false, std::memory_order_release);
                    Fail({Preview::Fault::Code::IoError}, !Reclaimer->CanDispatch());
                }
            }
            static auto Retire(std::shared_ptr<Resource> Self) -> Net::awaitable<void>
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                if (Self->ContentsReleased.load()) co_return;
                if (!Self->Activity) { Self->Fail({Preview::Fault::Code::Blocked}); co_return; }
                auto Borrowers = co_await Self->Views.Drain();
                if (!Borrowers)
                { Self->Fail(Borrowers.error(), !Self->Reclaimer->CanDispatch()); co_return; }
                // 装饰器仍持旧 inner view 时不能 Seal 公共底层；先等这些真正借用退出。
                Self->Activity->Seal();
                auto Operations = co_await Self->Activity->Drain();
                if (!Operations)
                { Self->Fail(Operations.error(), !Self->Reclaimer->CanDispatch()); co_return; }
                Self->Value = {};
                Self->Activity.reset();
                Self->ContentsReleased.store(true);
            }
            /** @brief 实际退休协程与完成通知都退出后，才归还唯一退休预约。 */
            auto FinishRetirement() noexcept -> void
            {
                CompletionReservation.reset();
                Completion.Seal();
                Retired.store(true);
                Storage->Collect();
            }
            auto CloseValue() -> std::expected<void, Failure>
            {
                if (Value.Mux) { Value.Mux->Cancel(); Value.Mux->Close(); }
                if (Value.Datagram) { Value.Datagram->Cancel(); Value.Datagram->Close(); }
                std::expected<void, Failure> Result;
                if (Value.Inbound)
                {
                    const auto Closed = CloseStream(Value.Inbound);
                    if (!Closed) Result = std::unexpected(Closed.error());
                }
                if (Value.Outbound)
                {
                    const auto Closed = CloseStream(Value.Outbound);
                    if (!Closed && Result) Result = std::unexpected(Closed.error());
                }
                return Result;
            }
            auto CloseStream(const Preview::SharedTransmission& Stream)
                -> std::expected<void, Failure>
            {
                const auto Cancel = Stream->Cancel();
                const auto Close = Stream->Close();
                if (!Cancel) return std::unexpected(Cancel.error());
                if (!Close) return std::unexpected(Close.error());
                return {};
            }
            [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired.load(); }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            { return DispatchUnavailable.load(std::memory_order_acquire); }
            const Net::any_io_executor DomainExecutor;
            std::shared_ptr<Preview::Executor::ContextOwner> Context;
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage;
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
            std::shared_ptr<Preview::Contract::CarrierActivity> Activity;
            OwnerKind OwnerType;
            Preview::Lifecycle::DrainBarrier Views, Completion;
            std::optional<Preview::Lifecycle::DrainReservation> CompletionReservation;
            ActiveTransportSnapshot Value;
            const void* Identity{nullptr};
            std::atomic<bool> Queued{false}, Closing{false}, Releasing{false}, Retiring{false}, Retired{false};
            std::atomic<bool> ExecutionProhibited{false}, ContentsReleased{false};
            std::atomic<bool> DispatchUnavailable{false};
            Preview::Fault::FailureState FailureState;
        };
    public:
        /** @brief 按值接管入站；成功返回唯一正式别名 owner，拒绝也保留原 executor 实物。
         * @details 调用者应移入 native owner 并在实际处理字段中采用返回值；Activity 必须由真实 I/O producer 提供。
         */
        [[nodiscard]] auto StoreInbound(Preview::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Preview::SharedTransmission, Failure>
        { return StoreStream(Kind::Inbound, std::move(Value), Domain); }
        /** @brief 出站同入站所有权合同；不得把返回 owner 丢弃后继续使用未计数 native 副本。 */
        [[nodiscard]] auto StoreOutbound(Preview::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Preview::SharedTransmission, Failure>
        { return StoreStream(Kind::Outbound, std::move(Value), Domain); }
        /** @brief 接管协议 Run owner；Domain 在移交前由实际协议 owner 固定，不借用 Session executor 猜测。 */
        [[nodiscard]] auto StoreDatagram(std::shared_ptr<Preview::Contract::DatagramSession> Value, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Preview::Contract::DatagramSession>, Failure>
        { return Store<Preview::Contract::DatagramSession>(Kind::Datagram, {{}, {}, std::move(Value), {}}, Domain); }
        /** @brief 接管 mux 根；真实 Run/子操作 completion 由 Activity 保证，拒绝保留整个根。 */
        [[nodiscard]] auto StoreMux(std::shared_ptr<Preview::Contract::MuxSession> Value, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Preview::Contract::MuxSession>, Failure>
        { return Store<Preview::Contract::MuxSession>(Kind::Mux, {{}, {}, {}, std::move(Value)}, Domain); }
        /** @brief 移除指定类型的当前 view 选择；物理 owner 仍由唯一资源槽持有至 Finalize。 */
        [[nodiscard]] auto ClearInbound() -> std::expected<void, Failure> { return Clear(Kind::Inbound); }
        [[nodiscard]] auto ClearOutbound() -> std::expected<void, Failure> { return Clear(Kind::Outbound); }
        [[nodiscard]] auto ClearDatagram() -> std::expected<void, Failure> { return Clear(Kind::Datagram); }
        [[nodiscard]] auto ClearMux() -> std::expected<void, Failure> { return Clear(Kind::Mux); }
        /** @brief 创建拥有 view 预约的别名 owner；空返回表示当前槽不存在或已封止。 */
        [[nodiscard]] auto LoadInbound() const -> Preview::SharedTransmission { return LoadView<Preview::Transmission>(Kind::Inbound); }
        [[nodiscard]] auto LoadOutbound() const -> Preview::SharedTransmission { return LoadView<Preview::Transmission>(Kind::Outbound); }
        /** @brief 快照的每个非空 shared 字段都独立 pin 原资源/context，须保活至实际 completion 退栈。 */
        [[nodiscard]] auto Load() const -> ActiveTransportSnapshot
        {
            return {LoadInbound(), LoadOutbound(), LoadView<Preview::Contract::DatagramSession>(Kind::Datagram),
                LoadView<Preview::Contract::MuxSession>(Kind::Mux)};
        }
        /** @brief 封止新 view，按 mux、datagram、stream 的 owner 依赖顺序请求关闭。 */
        [[nodiscard]] auto RequestClose() -> std::expected<void, Failure>
        {
            Closing_.store(true);
            if (HasOwner(OwnerKind::Mux)) return RequestCloseOwners(OwnerKind::Mux);
            if (HasOwner(OwnerKind::Datagram)) return RequestCloseOwners(OwnerKind::Datagram);
            return RequestCloseOwners(OwnerKind::Stream);
        }
        /** @brief 按根 owner 到 stream owner 顺序逐层关闭并排空。
         * @details 调用方须先停止 Store producer 和 carrier 操作；真实 I/O 完成只从 Activity::Drain 得到。
         * mux/datagram 完成前不关闭下层 stream，以免取消先打断仍由根 owner 管理的操作。
         */
        [[nodiscard]] auto Finalize() -> Net::awaitable<std::expected<void, Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            auto Result = RequestClose();
            const auto MuxResult = co_await FinalizeOwners(OwnerKind::Mux);
            if (!MuxResult) co_return std::unexpected(MuxResult.error());
            const auto DatagramResult = co_await FinalizeOwners(OwnerKind::Datagram);
            if (!DatagramResult) co_return std::unexpected(DatagramResult.error());
            const auto StreamResult = co_await FinalizeOwners(OwnerKind::Stream);
            if (!StreamResult) co_return std::unexpected(StreamResult.error());
            if (!Result) co_return Result;
            for (auto& Current : Current_) Current.store({});
            for (auto& Slot : Slots_) Slot.store({});
            co_return std::expected<void, Failure>{};
        }
    private:
        [[nodiscard]] auto HasOwner(OwnerKind Type) const -> bool
        {
            for (const auto& Slot : Slots_)
            {
                auto Value = Slot.load();
                if (Value && Value->OwnerType == Type) return true;
            }
            return false;
        }
        [[nodiscard]] auto RequestCloseOwners(OwnerKind Type) -> std::expected<void, Failure>
        {
            std::expected<void, Failure> Result;
            for (auto& Slot : Slots_)
            {
                auto Value = Slot.load();
                if (!Value || Value->OwnerType != Type) continue;
                Value->Close();
                if (Value->Error().Failed() && Result)
                    Result = std::unexpected(Value->Error());
            }
            return Result;
        }
        [[nodiscard]] auto FinalizeOwners(OwnerKind Type)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            for (auto& Slot : Slots_)
            {
                auto Value = Slot.load();
                if (!Value || Value->OwnerType != Type) continue;
                Value->Close();
            }
            for (auto& Slot : Slots_)
            {
                auto Value = Slot.load();
                if (!Value || Value->OwnerType != Type) continue;
                Value->Release();
            }
            std::expected<void, Failure> Result;
            for (auto& Slot : Slots_)
            {
                auto Value = Slot.load();
                if (!Value || Value->OwnerType != Type) continue;
                auto Retired = co_await Value->Completion.Drain();
                if (!Retired && Result)
                {
                    auto Error = Value->Error();
                    if (Error.Succeeded()) Error = Retired.error();
                    Result = std::unexpected(Error);
                }
            }
            co_return Result;
        }
        [[nodiscard]] auto Clear(Kind Type) -> std::expected<void, Failure>
        {
            auto Previous = Current_[static_cast<std::size_t>(Type)].exchange({});
            if (!Previous) return {};
            if (Previous->Error().Failed()) return std::unexpected(Previous->Error());
            return {};
        }
        template<class Carrier>
        [[nodiscard]] auto LoadView(Kind Type) const -> std::shared_ptr<Carrier>
        {
            auto Value = Current_[static_cast<std::size_t>(Type)].load();
            if (!Value) return {};
            auto Result = Value->View<Carrier>(Type);
            if (!Result) return {};
            return std::move(*Result);
        }
        /** @brief 取得输入物理载体提供的真实操作完成源。 */
        [[nodiscard]] static auto ActivityOf(const ActiveTransportSnapshot& Value)
            -> std::shared_ptr<Preview::Contract::CarrierActivity>
        {
            if (Value.Inbound) return Value.Inbound->Activity();
            if (Value.Outbound) return Value.Outbound->Activity();
            if (Value.Datagram) return Value.Datagram->Activity();
            if (Value.Mux) return Value.Mux->Activity();
            return {};
        }
        /** @brief 读取输入 carrier 自身执行域；协议根使用其真实 Activity executor。 */
        [[nodiscard]] static auto CarrierExecutorOf(
            const ActiveTransportSnapshot& Value,
            const std::shared_ptr<Preview::Contract::CarrierActivity>& Activity)
            -> Net::any_io_executor
        {
            if (Value.Inbound) return Value.Inbound->Executor();
            if (Value.Outbound) return Value.Outbound->Executor();
            if (Activity) return Activity->Executor();
            return {};
        }
        /** @brief 在不能证明输入执行域时保留原 owner，但禁止调度或触碰 native carrier。 */
        static auto RetainRejectedInputOn(
            const CarrierDomain& Domain,
            ActiveTransportSnapshot Input,
            const Failure Error) -> void
        {
            auto Held = std::make_shared<Resource>(Domain, std::move(Input));
            Held->ExecutionProhibited.store(true);
            Held->Storage->Retain(Held);
            Held->Fail(Error);
        }
        /** @brief 优先在输入 owner 自己的 context 固定拒绝资源。 */
        static auto RetainRejectedInput(
            const CarrierDomain& Domain,
            ActiveTransportSnapshot Input,
            const Failure Error) -> void
        {
            const auto Activity = ActivityOf(Input);
            const auto Executor = CarrierExecutorOf(Input, Activity);
            const auto HoldingDomain = CarrierDomain::Create(Executor, {});
            if (HoldingDomain)
            {
                RetainRejectedInputOn(*HoldingDomain, std::move(Input), Error);
                return;
            }
            RetainRejectedInputOn(Domain, std::move(Input), Error);
        }
        [[nodiscard]] auto StoreStream(Kind Type, Preview::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Preview::SharedTransmission, Failure>
        {
            ActiveTransportSnapshot Input;
            if (Type == Kind::Inbound) Input.Inbound = Value; else Input.Outbound = Value;
            return Store<Preview::Transmission>(Type, std::move(Input), Domain);
        }
        template<class Carrier>
        [[nodiscard]] auto Store(Kind Type, ActiveTransportSnapshot Input, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Carrier>, Failure>
        {
            if (!Input.Inbound && !Input.Outbound && !Input.Datagram && !Input.Mux)
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            const auto NativeActivity = ActivityOf(Input);
            if (!NativeActivity)
            {
                RetainRejectedInput(Domain, std::move(Input),
                    Failure{Preview::Fault::Code::InvalidArgument});
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto InputExecutor = CarrierExecutorOf(Input, NativeActivity);
            if (!InputExecutor || InputExecutor != NativeActivity->Executor())
            {
                RetainRejectedInput(Domain, std::move(Input),
                    Failure{Preview::Fault::Code::InvalidArgument});
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto NativeDomain = CarrierDomain::Create(
                NativeActivity->Executor(), NativeActivity);
            if (!NativeDomain)
            {
                RetainRejectedInput(Domain, std::move(Input), NativeDomain.error());
                return std::unexpected(NativeDomain.error());
            }
            if (Domain.Executor() != NativeDomain->Executor() ||
                Domain.Activity() != NativeActivity)
            {
                auto Held = std::make_shared<Resource>(*NativeDomain, std::move(Input));
                Held->Storage->Retain(Held);
                Held->Reject();
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            auto Candidate = std::make_shared<Resource>(Domain, std::move(Input));
            const auto Owner = ReserveResource(Candidate, Domain);
            if (!Owner)
            {
                if (Owner.error().Code == Preview::Fault::Code::ResourceUnavailable)
                {
                    Candidate->Storage->Retain(Candidate);
                    Candidate->Reject();
                }
                return std::unexpected(Owner.error());
            }
            if (*Owner == Candidate) Candidate->Storage->Retain(Candidate);
            auto View = (*Owner)->View<Carrier>(Type);
            if (!View) return std::unexpected(View.error());
            Current_[static_cast<std::size_t>(Type)].store(*Owner);
            if (Closing_.load())
            {
                (*Owner)->Reject();
                return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            }
            return std::move(*View);
        }
        /** @brief 复用同 Identity/Domain 的 owner；新物理 owner 受固定槽预算约束。 */
        [[nodiscard]] auto ReserveResource(const std::shared_ptr<Resource>& Candidate,
                                           const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Resource>, Failure>
        {
            const auto First = std::hash<const void*>{}(Candidate->Identity) % Slots_.size();
            for (std::size_t Offset = 0; Offset < Slots_.size(); ++Offset)
            {
                auto& Slot = Slots_[(First + Offset) % Slots_.size()];
                auto Existing = Slot.load();
                while (true)
                {
                    if (Existing && Existing->Identity == Candidate->Identity)
                    {
                        if (!Existing->Matches(*Candidate))
                            return std::unexpected(
                                Failure{Preview::Fault::Code::InvalidArgument});
                        if (!Existing->CanAcceptView())
                        {
                            const auto Error = Existing->Error();
                            if (Error.Failed()) return std::unexpected(Error);
                            return std::unexpected(Failure{Preview::Fault::Code::Canceled});
                        }
                        return Existing;
                    }
                    if (Existing && !Existing->IsRetired()) break;
                    if (Slot.compare_exchange_weak(Existing, Candidate,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                        return Candidate;
                }
            }
            return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
        }
        std::atomic<bool> Closing_{false};
        /** @brief 64 个唯一物理 owner 的 admission budget；同 Identity/Domain 的 Store 复用原槽。 */
        std::array<std::atomic<std::shared_ptr<Resource>>, 64> Slots_;
        std::array<std::atomic<std::shared_ptr<Resource>>, 4> Current_;
    };
}
