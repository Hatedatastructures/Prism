/** @file ActiveTransports.cpp @brief carrier view 与真实退休 owner 实现。 */
#include <Prism/Runtime/ActiveTransports.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>

#include <functional>
#include <memory>
#include <system_error>
#include <type_traits>
#include <utility>

namespace Prism::Runtime
{
    template<class Carrier>
    auto ActiveTransports::Resource::View(ActiveTransports::Kind Type)
        -> std::expected<std::shared_ptr<Carrier>, ActiveTransports::Failure>
    {
        if (!Views.Enter()) return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        Prism::Lifecycle::DrainReservation Reservation(Views);
        std::shared_ptr<Carrier> Native;
        if constexpr (std::is_same_v<Carrier, Prism::Transmission>)
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
        else if constexpr (std::is_same_v<Carrier, Prism::Contract::DatagramSession>) Native = Value.Datagram;
        else Native = Value.Mux;
        auto Pin = std::make_shared<ViewPin>(shared_from_this(), std::move(Reservation));
        return std::shared_ptr<Carrier>(std::move(Pin), Native.get());
    }

    template<class Carrier>
    auto ActiveTransports::LoadView(Kind Type) const -> std::shared_ptr<Carrier>
    {
        auto Value = Current_[static_cast<std::size_t>(Type)].load();
        if (!Value) return {};
        auto Result = Value->View<Carrier>(Type);
        if (!Result) return {};
        return std::move(*Result);
    }

    template<class Carrier>
    auto ActiveTransports::Store(
        Kind Type,
        ActiveTransportSnapshot Input,
        const CarrierDomain& Domain)
        -> std::expected<std::shared_ptr<Carrier>, Failure>
    {
        if (!Input.Inbound && !Input.Outbound && !Input.Datagram && !Input.Mux)
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        const auto NativeActivity = ActivityOf(Input);
        if (!NativeActivity)
        {
            RetainRejectedInput(Domain, std::move(Input),
                Failure{Prism::Fault::Code::InvalidArgument});
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto InputExecutor = CarrierExecutorOf(Input, NativeActivity);
        if (!InputExecutor || InputExecutor != NativeActivity->Executor())
        {
            RetainRejectedInput(Domain, std::move(Input),
                Failure{Prism::Fault::Code::InvalidArgument});
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
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
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Candidate = std::make_shared<Resource>(Domain, std::move(Input));
        const auto Owner = ReserveResource(Candidate, Domain);
        if (!Owner)
        {
            if (Owner.error().Code == Prism::Fault::Code::ResourceUnavailable)
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
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        return std::move(*View);
    }

    auto ActiveTransports::OwnerKindOf(const ActiveTransportSnapshot& Value) noexcept
        -> OwnerKind
    {
        if (Value.Mux) return OwnerKind::Mux;
        if (Value.Datagram) return OwnerKind::Datagram;
        return OwnerKind::Stream;
    }

    ActiveTransports::Resource::Resource(
        CarrierDomain Domain,
        ActiveTransportSnapshot Value)
        : DomainExecutor(Domain.Executor()),
          Context(Prism::Executor::ContextOwner::Find(DomainExecutor)),
          Storage(Prism::Executor::ContextOwner::Storage(DomainExecutor)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              Net::make_strand(DomainExecutor))),
          Activity(Domain.Activity()),
          OwnerType(ActiveTransports::OwnerKindOf(Value)),
          Views(Reclaimer),
          Completion(Reclaimer),
          Value(std::move(Value))
    {
        if (Completion.Enter()) CompletionReservation.emplace(Completion);
        if (this->Value.Inbound) Identity = this->Value.Inbound.get();
        if (this->Value.Outbound) Identity = this->Value.Outbound.get();
        if (this->Value.Datagram) Identity = this->Value.Datagram.get();
        if (this->Value.Mux) Identity = this->Value.Mux.get();
    }

    ActiveTransports::Resource::Delivery::Delivery(std::shared_ptr<Resource> Value)
        : Owner(std::move(Value))
    {
    }

    ActiveTransports::Resource::Delivery::Delivery(Delivery&& Other) noexcept
        : Owner(std::move(Other.Owner))
    {
    }

    ActiveTransports::Resource::Delivery::~Delivery()
    {
        if (!Owner || Invoked) return;
        Owner->Queued.store(false);
        Owner->Fail({Prism::Fault::Code::Blocked}, true);
    }

    auto ActiveTransports::Resource::Delivery::operator()() -> void
    {
        Invoked = true;
        Owner->Queued.store(false);
        Owner->Execute();
    }

    ActiveTransports::Resource::RetirementCompletion::RetirementCompletion(
        std::shared_ptr<Resource> Value)
        : Owner(std::move(Value))
    {
    }

    ActiveTransports::Resource::RetirementCompletion::RetirementCompletion(
        RetirementCompletion&& Other) noexcept
        : Owner(std::move(Other.Owner))
    {
    }

    ActiveTransports::Resource::RetirementCompletion::~RetirementCompletion()
    {
        if (!Owner) return;
        Owner->Retiring.store(false);
        if (!Invoked) Owner->Fail({Prism::Fault::Code::Blocked}, true);
        else Owner->FinishRetirement();
    }

    auto ActiveTransports::Resource::RetirementCompletion::operator()(
        std::exception_ptr Fatal) -> void
    {
        Invoked = true;
        if (Fatal)
        {
            Owner->Fail({Prism::Fault::Code::IoError});
            std::rethrow_exception(Fatal);
        }
    }

    auto ActiveTransports::Resource::Matches(const Resource& Other) const -> bool
    {
        return Identity == Other.Identity && OwnerType == Other.OwnerType &&
               DomainExecutor == Other.DomainExecutor && Activity == Other.Activity;
    }

    auto ActiveTransports::Resource::CanAcceptView() const noexcept -> bool
    {
        return !Closing.load() && !Releasing.load() && !Retired.load() && !Error().Failed();
    }

    auto ActiveTransports::Resource::RequestRetirement() -> void
    {
        if (ExecutionProhibited.load() || Retired.load() || Queued.exchange(true)) return;
        Storage->Retain(shared_from_this());
        const auto Posted = Reclaimer->Post(Delivery(shared_from_this()));
        if (!Posted) Fail(Posted.error(), true);
    }

    auto ActiveTransports::Resource::Fail(
        Failure Error,
        const bool DispatchUnavailable) noexcept -> void
    {
        if (DispatchUnavailable) this->DispatchUnavailable.store(true, std::memory_order_release);
        (void)FailureState.TrySet(Error);
        Completion.Block();
        Storage->Retain(shared_from_this());
    }

    auto ActiveTransports::Resource::Error() const noexcept -> Failure
    {
        return FailureState.Load();
    }

    auto ActiveTransports::Resource::Close() -> void
    {
        Closing.store(true);
        Views.Seal();
        RequestRetirement();
    }

    auto ActiveTransports::Resource::MarkCancelRequested() noexcept -> void
    {
        CancelRequested.store(true, std::memory_order_release);
        RequestRetirement();
    }

    auto ActiveTransports::Resource::Reject() -> void
    {
        Rejecting.store(true, std::memory_order_release);
        Closing.store(true);
        Releasing.store(true);
        Views.Seal();
        RequestRetirement();
    }

    auto ActiveTransports::Resource::Release() -> void
    {
        Releasing.store(true);
        Views.Seal();
        RequestRetirement();
    }

    auto ActiveTransports::Resource::Execute() -> void
    {
        if (Retired.load()) return;
        if (Closing.load())
        {
            const auto Closed = CloseValue();
            if (!Closed)
            {
                Fail(Closed.error(), !Reclaimer->CanDispatch());
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
        catch (const std::system_error& Error)
        {
            Completion.Invoked = true;
            Retiring.store(false, std::memory_order_release);
            Fail(Prism::Fault::FromNative(Error.code()), !Reclaimer->CanDispatch());
        }
        catch (...)
        {
            Completion.Invoked = true;
            Retiring.store(false, std::memory_order_release);
            Fail({Prism::Fault::Code::IoError}, !Reclaimer->CanDispatch());
        }
    }

    auto ActiveTransports::Resource::Retire(std::shared_ptr<Resource> Self)
        -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (Self->ContentsReleased.load()) co_return;
        if (!Self->Activity)
        {
            Self->Fail({Prism::Fault::Code::Blocked});
            co_return;
        }
        auto Borrowers = co_await Self->Views.Drain();
        if (!Borrowers)
        {
            Self->Fail(Borrowers.error(), !Self->Reclaimer->CanDispatch());
            co_return;
        }
        // 装饰器仍持旧 inner view 时不能 Seal 公共底层；先等这些真正借用退出。
        Self->Activity->Seal();
        auto Operations = co_await Self->Activity->Drain();
        if (!Operations && Self->Closing.load() &&
            Operations.error().Code == Prism::Fault::Code::IoError)
        {
            // 关闭已交付后，取消失败只保留为控制回执，不再阻断 carrier 物理退休。
            Self->Value = {};
            Self->Activity.reset();
            Self->ContentsReleased.store(true);
            co_return;
        }
        // 仅在独立退休回执已成立时接受取消；其余失败继续保留实物。
        if (!Operations &&
            (Operations.error().Code != Prism::Fault::Code::Canceled ||
             !Self->Activity->IsRetired()))
        {
            if (Operations.error().Code != Prism::Fault::Code::Canceled &&
                !Self->Activity->IsRetired())
            {
                Self->CancelRequested.store(true, std::memory_order_release);
                if (Self->Value.Mux) Self->Value.Mux->Cancel();
                if (Self->Value.Datagram) Self->Value.Datagram->Cancel();
                if (Self->Value.Inbound) (void)Self->Value.Inbound->Cancel();
                if (Self->Value.Outbound) (void)Self->Value.Outbound->Cancel();
            }
            Self->Fail(Operations.error(), !Self->Reclaimer->CanDispatch());
            co_return;
        }
        Self->Value = {};
        Self->Activity.reset();
        Self->ContentsReleased.store(true);
    }

    auto ActiveTransports::Resource::FinishRetirement() noexcept -> void
    {
        CompletionReservation.reset();
        Completion.Seal();
        Retired.store(true);
        Storage->Collect();
    }

    auto ActiveTransports::Resource::CloseValue() -> std::expected<void, Failure>
    {
        if (Value.Mux)
        {
            if (Rejecting.load(std::memory_order_acquire) ||
                CancelRequested.load(std::memory_order_acquire))
                Value.Mux->Cancel();
            Value.Mux->Close();
        }
        if (Value.Datagram)
        {
            if (Rejecting.load(std::memory_order_acquire) ||
                CancelRequested.load(std::memory_order_acquire))
                Value.Datagram->Cancel();
            Value.Datagram->Close();
        }
        std::expected<void, Failure> Result;
        if (Value.Inbound)
        {
            const auto CancelInFlight = Rejecting.load(std::memory_order_acquire) ||
                CancelRequested.load(std::memory_order_acquire);
            const auto Closed = CloseStream(Value.Inbound, CancelInFlight);
            if (!Closed) Result = std::unexpected(Closed.error());
        }
        if (Value.Outbound)
        {
            const auto CancelInFlight = Rejecting.load(std::memory_order_acquire) ||
                CancelRequested.load(std::memory_order_acquire);
            const auto Closed = CloseStream(Value.Outbound, CancelInFlight);
            if (!Closed && Result) Result = std::unexpected(Closed.error());
        }
        return Result;
    }

    auto ActiveTransports::Resource::CloseStream(
        const Prism::SharedTransmission& Stream,
        const bool CancelInFlight) -> std::expected<void, Failure>
    {
        if (CancelInFlight)
        {
            const auto Cancel = Stream->Cancel();
            if (!Cancel)
            {
                (void)FailureState.TrySet(Cancel.error());
                Storage->Retain(shared_from_this());
            }
        }
        const auto Close = Stream->Close();
        if (!Close) return std::unexpected(Close.error());
        return {};
    }

    auto ActiveTransports::Resource::IsRetired() const noexcept -> bool
    {
        return Retired.load();
    }

    auto ActiveTransports::Resource::IsDispatchUnavailable() const noexcept -> bool
    {
        return DispatchUnavailable.load(std::memory_order_acquire);
    }

    auto ActiveTransports::StoreInbound(
        Prism::SharedTransmission Value,
        const CarrierDomain& Domain) -> std::expected<Prism::SharedTransmission, Failure>
    {
        return StoreStream(Kind::Inbound, std::move(Value), Domain);
    }

    auto ActiveTransports::StoreOutbound(
        Prism::SharedTransmission Value,
        const CarrierDomain& Domain) -> std::expected<Prism::SharedTransmission, Failure>
    {
        return StoreStream(Kind::Outbound, std::move(Value), Domain);
    }

    auto ActiveTransports::StoreDatagram(
        std::shared_ptr<Prism::Contract::DatagramSession> Value,
        const CarrierDomain& Domain)
        -> std::expected<std::shared_ptr<Prism::Contract::DatagramSession>, Failure>
    {
        return Store<Prism::Contract::DatagramSession>(
            Kind::Datagram, {{}, {}, std::move(Value), {}}, Domain);
    }

    auto ActiveTransports::StoreMux(
        std::shared_ptr<Prism::Contract::MuxSession> Value,
        const CarrierDomain& Domain)
        -> std::expected<std::shared_ptr<Prism::Contract::MuxSession>, Failure>
    {
        return Store<Prism::Contract::MuxSession>(Kind::Mux, {{}, {}, {}, std::move(Value)}, Domain);
    }

    auto ActiveTransports::ClearInbound() -> std::expected<void, Failure>
    {
        return Clear(Kind::Inbound);
    }

    auto ActiveTransports::ClearOutbound() -> std::expected<void, Failure>
    {
        return Clear(Kind::Outbound);
    }

    auto ActiveTransports::ClearDatagram() -> std::expected<void, Failure>
    {
        return Clear(Kind::Datagram);
    }

    auto ActiveTransports::ClearMux() -> std::expected<void, Failure>
    {
        return Clear(Kind::Mux);
    }

    auto ActiveTransports::LoadInbound() const -> Prism::SharedTransmission
    {
        return LoadView<Prism::Transmission>(Kind::Inbound);
    }

    auto ActiveTransports::LoadOutbound() const -> Prism::SharedTransmission
    {
        return LoadView<Prism::Transmission>(Kind::Outbound);
    }

    auto ActiveTransports::Load() const -> ActiveTransportSnapshot
    {
        return {LoadInbound(), LoadOutbound(),
            LoadView<Prism::Contract::DatagramSession>(Kind::Datagram),
            LoadView<Prism::Contract::MuxSession>(Kind::Mux)};
    }

    auto ActiveTransports::RequestClose() -> std::expected<void, Failure>
    {
        Closing_.store(true);
        if (HasOwner(OwnerKind::Mux)) return RequestCloseOwners(OwnerKind::Mux);
        if (HasOwner(OwnerKind::Datagram)) return RequestCloseOwners(OwnerKind::Datagram);
        return RequestCloseOwners(OwnerKind::Stream);
    }

    auto ActiveTransports::MarkCancelRequested() noexcept -> void
    {
        Closing_.store(true, std::memory_order_release);
        for (auto& Slot : Slots_)
        {
            if (auto Value = Slot.load()) Value->MarkCancelRequested();
        }
    }

    auto ActiveTransports::Finalize()
        -> Net::awaitable<std::expected<void, Failure>>
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

    auto ActiveTransports::HasOwner(const OwnerKind Type) const -> bool
    {
        for (const auto& Slot : Slots_)
        {
            auto Value = Slot.load();
            if (Value && Value->OwnerType == Type) return true;
        }
        return false;
    }

    auto ActiveTransports::RequestCloseOwners(const OwnerKind Type)
        -> std::expected<void, Failure>
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

    auto ActiveTransports::FinalizeOwners(const OwnerKind Type)
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
            auto Error = Value->Error();
            if (!Retired && Error.Succeeded()) Error = Retired.error();
            if (Error.Code == Prism::Fault::Code::Canceled && Value->IsRetired()) Error = {};
            if (Error.Failed() && Result) Result = std::unexpected(Error);
        }
        co_return Result;
    }

    auto ActiveTransports::Clear(const Kind Type) -> std::expected<void, Failure>
    {
        auto Previous = Current_[static_cast<std::size_t>(Type)].exchange({});
        if (!Previous) return {};
        if (Previous->Error().Failed()) return std::unexpected(Previous->Error());
        return {};
    }

    auto ActiveTransports::ActivityOf(const ActiveTransportSnapshot& Value)
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        if (Value.Inbound) return Value.Inbound->Activity();
        if (Value.Outbound) return Value.Outbound->Activity();
        if (Value.Datagram) return Value.Datagram->Activity();
        if (Value.Mux) return Value.Mux->Activity();
        return {};
    }

    auto ActiveTransports::CarrierExecutorOf(
        const ActiveTransportSnapshot& Value,
        const std::shared_ptr<Prism::Contract::CarrierActivity>& Activity)
        -> Net::any_io_executor
    {
        if (Value.Inbound) return Value.Inbound->Executor();
        if (Value.Outbound) return Value.Outbound->Executor();
        if (Activity) return Activity->Executor();
        return {};
    }

    auto ActiveTransports::RetainRejectedInputOn(
        const CarrierDomain& Domain,
        ActiveTransportSnapshot Input,
        const Failure Error) -> void
    {
        auto Held = std::make_shared<Resource>(Domain, std::move(Input));
        Held->ExecutionProhibited.store(true);
        Held->Storage->Retain(Held);
        Held->Fail(Error);
    }

    auto ActiveTransports::RetainRejectedInput(
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

    auto ActiveTransports::StoreStream(
        const Kind Type,
        Prism::SharedTransmission Value,
        const CarrierDomain& Domain) -> std::expected<Prism::SharedTransmission, Failure>
    {
        ActiveTransportSnapshot Input;
        if (Type == Kind::Inbound) Input.Inbound = Value;
        else Input.Outbound = Value;
        return Store<Prism::Transmission>(Type, std::move(Input), Domain);
    }

    auto ActiveTransports::ReserveResource(
        const std::shared_ptr<Resource>& Candidate,
        const CarrierDomain& Domain) -> std::expected<std::shared_ptr<Resource>, Failure>
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
                        return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
                    if (!Existing->CanAcceptView())
                    {
                        const auto Error = Existing->Error();
                        if (Error.Failed()) return std::unexpected(Error);
                        return std::unexpected(Failure{Prism::Fault::Code::Canceled});
                    }
                    return Existing;
                }
                if (Existing && !Existing->IsRetired()) break;
                if (Slot.compare_exchange_weak(Existing, Candidate,
                    std::memory_order_acq_rel, std::memory_order_acquire))
                    return Candidate;
            }
        }
        return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
    }
}
