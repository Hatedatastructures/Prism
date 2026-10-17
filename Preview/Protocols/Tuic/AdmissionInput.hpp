/** @file AdmissionInput.hpp @brief TUIC 有界输入预约、原 executor 交付与失败 owner。 */
#pragma once
#include <Preview/Protocols/Tuic/Admission.hpp>

namespace Preview::Tuic
{
    inline ConnectionAdmission::InputReservation::InputReservation(
        Preview::Lifecycle::DrainBarrier &Barrier, std::atomic<std::size_t> *Count)
        : Barrier_(std::in_place, Barrier), Count_(Count)
    {
    }

    inline ConnectionAdmission::InputReservation::InputReservation(InputReservation &&Other) noexcept
        : Barrier_(std::move(Other.Barrier_)), Count_(std::exchange(Other.Count_, nullptr))
    {
    }

    inline auto ConnectionAdmission::InputReservation::operator=(InputReservation &&Other) noexcept
        -> InputReservation &
    {
        if (this != &Other)
        {
            Reset();
            if (Other.Barrier_)
            {
                Barrier_.emplace(std::move(*Other.Barrier_));
                Other.Barrier_.reset();
            }
            Count_ = std::exchange(Other.Count_, nullptr);
        }
        return *this;
    }

    inline ConnectionAdmission::InputReservation::~InputReservation() noexcept
    {
        Reset();
    }

    inline auto ConnectionAdmission::InputReservation::Reset() noexcept -> void
    {
        Barrier_.reset();
        if (Count_)
        {
            Count_->fetch_sub(1U, std::memory_order_acq_rel);
            Count_ = nullptr;
        }
    }

    class ConnectionAdmission::InputDelivery final : public Preview::Executor::ClosingResource,
        public std::enable_shared_from_this<ConnectionAdmission::InputDelivery>
    {
        friend class ConnectionAdmission;
        enum class DeliveryState : std::uint8_t
        {
            Created,
            Queued,
            Retryable,
            Running,
            Failed,
            Quarantined,
            Completed
        };
        static constexpr std::size_t NoRetrySlot = MaxRetryableInputDeliveries;
        static constexpr std::size_t RegisteringRetrySlot = MaxRetryableInputDeliveries + 1U;

        struct InputDeliveryAction final
        {
            std::shared_ptr<InputDelivery> Delivery;
            auto operator()() noexcept -> void { Delivery->Deliver(); }
            auto OnQuarantine() noexcept -> void { Delivery->OnQuarantine(); }
        };

    public:
        InputDelivery(std::shared_ptr<ConnectionAdmission> Owner, InputEvent Event)
            : Owner_(std::move(Owner)), Event_(std::move(Event)), Storage_(Owner_->Storage_),
              Identity_(Owner_->Options_.Metadata.TaskIdentity) {}

        /** @brief 首次提交；只有 Reclaimer 明确拒收后才登记可复投状态。 */
        [[nodiscard]] auto SubmitInitial() -> std::expected<void, Preview::Fault::Failure>
        {
            return Submit(DeliveryState::Created);
        }

        /** @brief 只重投仍处于明确拒收状态的原始事件。 */
        [[nodiscard]] auto RetryRejected() -> std::expected<void, Preview::Fault::Failure>
        {
            if (State_.load(std::memory_order_acquire) != DeliveryState::Retryable) return {};
            if (!IsCurrentEvent())
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            const auto OwnerFailure = Owner_->Failure_.Load();
            if (OwnerFailure.Failed() && Event_.Kind != InputKind::Close &&
                Event_.Kind != InputKind::NativeClosed)
                return std::unexpected(OwnerFailure);
            return Submit(DeliveryState::Retryable);
        }

        /** @brief 由实际原 executor 处理已接受输入；失败与未知结果保留原 reservation。 */
        auto Deliver() noexcept -> void
        {
            auto Expected = DeliveryState::Queued;
            if (!State_.compare_exchange_strong(
                    Expected, DeliveryState::Running, std::memory_order_acq_rel))
                return;
            if (!IsCurrentEvent())
            {
                Fail({Preview::Fault::Code::Blocked});
                return;
            }
            if (Event_.Kind != InputKind::Close && Event_.Kind != InputKind::NativeClosed &&
                (Owner_->NativeClosed_.load(std::memory_order_acquire) ||
                    Owner_->CloseQueued_.load(std::memory_order_acquire)))
                Owner_->CloseOnExecutor();
            const auto OwnerFailure = Owner_->Failure_.Load();
            if (OwnerFailure.Failed() && Event_.Kind != InputKind::Close &&
                Event_.Kind != InputKind::NativeClosed)
            {
                Fail(OwnerFailure);
                return;
            }
            if (!Event_.Reservation)
            {
                Fail({Preview::Fault::Code::Blocked});
                return;
            }
            try
            {
                if (!DeliverEvent()) return;
                Event_.Carrier.reset();
                Event_.StreamProvider.reset();
                Event_.Provider.reset();
                Event_.Exporter = {};
                Event_.Reservation.reset();
                Owner_->MaybeFinishClose();
                State_.store(DeliveryState::Completed, std::memory_order_release);
                Owner_->RemoveRetryableInputDelivery(*this);
                if (Storage_) Storage_->Collect();
            }
            catch (...)
            {
                Owner_->RecordFatal(std::current_exception());
                Fail({Preview::Fault::Code::Blocked});
            }
        }

        /** @brief 已接受动作被隔离后标为未知终态；绝不把它当作可复投拒收。 */
        auto OnQuarantine() noexcept -> void
        {
            auto Expected = DeliveryState::Queued;
            if (!State_.compare_exchange_strong(
                    Expected, DeliveryState::Quarantined, std::memory_order_acq_rel))
                return;
            RetainFailure({Preview::Fault::Code::Blocked});
        }

        auto RequestRetirement() -> void override
        {
            (void)RetryRejected();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_.load(std::memory_order_acquire) == DeliveryState::Completed;
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            const auto State = State_.load(std::memory_order_acquire);
            return State == DeliveryState::Failed || State == DeliveryState::Quarantined ||
                (State == DeliveryState::Retryable && Owner_->Reclaimer_->IsQuarantined());
        }

    private:
        [[nodiscard]] auto Submit(DeliveryState ExpectedState)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!IsCurrentEvent())
            {
                if (ExpectedState == DeliveryState::Created)
                    Fail({Preview::Fault::Code::Blocked});
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            auto Expected = ExpectedState;
            if (!State_.compare_exchange_strong(
                    Expected, DeliveryState::Queued, std::memory_order_acq_rel))
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            if (ExpectedState == DeliveryState::Retryable) ClearRetryIndexMissing();
            std::expected<void, Preview::Fault::Failure> Posted;
            try
            {
                Posted = Owner_->Reclaimer_->Post(InputDeliveryAction{shared_from_this()});
            }
            catch (...)
            {
                Posted = std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if (Posted) return {};
            Expected = DeliveryState::Queued;
            if (State_.compare_exchange_strong(
                    Expected, DeliveryState::Retryable, std::memory_order_acq_rel))
            {
                const auto Indexed =
                    Owner_->TrackRetryableInputDelivery(shared_from_this());
                if (Storage_) Storage_->Retain(shared_from_this());
                if (!Indexed)
                    return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::ResourceUnavailable,
                        std::make_error_code(std::errc::no_buffer_space)});
            }
            return std::unexpected(Posted.error());
        }

        [[nodiscard]] auto IsCurrentEvent() const noexcept -> bool
        {
            if (Identity_ != Owner_->Options_.Metadata.TaskIdentity) return false;
            switch (Event_.Kind)
            {
            case InputKind::Close:
                return Owner_->CloseQueued_.load(std::memory_order_acquire);
            case InputKind::NativeClosed:
                return Owner_->NativeClosed_.load(std::memory_order_acquire);
            case InputKind::Exporter:
                return Owner_->ExporterQueued_.load(std::memory_order_acquire);
            case InputKind::Datagram:
                return Owner_->DatagramInput_.load(std::memory_order_acquire) == Event_.Provider;
            case InputKind::Authentication:
            case InputKind::Stream:
                return true;
            }
            return false;
        }

        [[nodiscard]] auto DeliverEvent() -> bool
        {
            switch (Event_.Kind)
            {
            case InputKind::Authentication:
                if (Event_.StreamProvider && !Event_.Carrier)
                    Event_.Carrier = std::make_shared<Preview::Quic::StreamAdapter>(
                        Event_.StreamProvider->Executor(), Event_.StreamProvider);
                Owner_->AdmitAuthentication(Event_.Carrier, std::move(*Event_.Reservation));
                break;
            case InputKind::Exporter:
                if (!Owner_->Closed_ && !Owner_->ExporterReady_)
                {
                    Owner_->ExporterReady_ = true;
                    Owner_->Exporter_ = std::move(Event_.Exporter);
                    Owner_->StartAuthentication();
                }
                break;
            case InputKind::Stream:
                if (Event_.StreamProvider && !Event_.Carrier)
                    Event_.Carrier = std::make_shared<Preview::Quic::StreamAdapter>(
                        Event_.StreamProvider->Executor(), Event_.StreamProvider);
                Owner_->AdmitStream(Event_.Carrier, std::move(*Event_.Reservation));
                break;
            case InputKind::Datagram:
                if (Event_.Provider && Event_.Provider->IsClosed())
                {
                    if (!Event_.Carrier)
                        Event_.Carrier =
                            std::make_shared<Preview::Quic::DatagramAdapter>(Event_.Provider);
                    Owner_->QueueRejectedTransmission(
                        Event_.Carrier, std::move(*Event_.Reservation));
                }
                else
                    Owner_->AdmitDatagram(Event_.Provider, Event_.Carrier,
                        std::move(*Event_.Reservation));
                break;
            case InputKind::Close:
            case InputKind::NativeClosed:
                Owner_->CloseOnExecutor();
                break;
            }
            return true;
        }

        auto Fail(Preview::Fault::Failure Reason) noexcept -> void
        {
            State_.store(DeliveryState::Failed, std::memory_order_release);
            RetainFailure(Reason);
        }

        auto RetainFailure(Preview::Fault::Failure Reason) noexcept -> void
        {
            if (Reason.Succeeded()) Reason = {Preview::Fault::Code::Blocked};
            Owner_->RecordFailure(Reason);
            Owner_->Inputs_.Block();
            if (Storage_) Storage_->Retain(shared_from_this());
        }

        auto MarkRetryIndexMissing() noexcept -> void
        {
            bool Missing = false;
            if (RetryIndexMissing_.compare_exchange_strong(
                    Missing, true, std::memory_order_acq_rel))
                Owner_->UnindexedRetryCount_.fetch_add(1U, std::memory_order_acq_rel);
            if (State_.load(std::memory_order_acquire) != DeliveryState::Retryable)
                ClearRetryIndexMissing();
        }

        auto ClearRetryIndexMissing() noexcept -> void
        {
            if (RetryIndexMissing_.exchange(false, std::memory_order_acq_rel))
                Owner_->UnindexedRetryCount_.fetch_sub(1U, std::memory_order_acq_rel);
        }
        std::shared_ptr<ConnectionAdmission> Owner_;
        InputEvent Event_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        Preview::Lifecycle::TaskIdentity Identity_{};
        std::atomic<DeliveryState> State_{DeliveryState::Created};
        std::atomic<std::size_t> RetrySlot_{NoRetrySlot};
        std::atomic<bool> RetryIndexMissing_{false};
    };

    inline auto ConnectionAdmission::ReserveInput() noexcept
        -> std::optional<InputReservation>
    {
        auto Count = PendingInputCount_.load(std::memory_order_acquire);
        while (Count < MaxPendingInputs)
        {
            if (PendingInputCount_.compare_exchange_weak(
                    Count, Count + 1U, std::memory_order_acq_rel))
            {
                if (Inputs_.Enter()) return InputReservation{Inputs_, &PendingInputCount_};
                PendingInputCount_.fetch_sub(1U, std::memory_order_acq_rel);
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    /** @brief 在建立 adapter 前取得有界预约，再投递到唯一 admission strand。 */
    inline auto ConnectionAdmission::DispatchInput(InputEvent Event)
        -> std::expected<void, Preview::Fault::Failure>
    {
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed() && Event.Kind != InputKind::Close &&
            Event.Kind != InputKind::NativeClosed)
            return std::unexpected(ExistingFailure);
        if (Event.Kind == InputKind::Close || Event.Kind == InputKind::NativeClosed)
        {
            if (Event.Kind == InputKind::Close &&
                CloseQueued_.exchange(true, std::memory_order_acq_rel)) return {};
            if (!Inputs_.Enter())
            {
                if(Inputs_.IsSealed())return {};
                auto Failure=Failure_.Load();
                if(!Failure.Failed())
                {
                    Failure={Preview::Fault::Code::Blocked};
                    RecordFailure(Failure);
                    Inputs_.Block();
                    Failure=Failure_.Load();
                }
                return std::unexpected(Failure);
            }
            Event.Reservation.emplace(Inputs_,nullptr);
        }
        else
        {
            auto Reservation = ReserveInput();
            if (!Reservation)
            {
                auto Failure = Failure_.Load();
                if (!Failure.Failed())
                {
                    auto Code = Preview::Fault::Code::ResourceUnavailable;
                    if (Inputs_.IsSealed()) Code = Preview::Fault::Code::Canceled;
                    Failure = {Code};
                    RecordFailure(Failure);
                    Inputs_.Block();
                    Failure = Failure_.Load();
                }
                return std::unexpected(Failure);
            }
            Event.Reservation.emplace(std::move(*Reservation));
        }

        try
        {
            auto Delivery = std::make_shared<InputDelivery>(shared_from_this(), std::move(Event));
            Storage_->Retain(Delivery);
            return Delivery->SubmitInitial();
        }
        catch (const std::bad_alloc &)
        {
            const Preview::Fault::Failure Failure{
                Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)};
            RecordFailure(Failure);
            StoreFailedInput(std::move(Event));
            Inputs_.Block();
            return std::unexpected(Failure_.Load());
        }
        catch (...)
        {
            const auto Exception = std::current_exception();
            RecordFatal(Exception);
            StoreFailedInput(std::move(Event));
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
    }

    inline auto ConnectionAdmission::OnUnidirectional(
        Preview::Quic::SharedStreamProvider AuthStream)
        -> std::expected<void, Preview::Fault::Failure>
    {
        if (!AuthStream) return {};
        InputEvent Event;
        Event.Kind = InputKind::Authentication;
        Event.StreamProvider = std::move(AuthStream);
        return DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::OnExporter(KeyingMaterialExporter Exporter)
        -> std::expected<void, Preview::Fault::Failure>
    {
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
        if (ExporterQueued_.exchange(true, std::memory_order_acq_rel)) return {};
        InputEvent Event;
        Event.Kind = InputKind::Exporter;
        Event.Exporter = std::move(Exporter);
        return DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::OnBidirectional(
        Preview::Quic::SharedStreamProvider Stream)
        -> std::expected<void, Preview::Fault::Failure>
    {
        if (!Stream) return {};
        InputEvent Event;
        Event.Kind = InputKind::Stream;
        Event.StreamProvider = std::move(Stream);
        return DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::OnDatagram(
        Preview::Quic::SharedDatagramProvider Provider)
        -> std::expected<void, Preview::Fault::Failure>
    {
        if (!Provider) return {};
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
        auto Existing = DatagramInput_.load(std::memory_order_acquire);
        if (Existing == Provider) return {};
        if (Existing || !DatagramInput_.compare_exchange_strong(
                Existing, Provider, std::memory_order_acq_rel))
        {
            if (Existing == Provider) return {};
            const Preview::Fault::Failure Failure{Preview::Fault::Code::ResourceUnavailable};
            RecordFailure(Failure);
            Inputs_.Block();
            return std::unexpected(Failure_.Load());
        }
        InputEvent Event;
        Event.Kind = InputKind::Datagram;
        Event.Provider = std::move(Provider);
        return DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::Close() -> void
    {
        InputEvent Event;
        Event.Kind = InputKind::Close;
        (void)DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::OnClosed() -> void
    {
        NativeClosed_.store(true, std::memory_order_release);
        if (NativeClosedQueued_.exchange(true, std::memory_order_acq_rel)) return;
        InputEvent Event;
        Event.Kind = InputKind::NativeClosed;
        (void)DispatchInput(std::move(Event));
    }

    inline auto ConnectionAdmission::RecordFailure(Preview::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure = {Preview::Fault::Code::Blocked};
        if (Failure_.TrySet(Failure))
        {
            if(Executor_.running_in_this_thread())
            {
                const auto CloseResult=RequestOwnerClose();
                if(!CloseResult)return;
            }
            else
            {
                Close();
            }
        }
    }

    inline auto ConnectionAdmission::RequestOwnerClose() noexcept
        -> std::expected<void, Preview::Fault::Failure>
    {
        if(CloseOwnerAccepted_)return {};
        if(OwnerCloseFailure_)
        {
            if(!RetryOwnerClose_)return std::unexpected(*OwnerCloseFailure_);
            RetryOwnerClose_=false;
        }
        if(!Options_.CloseOwner)
        {
            CloseOwnerAccepted_=true;
            OwnerCloseFailure_.reset();
            return {};
        }
        try
        {
            const auto Result=Options_.CloseOwner();
            if(!Result)
            {
                if(!OwnerCloseFailure_)OwnerCloseFailure_=Result.error();
                return std::unexpected(*OwnerCloseFailure_);
            }
            CloseOwnerAccepted_=true;
            OwnerCloseFailure_.reset();
            return {};
        }
        catch (...)
        {
            if(Fatal_)Fatal_->Publish(std::current_exception());
            const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
            if(!OwnerCloseFailure_)OwnerCloseFailure_=Failure;
            return std::unexpected(*OwnerCloseFailure_);
        }
    }

    inline auto ConnectionAdmission::StoreFailedInput(InputEvent Event) noexcept -> void
    {
        const auto Index = FailedInputCount_.fetch_add(1U, std::memory_order_acq_rel);
        if (Index >= FailedInputCapacity_)
        {
            RecordFailure({Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::no_buffer_space)});
            Inputs_.Block();
            return;
        }
        FailedInputs_[Index] = std::move(Event);
    }

    inline auto ConnectionAdmission::RetainFailedInput(InputEvent Event) noexcept -> void
    {
        RecordFailure({Preview::Fault::Code::Blocked});
        StoreFailedInput(std::move(Event));
        Inputs_.Block();
    }

    inline auto ConnectionAdmission::RecordFatal(std::exception_ptr Error) noexcept -> void
    {
        if (Fatal_) Fatal_->Publish(std::move(Error));
        RecordFailure({Preview::Fault::Code::Blocked});
        Inputs_.Block();
        Children_.Block();
    }

    inline auto ConnectionAdmission::RetainFailedCarrier(Preview::SharedTransmission Carrier) noexcept -> void
    {
        if (!Carrier) return;
        InputEvent Event;
        Event.Carrier = std::move(Carrier);
        RetainFailedInput(std::move(Event));
    }


} // namespace Preview::Tuic
