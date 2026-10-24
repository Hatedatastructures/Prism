/** @file UdpAssocRetirement.cpp @brief SOCKS5 UDP 关联的首因与原生失败记录。 */
#include <Prism/Protocols/Socks5/UdpAssocRetirement.hpp>

#include <boost/system/system_error.hpp>

#include <new>
#include <utility>

namespace Prism::Socks5
{

    UdpAssocRetirement::DrainWaiter::DrainWaiter(
        std::atomic<std::size_t> &Count)
        : Count_(Count)
    {
        Count_.fetch_add(1, std::memory_order_acq_rel);
    }

    UdpAssocRetirement::DrainWaiter::~DrainWaiter()
    {
        Count_.fetch_sub(1, std::memory_order_acq_rel);
    }

    UdpAssocRetirement::Operation::Operation(Operation &&Other) noexcept
        : Owner_(std::move(Other.Owner_)), Reservation_(std::move(Other.Reservation_))
    {
    }

    UdpAssocRetirement::Operation::~Operation()
    {
        Complete();
    }

    auto UdpAssocRetirement::Operation::Complete() noexcept -> void
    {
        if (!Reservation_) return;
        Reservation_->Complete();
        Reservation_.reset();
        Owner_.reset();
    }

    UdpAssocRetirement::Operation::Operation(
        std::shared_ptr<UdpAssocRetirement> Owner,
        Prism::Protocols::ProtocolActivity::Reservation Reservation)
        : Owner_(std::move(Owner)), Reservation_(std::move(Reservation))
    {
    }

    UdpAssocRetirement::Delivery::Delivery(
        std::shared_ptr<UdpAssocRetirement> Value)
        : Owner(std::move(Value))
    {
    }

    UdpAssocRetirement::Delivery::Delivery(Delivery &&Other) noexcept
        : Owner(std::move(Other.Owner)), Invoked(Other.Invoked)
    {
    }

    UdpAssocRetirement::Delivery::~Delivery()
    {
        if (Owner && !Invoked)
        {
            Owner->Scheduled_.store(false, std::memory_order_release);
            Owner->RecordFailure({Prism::Fault::Code::Blocked});
        }
    }

    auto UdpAssocRetirement::Delivery::operator()() -> void
    {
        Invoked = true;
        Owner->StartRetirement();
    }

    auto UdpAssocRetirement::CloseSocket(Socket &Value) noexcept -> Failure
    {
        boost::system::error_code ErrorCode;
        if (!Value.is_open()) return {};
        Value.cancel(ErrorCode);
        Failure Result;
        if (ErrorCode)
            Result = Prism::Fault::FromNative(static_cast<std::error_code>(ErrorCode));
        ErrorCode.clear();
        Value.close(ErrorCode);
        if (ErrorCode)
            PreserveFailure(Result, Prism::Fault::FromNative(
                static_cast<std::error_code>(ErrorCode)));
        return Result;
    }

    auto UdpAssocRetirement::PreserveFailure(
        Failure &Primary, const Failure &Next) noexcept -> void
    {
        if (!Primary.Failed()) Primary = Next;
        else if (!Primary.Native && Next.Native) Primary.Native = Next.Native;
    }

    auto UdpAssocRetirement::RecordFailure(const Failure Value) noexcept -> void
    {
        if (Value.Succeeded())
        {
            return;
        }
        (void)FailureState_.TrySet(Value);
        if (Value.Native && !NativeFailure_.load(std::memory_order_acquire))
        {
            try
            {
                auto Native = std::make_shared<const std::error_code>(Value.Native);
                std::shared_ptr<const std::error_code> Empty;
                (void)NativeFailure_.compare_exchange_strong(
                    Empty, std::move(Native), std::memory_order_acq_rel);
            }
            catch (...)
            {
            }
        }
        Storage_->Retain(shared_from_this());
        Notify();
    }

    auto UdpAssocRetirement::RecordNative(
        const boost::system::error_code Native) noexcept -> void
    {
        if (!Native)
        {
            return;
        }
        RecordFailure(Prism::Fault::FromNative(static_cast<std::error_code>(Native)));
    }

    auto UdpAssocRetirement::RecordException(
        const std::exception_ptr Exception) noexcept -> Failure
    {
        const auto Value = FailureFromException(Exception);
        RecordFailure(Value);
        return Value;
    }

    auto UdpAssocRetirement::LoadFailure() const noexcept -> Failure
    {
        auto Value = FailureState_.Load();
        if (!Value.Native)
        {
            if (const auto Native = NativeFailure_.load(std::memory_order_acquire))
            {
                Value.Native = *Native;
            }
        }
        return Value;
    }

    [[nodiscard]] auto UdpAssocRetirement::IsDispatchUnavailable() const noexcept -> bool
    {
        if (Retired_.load(std::memory_order_acquire)) return false;
        if (Context_ && !Context_->CanDispatch()) return true;
        return !Reclaimer_->CanDispatch();
    }

    auto UdpAssocRetirement::FailureFromException(
        const std::exception_ptr Exception) noexcept -> Failure
    {
        try
        {
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
        }
        catch (const boost::system::system_error& ErrorValue)
        {
            const auto Native = static_cast<std::error_code>(ErrorValue.code());
            return {Prism::Fault::ToCode(Native), Native};
        }
        catch (const std::system_error& ErrorValue)
        {
            return {Prism::Fault::ToCode(ErrorValue.code()), ErrorValue.code()};
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }


    UdpAssocRetirement::UdpAssocRetirement(Net::any_io_executor Executor,
                       std::shared_ptr<Conn<>> Tcp)
        : Executor_(std::move(Executor)),
          Context_(Prism::Executor::ContextOwner::Find(Executor_)),
          Storage_(Prism::Executor::ContextOwner::Storage(Executor_)),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_)),
          Operations_(Executor_),
          Changes_(Executor_, 1),
          Ingress_(Executor_),
          Egress_(Executor_),
          Tcp_(std::move(Tcp))
    {
        if (Tcp_)
        {
            for (Prism::Transmission *Layer = Tcp_.get(); Layer; Layer = Layer->NextLayer())
            {
                auto Activity = Layer->Activity();
                if (!Activity)
                {
                    (void)FailureState_.TrySet(
                        Failure{Prism::Fault::Code::InvalidArgument});
                    continue;
                }
                TcpActivities_.push_back(std::move(Activity));
            }
        }
    }

    [[nodiscard]] auto UdpAssocRetirement::BeginOperation() -> std::expected<Operation, Failure>
    {
        if (CloseRequested_.load(std::memory_order_acquire))
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        auto Reservation = Operations_.TryBegin();
        if (!Reservation) return std::unexpected(Reservation.error());
        if (CloseRequested_.load(std::memory_order_acquire))
        {
            Reservation->Complete();
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        return Operation(shared_from_this(), std::move(*Reservation));
    }

    [[nodiscard]] auto UdpAssocRetirement::BeginRun() -> std::expected<Operation, Failure>
    {
        if (RunStarted_.exchange(true, std::memory_order_acq_rel))
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        return BeginOperation();
    }

    [[nodiscard]] auto UdpAssocRetirement::Executor() const -> Net::any_io_executor
    {
        return Executor_;
    }

    auto UdpAssocRetirement::Seal() noexcept -> void
    {
        Operations_.Seal();
    }

    [[nodiscard]] auto UdpAssocRetirement::Drain()
        -> Net::awaitable<Result>
    {
        return AwaitRetirement(true);
    }

    [[nodiscard]] auto UdpAssocRetirement::RunDrain() -> Net::awaitable<Result>
    {
        return AwaitRetirement(false);
    }

    auto UdpAssocRetirement::SetEgressProtocol(Net::ip::udp Protocol) noexcept -> void
    {
        EgressProtocol_ = Protocol;
    }

    [[nodiscard]] auto UdpAssocRetirement::ReadControlEndpoints() const
        -> std::expected<ControlEndpointSnapshot, Failure>
    {
        if (!Tcp_) return std::unexpected(Failure{Prism::Fault::Code::IoError});
        const auto Underlying = Tcp_->Underlying();
        if (!Underlying) return std::unexpected(Failure{Prism::Fault::Code::IoError});
        auto *Reliable = Underlying->lowest_layer<Prism::Transport::Reliable>();
        if (!Reliable || !Reliable->IsOpen())
            return std::unexpected(Failure{Prism::Fault::Code::IoError});
        boost::system::error_code LocalError;
        boost::system::error_code PeerError;
        const auto Local = Reliable->NativeSocket().local_endpoint(LocalError);
        if (LocalError)
            return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(LocalError)));
        const auto Peer = Reliable->NativeSocket().remote_endpoint(PeerError);
        if (PeerError)
            return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(PeerError)));
        return ControlEndpointSnapshot{Local, Peer};
    }

    auto UdpAssocRetirement::CloseEgress() noexcept -> Failure
    {
        const auto Result = CloseSocket(Egress_);
        if (!Egress_.is_open()) EgressProtocol_.reset();
        if (Result.Failed()) RecordFailure(Result);
        return Result;
    }

    auto UdpAssocRetirement::PinOwner(std::shared_ptr<void> OwnerPin, Completion Callback) noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        if (OwnerPin) OwnerPin_.store(std::move(OwnerPin), std::memory_order_release);
        if (Callback)
        {
            try
            {
                Callback_.store(std::make_shared<Completion>(std::move(Callback)),
                                std::memory_order_release);
            }
            catch (...)
            {
                RecordFailure({Prism::Fault::Code::Blocked});
            }
        }
        if (Retired_.load(std::memory_order_acquire))
        {
            OwnerPin_.store({}, std::memory_order_release);
            Callback_.store({}, std::memory_order_release);
        }
    }

    auto UdpAssocRetirement::RequestClose(std::shared_ptr<void> OwnerPin, Completion Callback) noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        PinOwner(std::move(OwnerPin), std::move(Callback));
        if (Retired_.load(std::memory_order_acquire)) return;
        CloseRequested_.store(true, std::memory_order_release);
        Operations_.Seal();
        Storage_->Retain(shared_from_this());
        ScheduleRetirement();
    }

    auto UdpAssocRetirement::RequestCancel(std::shared_ptr<void> OwnerPin, Completion Callback) noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        Cancelled_.store(true, std::memory_order_release);
        RequestClose(std::move(OwnerPin), std::move(Callback));
    }

    auto UdpAssocRetirement::RequestRetirement() -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        if (!CloseRequested_.load(std::memory_order_acquire))
        {
            RequestClose(OwnerPin_.load(std::memory_order_acquire), LoadCompletion());
            return;
        }
        ScheduleRetirement();
    }

    auto UdpAssocRetirement::ScheduleRetirement() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire) ||
            Scheduled_.exchange(true, std::memory_order_acq_rel))
            return;
        try
        {
            /** @brief 拒绝时由未执行 Delivery 的析构唯一复位 Scheduled_ 并记录 Blocked。 */
            (void)Reclaimer_->Post(Delivery(shared_from_this()));
        }
        catch (...)
        {
            Scheduled_.store(false, std::memory_order_release);
            RecordFailure(FailureFromException(std::current_exception()));
        }
    }

    auto UdpAssocRetirement::StartRetirement() noexcept -> void
    {
        const auto Self = shared_from_this();
        try
        {
            Net::co_spawn(
                Executor_, RetireOnExecutor(),
                [Self](std::exception_ptr Exception, Result RetiredResult)
                {
                    Self->CompleteRetirement(std::move(Exception), std::move(RetiredResult));
                });
        }
        catch (...)
        {
            Scheduled_.store(false, std::memory_order_release);
            RecordFailure(FailureFromException(std::current_exception()));
        }
    }

    [[nodiscard]] auto UdpAssocRetirement::RetireOnExecutor() -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Cancellation_.emit(Net::cancellation_type::all);

        auto FirstFailure = CloseSocket(Ingress_);
        PreserveFailure(FirstFailure, CloseSocket(Egress_));
        if (Tcp_)
        {
            const auto Cancel = Tcp_->Cancel();
            if (!Cancel) PreserveFailure(FirstFailure, Cancel.error());
            const auto Close = Tcp_->Close();
            if (!Close) PreserveFailure(FirstFailure, Close.error());
        }

        if (FirstFailure.Failed())
        {
            RecordFailure(FirstFailure);
            co_return std::unexpected(LoadFailure());
        }

        for (const auto &Activity : TcpActivities_)
        {
            Activity->Seal();
            const auto Drained = co_await Activity->Drain();
            if (!Drained &&
                (Drained.error().Code != Prism::Fault::Code::Canceled ||
                 !Activity->IsRetired()))
            {
                RecordFailure(Drained.error());
                co_return std::unexpected(LoadFailure());
            }
        }

        const auto OperationsDrained = co_await Operations_.Drain();
        if (!OperationsDrained &&
            (OperationsDrained.error().Code != Prism::Fault::Code::Canceled ||
             !Operations_.IsRetired()))
        {
            RecordFailure(OperationsDrained.error());
            co_return std::unexpected(LoadFailure());
        }

        TcpActivities_.clear();
        Tcp_.reset();
        if (const auto Callback = Callback_.load(std::memory_order_acquire))
        {
            try { (*Callback)(); }
            catch (...) { RecordFailure({Prism::Fault::Code::IoError}); }
        }
        OwnerPin_.store({}, std::memory_order_release);
        Retired_.store(true, std::memory_order_release);
        Notify();
        Storage_->Collect();
        co_return Result{};
    }

    auto UdpAssocRetirement::CompleteRetirement(std::exception_ptr Exception, Result RetiredResult) noexcept -> void
    {
        if (Exception) RecordFailure(FailureFromException(Exception));
        else if (!RetiredResult) RecordFailure(RetiredResult.error());
        Scheduled_.store(false, std::memory_order_release);
        if (Retired_.load(std::memory_order_acquire)) Storage_->Collect();
        Notify();
    }

    auto UdpAssocRetirement::Notify() noexcept -> void
    {
        (void)Changes_.try_send(boost::system::error_code{});
    }

    [[nodiscard]] auto UdpAssocRetirement::AwaitRetirement(const bool ConsumeFailure)
        -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        if (Retired_.load(std::memory_order_acquire) &&
            !Scheduled_.load(std::memory_order_acquire))
            co_return CompletedResult(ConsumeFailure);
        RequestClose(OwnerPin_.load(std::memory_order_acquire), LoadCompletion());
        for (;;)
        {
            if (Retired_.load(std::memory_order_acquire) &&
                !Scheduled_.load(std::memory_order_acquire))
                co_return CompletedResult(ConsumeFailure);
            const auto FailureValue = LoadFailure();
            if (FailureValue.Failed() && (!ConsumeFailure ||
                !Scheduled_.load(std::memory_order_acquire)))
            {
                if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                WakeWaiter();
                co_return std::unexpected(FailureValue);
            }
            if (!Reclaimer_->CanDispatch())
            {
                RecordFailure({Prism::Fault::Code::Blocked});
                if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                WakeWaiter();
                co_return std::unexpected(LoadFailure());
            }
            boost::system::error_code ErrorCode;
            {
                DrainWaiter Waiter(DrainWaiters_);
                co_await Changes_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
            if (ErrorCode)
            {
                RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode)));
                if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                WakeWaiter();
                co_return std::unexpected(LoadFailure());
            }
        }
    }

    [[nodiscard]] auto UdpAssocRetirement::CompletedResult(const bool ConsumeFailure) noexcept -> Result
    {
        const auto FailureValue = LoadFailure();
        WakeWaiter();
        if (FailureValue.Failed() &&
            (!ConsumeFailure || !FailureObserved_.exchange(true, std::memory_order_acq_rel)))
            return std::unexpected(FailureValue);
        return {};
    }

    auto UdpAssocRetirement::WakeWaiter() noexcept -> void
    {
        if (DrainWaiters_.load(std::memory_order_acquire) != 0) Notify();
    }

} // namespace Prism::Socks5
