/**
 * @file CanceledRetireTest.cpp
 * @brief 验证已物理退休的 Activity 取消结果与未退休失败的边界。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <barrier>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <thread>
#include <utility>

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>
#include <Prism/Transport/Detail/TransmissionControl.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include "CanceledRetireTestSupport.hpp"

namespace
{

    /** @brief 注入已记录的取消失败，并单独观察最终 Close 是否仍被交付。 */
    class CancelRejectedTransmission final : public Prism::Transmission
    {
    public:
        explicit CancelRejectedTransmission(Net::any_io_executor Executor)
            : Transmission(Executor), Executor_(std::move(Executor)),
              CancelReturned_(std::make_shared<CloseSignal>(Executor_, 1))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        std::size_t CancelCalls{0};
        std::size_t CloseCalls{0};

        /** @brief 等待第一次取消调用返回，使失败预约已被 owner 记录。 */
        auto WaitForCancel() -> Net::awaitable<bool>
        {
            boost::system::error_code Error;
            co_await CancelReturned_->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            co_return !Error;
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls;
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++CancelCalls;
            if (CancelCalls == 1U)
            {
                (void)CancelReturned_->try_send(boost::system::error_code{});
                return std::unexpected(Failure{Prism::Fault::Code::IoError});
            }
            return {};
        }

    private:
        Net::any_io_executor Executor_;
        bool Closed_{false};
        std::shared_ptr<CloseSignal> CancelReturned_;
    };

    auto ExpireTestWatchdog(Net::steady_timer &Watchdog) -> Net::awaitable<bool>
    {
        co_await Watchdog.async_wait(Net::use_awaitable);
        co_return true;
    }

    auto AwaitFirstCancel(Net::io_context &Context,
                          const std::shared_ptr<CancelRejectedTransmission> &Transport)
        -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(Context);
        Watchdog.expires_after(std::chrono::seconds(2));
        const auto Wait = co_await (Transport->WaitForCancel() || ExpireTestWatchdog(Watchdog));
        if (Wait.index() != 0U || !std::get<0>(Wait))
        {
            throw std::runtime_error("cancel control did not return before its watchdog");
        }
    }

    TEST(ActiveTransportsCanceledRetirement, NormalStreamCloseDoesNotCancelCarrier)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Transport = std::make_shared<Prism::PrismMockTransport>(
            Context->Io.get_executor());
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Transport->Activity());
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        auto Stored = Active.StoreInbound(Transport, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();

        const auto Result = Finalize(Context->Io, Active);

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_FALSE(Transport->IsCancelled());
    }

    TEST(ActiveTransportsCanceledRetirement, ExplicitCancelStillCancelsStreamCarrier)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Transport = std::make_shared<Prism::PrismMockTransport>(
            Context->Io.get_executor());
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Transport->Activity());
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        auto Stored = Active.StoreInbound(Transport, *Domain);
        ASSERT_TRUE(Stored);
        auto HeldView = *Stored;
        Stored->reset();
        Active.MarkCancelRequested();

        EXPECT_FALSE(Transport->IsCancelled());
        Context->Io.run();

        EXPECT_TRUE(Transport->IsCancelled());
        EXPECT_FALSE(Transport->IsClosed());
        HeldView.reset();
        Context->Io.restart();

        const auto Result = Finalize(Context->Io, Active);

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_TRUE(Transport->IsCancelled());
    }

    TEST(ActiveTransportsCanceledRetirement,
         AttemptsStreamCloseAfterPriorCancelFailure)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Transport = std::make_shared<CancelRejectedTransmission>(Context->Io.get_executor());
        std::weak_ptr<CancelRejectedTransmission> WeakTransport = Transport;
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Transport->Activity());
        ASSERT_TRUE(Domain);
        ASSERT_TRUE(Transport->Cancel());

        Prism::Testing::RunCoro(Context->Io, AwaitFirstCancel(Context->Io, Transport));

        ASSERT_EQ(Transport->CancelCalls, 1U);
        EXPECT_TRUE(Transport->IsOpen());
        Context->Io.restart();

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
        auto Stored = Active->StoreInbound(Transport, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Active->MarkCancelRequested();

        const auto Finalized = FinalizeAndStopAtResult(Context->Io, *Active);

        ASSERT_FALSE(Finalized);
        EXPECT_EQ(Finalized.error().Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Transport->CancelCalls, 1U);
        EXPECT_EQ(Transport->CloseCalls, 1U);
        EXPECT_FALSE(Transport->IsOpen());
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_FALSE(WeakTransport.expired());

        Transport.reset();
        Active.reset();
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(WeakTransport.expired());
    }

    TEST(ActiveTransportsCanceledRetirement,
         SuccessfulCloseSettlesAlreadyQueuedCancelRetry)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Transport = std::make_shared<CancelRejectedTransmission>(Context->Io.get_executor());
        ASSERT_TRUE(Transport->Cancel());

        Prism::Testing::RunCoro(Context->Io, AwaitFirstCancel(Context->Io, Transport));
        ASSERT_EQ(Transport->CancelCalls, 1U);

        Context->Io.restart();
        const auto Closed = Transport->Close();
        ASSERT_TRUE(Closed);
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_EQ(Transport->CancelCalls, 1U);
        EXPECT_EQ(Transport->CloseCalls, 1U);
        EXPECT_FALSE(Transport->IsOpen());
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    TEST(ActiveTransportsCanceledRetirement,
         ExternalCloseHandsClaimedRetryToItsDelivery)
    {
        using ControlOwner = Prism::Transport::Detail::TransmissionControlOwner;
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(
            Context->Io.get_executor());
        auto Owner = std::make_shared<ControlOwner>(Context->Io.get_executor(), Activity);
        auto Carrier = std::make_shared<CancelRejectedTransmission>(Context->Io.get_executor());
        const auto CloseIndex = ControlOwner::CancelCapacity;
        auto& Command = Owner->Commands[CloseIndex];
        auto Reservation = Activity->TryAcquireCloseControl(Carrier);
        ASSERT_TRUE(Reservation);
        Command.Used.store(true, std::memory_order_release);
        Command.Reservation.emplace(std::move(*Reservation));
        Command.Carrier.store(Carrier, std::memory_order_release);
        Command.AwaitingExternalReceipt.store(true, std::memory_order_release);
        ASSERT_TRUE(Owner->RecordKnownFailure(CloseIndex,
            Failure{Prism::Fault::Code::IoError}));
        Command.Retry.store(ControlOwner::RetryState::InFlight, std::memory_order_release);
        Activity->BeginControlRetry();

        Owner->DeliverExternalClose();

        EXPECT_EQ(Command.Retry.load(std::memory_order_acquire),
            ControlOwner::RetryState::ClosePending);
        EXPECT_EQ(Command.KnownControlFailure.load(std::memory_order_acquire),
            ControlOwner::KnownFailurePhase::Recorded);
        EXPECT_TRUE(Command.Retryable.load(std::memory_order_acquire));
        EXPECT_TRUE(Command.Used.load(std::memory_order_acquire));

        Context->Io.restart();
        const auto Posted = Owner->Reclaimer->Post(
            ControlOwner::Delivery(Owner, CloseIndex, true));
        ASSERT_TRUE(Posted);
        Context->Io.run();
        EXPECT_FALSE(Command.Used.load(std::memory_order_acquire));
        EXPECT_TRUE(Owner->IsRetired());
        EXPECT_FALSE(Owner->Unrecoverable.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), 0U);

        Context->Io.restart();
        std::expected<void, Failure> DrainResult;
        std::exception_ptr Fatal;
        Net::co_spawn(Context->Io, Activity->Drain(),
            [&DrainResult, &Fatal](std::exception_ptr Error,
                std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                DrainResult = std::move(Result);
            });
        Context->Io.run();
        if (Fatal) std::rethrow_exception(Fatal);
        EXPECT_TRUE(DrainResult);
    }

    TEST(ActiveTransportsCanceledRetirement,
         ExternalCloseReleasesClaimedRetryWithoutRetryableWork)
    {
        using ControlOwner = Prism::Transport::Detail::TransmissionControlOwner;
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(
            Context->Io.get_executor());
        auto Owner = std::make_shared<ControlOwner>(Context->Io.get_executor(), Activity);
        auto Carrier = std::make_shared<CancelRejectedTransmission>(Context->Io.get_executor());
        const auto CloseIndex = ControlOwner::CancelCapacity;
        auto& Command = Owner->Commands[CloseIndex];
        auto Reservation = Activity->TryAcquireCloseControl(Carrier);
        ASSERT_TRUE(Reservation);
        Command.Used.store(true, std::memory_order_release);
        Command.Reservation.emplace(std::move(*Reservation));
        Command.Carrier.store(Carrier, std::memory_order_release);
        Command.AwaitingExternalReceipt.store(true, std::memory_order_release);
        const std::size_t CancelIndex = 0U;
        auto CancelReservation = Activity->TryAcquireControl(Carrier);
        ASSERT_TRUE(CancelReservation);
        auto& CancelCommand = Owner->Commands[CancelIndex];
        CancelCommand.Used.store(true, std::memory_order_release);
        CancelCommand.Reservation.emplace(std::move(*CancelReservation));
        CancelCommand.Carrier.store(Carrier, std::memory_order_release);
        ASSERT_TRUE(Owner->RecordKnownFailure(CloseIndex,
            Failure{Prism::Fault::Code::IoError}));
        ASSERT_TRUE(Owner->RecordKnownFailure(CancelIndex,
            Failure{Prism::Fault::Code::IoError}));
        CancelCommand.Retry.store(ControlOwner::RetryState::InFlight,
            std::memory_order_release);
        Activity->BeginControlRetry();

        Command.Retryable.store(false, std::memory_order_release);
        Command.Retry.store(ControlOwner::RetryState::InFlight, std::memory_order_release);
        Activity->BeginControlRetry();

        Owner->DeliverExternalClose();
        EXPECT_TRUE(Command.Used.load(std::memory_order_acquire));
        EXPECT_EQ(Command.Retry.load(std::memory_order_acquire),
            ControlOwner::RetryState::ClosePending);
        EXPECT_EQ(CancelCommand.Retry.load(std::memory_order_acquire),
            ControlOwner::RetryState::ClosePending);

        Owner->CompleteRetryWithoutOperation(CloseIndex);
        ControlOwner::Delivery CancelRetry(Owner, CancelIndex, true);
        CancelRetry.OnQuarantine();
        Context->Io.run();
        EXPECT_FALSE(Command.Used.load(std::memory_order_acquire));
        EXPECT_FALSE(CancelCommand.Used.load(std::memory_order_acquire));
        EXPECT_EQ(CancelCommand.Retry.load(std::memory_order_acquire),
            ControlOwner::RetryState::Idle);
        EXPECT_EQ(Command.Retry.load(std::memory_order_acquire), ControlOwner::RetryState::Idle);
        EXPECT_TRUE(Owner->IsRetired());
        EXPECT_FALSE(Owner->Unrecoverable.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), 0U);

        Context->Io.restart();
        std::expected<void, Failure> DrainResult;
        std::exception_ptr Fatal;
        Net::co_spawn(Context->Io, Activity->Drain(),
            [&DrainResult, &Fatal](std::exception_ptr Error,
                std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                DrainResult = std::move(Result);
            });
        Context->Io.run();
        if (Fatal) std::rethrow_exception(Fatal);
        EXPECT_TRUE(DrainResult);
    }

    TEST(ActiveTransportsCanceledRetirement,
         QuarantinedClaimedRetrySettlesAfterExternalClose)
    {
        using ControlOwner = Prism::Transport::Detail::TransmissionControlOwner;
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(
            Context->Io.get_executor());
        auto Owner = std::make_shared<ControlOwner>(Context->Io.get_executor(), Activity);
        auto Carrier = std::make_shared<CancelRejectedTransmission>(Context->Io.get_executor());
        const auto CloseIndex = ControlOwner::CancelCapacity;
        auto& Command = Owner->Commands[CloseIndex];
        auto Reservation = Activity->TryAcquireCloseControl(Carrier);
        ASSERT_TRUE(Reservation);
        Command.Used.store(true, std::memory_order_release);
        Command.Reservation.emplace(std::move(*Reservation));
        Command.Carrier.store(Carrier, std::memory_order_release);
        Command.AwaitingExternalReceipt.store(true, std::memory_order_release);
        auto& InitialCancelCommand = Owner->Commands[0U];
        auto InitialCancelReservation = Activity->TryAcquireControl(Carrier);
        ASSERT_TRUE(InitialCancelReservation);
        InitialCancelCommand.Used.store(true, std::memory_order_release);
        InitialCancelCommand.Reservation.emplace(std::move(*InitialCancelReservation));
        InitialCancelCommand.Carrier.store(Carrier, std::memory_order_release);
        ASSERT_TRUE(Owner->RecordKnownFailure(CloseIndex,
            Failure{Prism::Fault::Code::IoError}));
        Command.Retry.store(ControlOwner::RetryState::InFlight, std::memory_order_release);
        Activity->BeginControlRetry();
        Owner->DeliverExternalClose();
        Owner->LocalClosed.store(false, std::memory_order_release);
        Owner->Finished.store(false, std::memory_order_release);
        ControlOwner::Delivery InitialCancel(Owner, 0U, false);
        InitialCancel.OnQuarantine();
        EXPECT_FALSE(Owner->LocalClosed.load(std::memory_order_acquire));
        EXPECT_FALSE(InitialCancelCommand.Used.load(std::memory_order_acquire));
        EXPECT_FALSE(Owner->Unrecoverable.load(std::memory_order_acquire));
        Owner->LocalClosed.store(true, std::memory_order_release);
        Owner->Finished.store(true, std::memory_order_release);
        ControlOwner::Delivery Retry(Owner, CloseIndex, true);
        Retry.OnQuarantine();
        Context->Io.run();
        EXPECT_FALSE(Command.Used.load(std::memory_order_acquire));
        EXPECT_EQ(Command.Retry.load(std::memory_order_acquire), ControlOwner::RetryState::Idle);
        EXPECT_TRUE(Owner->IsRetired());
        EXPECT_FALSE(Owner->Unrecoverable.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), 0U);

        Context->Io.restart();
        std::expected<void, Failure> DrainResult;
        std::exception_ptr Fatal;
        Net::co_spawn(Context->Io, Activity->Drain(),
            [&DrainResult, &Fatal](std::exception_ptr Error,
                std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                DrainResult = std::move(Result);
            });
        Context->Io.run();
        if (Fatal) std::rethrow_exception(Fatal);
        EXPECT_TRUE(DrainResult);
    }

    TEST(ActiveTransportsCanceledRetirement,
         ConcurrentDuplicateFailureRecordDrainsAfterSingleResolution)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(
            Context->Io.get_executor());
        using ControlOwner = Prism::Transport::Detail::TransmissionControlOwner;
        auto Owner = std::make_shared<ControlOwner>(Context->Io.get_executor(), Activity);
        constexpr std::size_t Repetitions = 256U;
        std::barrier Gate(3);
        const auto Record = [&]
        {
            for (std::size_t Index = 0U; Index < Repetitions; ++Index)
            {
                Gate.arrive_and_wait();
                (void)Owner->RecordKnownFailure(0U,
                    Failure{Prism::Fault::Code::IoError});
                Gate.arrive_and_wait();
            }
        };
        std::thread First(Record);
        std::thread Second(Record);
        for (std::size_t Index = 0U; Index < Repetitions; ++Index)
        {
            Gate.arrive_and_wait();
            Gate.arrive_and_wait();
            EXPECT_TRUE(Owner->ResolveKnownFailure(0U));
        }
        First.join();
        Second.join();

        Owner->LocalClosed.store(true, std::memory_order_release);
        Activity->RecordCloseDelivered();
        std::expected<void, Failure> DrainResult;
        std::exception_ptr Fatal;
        Net::co_spawn(Context->Io, Activity->Drain(),
            [&DrainResult, &Fatal](std::exception_ptr Error,
                std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                DrainResult = std::move(Result);
            });
        Context->Io.run();
        if (Fatal) std::rethrow_exception(Fatal);
        EXPECT_TRUE(DrainResult);
        Storage->Collect();
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    TEST(ActiveTransportsCanceledRetirement,
         AcceptsCanceledDrainOnlyAfterPhysicalRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<CanceledRetirementState>();
        auto Datagram = std::make_shared<CanceledDrainDatagram>(
            Context->Io.get_executor(), State);
        std::weak_ptr<CanceledDrainDatagram> WeakDatagram = Datagram;
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Datagram->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
        auto Stored = Active->StoreDatagram(Datagram, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Datagram.reset();

        const auto Result = Finalize(Context->Io, *Active);

        ASSERT_TRUE(Result);
        EXPECT_TRUE(State->PhysicallyRetired.load(std::memory_order_acquire));
        EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(State->CloseCalls.load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(State->DrainCalls.load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(Storage->Pending(), 0U);
        Active.reset();
        EXPECT_TRUE(WeakDatagram.expired());
    }

    TEST(ActiveTransportsCanceledRetirement,
         RetainsCanceledDrainOwnerUntilPhysicalRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<CanceledRetirementState>();
        State->RetireOnClose.store(false, std::memory_order_release);
        auto Datagram = std::make_shared<CanceledDrainDatagram>(
            Context->Io.get_executor(), State);
        std::weak_ptr<CanceledDrainDatagram> WeakDatagram = Datagram;
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Datagram->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
        auto Stored = Active->StoreDatagram(Datagram, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Datagram.reset();

        const auto Result = Finalize(Context->Io, *Active);

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Canceled);
        EXPECT_FALSE(State->PhysicallyRetired.load(std::memory_order_acquire));
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_FALSE(WeakDatagram.expired());
        EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(State->DrainCalls.load(std::memory_order_relaxed), 1U);
        const auto CloseCallsBeforeRetry = State->CloseCalls.load(std::memory_order_relaxed);

        State->RetireOnClose.store(true, std::memory_order_release);
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();
        Active.reset();

        EXPECT_TRUE(State->PhysicallyRetired.load(std::memory_order_acquire));
        EXPECT_GE(State->DrainCalls.load(std::memory_order_relaxed), 2U);
        EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 0U);
        EXPECT_GT(State->CloseCalls.load(std::memory_order_relaxed), CloseCallsBeforeRetry);
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(WeakDatagram.expired());
    }

    TEST(ActiveTransportsCanceledRetirement,
         UpgradesInFlightCloseWhenExplicitCancellationArrives)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<CanceledRetirementState>();
        State->CloseEvents = std::make_shared<CloseSignal>(
            Context->Io.get_executor(), 3);
        auto Datagram = std::make_shared<CanceledDrainDatagram>(
            Context->Io.get_executor(), State);
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Datagram->Activity());
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        auto Stored = Active.StoreDatagram(Datagram, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Datagram.reset();

        auto Scenario = [&]() -> Net::awaitable<void>
        {
            const auto Requested = Active.RequestClose();
            EXPECT_TRUE(Requested);
            co_await State->CloseEvents->async_receive(Net::use_awaitable);
            Active.MarkCancelRequested();
            co_await State->CloseEvents->async_receive(Net::use_awaitable);
            const auto Result = co_await Active.Finalize();
            EXPECT_TRUE(Result);
        };
        std::exception_ptr Fatal;
        Net::co_spawn(Context->Io, Scenario(),
            [&Fatal](std::exception_ptr Error) { Fatal = std::move(Error); });
        Context->Io.run();
        if (Fatal) std::rethrow_exception(Fatal);

        EXPECT_GE(State->CancelCalls.load(std::memory_order_relaxed), 1U);
        EXPECT_GE(State->CloseCalls.load(std::memory_order_relaxed), 2U);
        EXPECT_TRUE(State->PhysicallyRetired.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    TEST(ActiveTransportsCanceledRetirement,
         DoesNotNormalizeOtherErrorsAfterPhysicalRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<CanceledRetirementState>();
        State->DrainResultCode.store(Prism::Fault::Code::IoError,
                                     std::memory_order_release);
        auto Datagram = std::make_shared<CanceledDrainDatagram>(
            Context->Io.get_executor(), State);
        std::weak_ptr<CanceledDrainDatagram> WeakDatagram = Datagram;
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Context->Io.get_executor(), Datagram->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
        auto Stored = Active->StoreDatagram(Datagram, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Datagram.reset();

        const auto Result = Finalize(Context->Io, *Active);

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::IoError);
        EXPECT_TRUE(State->PhysicallyRetired.load(std::memory_order_acquire));
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_FALSE(WeakDatagram.expired());

        State->DrainResultCode.store(Prism::Fault::Code::Canceled,
                                     std::memory_order_release);
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();
        Active.reset();

        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(WeakDatagram.expired());
    }

} // namespace
