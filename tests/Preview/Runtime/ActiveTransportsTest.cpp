#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <Preview/Contract/Ingress/DatagramSession.hpp>
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <Preview/Runtime/ActiveTransports.hpp>
#include <Preview/Runtime/CarrierDomain.hpp>
#include <Preview/Runtime/ListenerConnectionDrain.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Failure = Preview::Fault::Failure;
    using ByteChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto MakeReleaseChannel(Net::any_io_executor Executor) -> std::shared_ptr<ByteChannel>
    {
        return std::make_shared<ByteChannel>(std::move(Executor), 1);
    }

    /** @brief 仅用于验证 Store 拒绝 Executor 与真实 Activity 不一致的 carrier。 */
    class MismatchedExecutorTransport final : public Preview::Transmission
    {
    public:
        MismatchedExecutorTransport(Net::any_io_executor ActivityExecutor,
                                    Net::any_io_executor ReportedExecutor)
            : Preview::Transmission(std::move(ActivityExecutor)),
              ReportedExecutor_(std::move(ReportedExecutor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return ReportedExecutor_;
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return true; }
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Tcp; }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            (void)Handler;
        }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            (void)Handler;
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            (void)Handler;
        }
        [[nodiscard]] auto OnClose() -> ControlResult override { return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        Net::any_io_executor ReportedExecutor_;
    };

    /** @brief 可重复尝试的测试原生端点；首个 Close 留下可观察 native 失败。 */
    struct RetryableCloseState final
    {
        explicit RetryableCloseState(std::error_code FailureValue)
            : NativeFailure(std::move(FailureValue))
        {
        }

        const std::error_code NativeFailure;
        std::atomic<std::size_t> CancelAttempts{0};
        std::atomic<std::size_t> CloseAttempts{0};
        std::atomic<std::size_t> DrainAttempts{0};
        std::atomic<bool> NativeClosed{false};
    };

    /** @brief 按关闭 owner 的实际完成状态报告 native cause，而不是仅报告请求已投递。 */
    class RetryableCloseActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        RetryableCloseActivity(Net::any_io_executor Executor,
                               std::shared_ptr<RetryableCloseState> State)
            : Executor_(std::move(Executor)), State_(std::move(State))
        {
        }

        auto Seal() noexcept -> void override { Sealed_.store(true, std::memory_order_release); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Sealed_.load(std::memory_order_acquire) &&
            State_->NativeClosed.load(std::memory_order_acquire); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            State_->DrainAttempts.fetch_add(1, std::memory_order_relaxed);
            if (!Sealed_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!State_->NativeClosed.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Preview::Fault::FromNative(State_->NativeFailure));
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<RetryableCloseState> State_;
        std::atomic<bool> Sealed_{false};
    };

    /** @brief 复现 typed Run 与可重试 Activity close 的真实失败 owner。 */
    class RetryableCloseDatagram final : public Preview::Contract::DatagramSession
    {
    public:
        RetryableCloseDatagram(Net::any_io_executor Executor,
                               std::shared_ptr<RetryableCloseState> State)
            : State_(std::move(State)),
              Activity_(std::make_shared<RetryableCloseActivity>(std::move(Executor), State_))
        {
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        auto Cancel() noexcept -> void override
        {
            State_->CancelAttempts.fetch_add(1, std::memory_order_relaxed);
        }

        auto Close() noexcept -> void override
        {
            const auto Attempts = State_->CloseAttempts.fetch_add(1, std::memory_order_acq_rel) + 1U;
            if (Attempts >= 2U) State_->NativeClosed.store(true, std::memory_order_release);
        }

    private:
        std::shared_ptr<RetryableCloseState> State_;
        std::shared_ptr<RetryableCloseActivity> Activity_;
    };

    struct NativeDrainState final
    {
        explicit NativeDrainState(std::error_code Failure)
            : NativeError(std::move(Failure))
        {
        }

        const std::error_code NativeError;
        std::atomic<std::size_t> Attempts{0};
        std::atomic<bool> FailedOnce{false};
    };

    /** @brief 只在首次 drain 注入保留 native identity 的可重试观测失败。 */
    class FailOnceNativeActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        FailOnceNativeActivity(std::shared_ptr<Preview::Contract::CarrierActivity> Inner,
                               std::shared_ptr<NativeDrainState> State)
            : Inner_(std::move(Inner)), State_(std::move(State))
        {
        }

        auto Seal() noexcept -> void override { Inner_->Seal(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Inner_->IsRetired(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            State_->Attempts.fetch_add(1, std::memory_order_relaxed);
            auto Result = co_await Inner_->Drain();
            if (!Result) co_return std::unexpected(Result.error());
            if (!State_->FailedOnce.exchange(true, std::memory_order_acq_rel))
            {
                co_return std::unexpected(Preview::Fault::FromNative(State_->NativeError));
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        std::shared_ptr<Preview::Contract::CarrierActivity> Inner_;
        std::shared_ptr<NativeDrainState> State_;
    };

    /** @brief 通过真实 Transmission control/Activity owner 测试 listener drain 的可重试边界。 */
    class RetryableDrainTransmission final : public Preview::Transmission
    {
    public:
        RetryableDrainTransmission(Net::any_io_executor Executor,
                                   std::shared_ptr<NativeDrainState> State)
            : Preview::Transmission(std::move(Executor)),
              Activity_(std::make_shared<FailOnceNativeActivity>(
                  Preview::Transmission::Activity(), std::move(State)))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Activity_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

        std::atomic<std::size_t> CloseCalls{0};

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0, {Preview::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            CloseCalls.fetch_add(1, std::memory_order_relaxed);
            Closed_.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::shared_ptr<FailOnceNativeActivity> Activity_;
        std::atomic<bool> Closed_{false};
    };

    struct CanceledRetirementReceipt final
    {
        std::atomic<bool> AllowRetirement{true};
        std::atomic<bool> ReturnedCanceled{false};
        std::atomic<bool> UnderlyingRetired{false};
    };

    /** @brief 底层真实退休后返回取消结果，供 listener owner 核对物理回执。 */
    class RetiredCanceledActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        RetiredCanceledActivity(
            std::shared_ptr<Preview::Contract::CarrierActivity> Underlying,
            std::shared_ptr<CanceledRetirementReceipt> Receipt)
            : Underlying_(std::move(Underlying)), Receipt_(std::move(Receipt))
        {
        }

        auto Seal() noexcept -> void override { Underlying_->Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Underlying_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Receipt_->ReturnedCanceled.load(std::memory_order_acquire) &&
                   Receipt_->UnderlyingRetired.load(std::memory_order_acquire) &&
                   Underlying_->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            const auto Drained = co_await Underlying_->Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            Receipt_->UnderlyingRetired.store(
                Underlying_->IsRetired() &&
                    Receipt_->AllowRetirement.load(std::memory_order_acquire),
                std::memory_order_release);
            Receipt_->ReturnedCanceled.store(true, std::memory_order_release);
            co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        }

    private:
        std::shared_ptr<Preview::Contract::CarrierActivity> Underlying_;
        std::shared_ptr<CanceledRetirementReceipt> Receipt_;
    };

    /** @brief listener cleanup 使用的无 I/O transport；关闭时回报已退休的取消结果。 */
    class RetiredCanceledTransmission final : public Preview::Transmission
    {
    public:
        RetiredCanceledTransmission(
            Net::any_io_executor Executor,
            std::shared_ptr<CanceledRetirementReceipt> Receipt)
            : Preview::Transmission(std::move(Executor)),
              Activity_(std::make_shared<RetiredCanceledActivity>(
                  Preview::Transmission::Activity(), std::move(Receipt)))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0, {Preview::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
        std::atomic<bool> Closed_{false};
    };

    struct ActiveTransportWorker final
    {
        Preview::Runtime::ActiveTransports &Active;
        std::shared_ptr<Preview::PreviewMockTransport> First;
        std::shared_ptr<Preview::PreviewMockTransport> Second;
        std::atomic_bool &Failed;
        std::atomic<int> &FirstFailureCode;
        int Index{0};

        /** @brief 保留并发 fixture 首次失败的 typed code 供原断言输出。 */
        auto RecordFailure(Failure Error) -> void
        {
            Failed.store(true, std::memory_order_release);
            auto Expected = -1;
            (void)FirstFailureCode.compare_exchange_strong(
                Expected, static_cast<int>(Error.Code), std::memory_order_acq_rel);
        }
    };

    auto RunActiveTransportWorker(ActiveTransportWorker Worker) -> void
    {
        for (int Iteration = 0; Iteration < 10000; ++Iteration)
        {
            auto Value = ((Iteration + Worker.Index) % 2 == 0) ? Worker.First : Worker.Second;
            const auto Domain = Preview::Runtime::CarrierDomain::Create(
                Value->Executor(), Value->Activity());
            if (!Domain)
            {
                Worker.RecordFailure(Domain.error());
                continue;
            }
            auto Inbound = Worker.Active.StoreInbound(Value, *Domain);
            if (!Inbound)
            {
                Worker.RecordFailure(Inbound.error());
                continue;
            }
            auto Outbound = Worker.Active.StoreOutbound(Value, *Domain);
            if (!Outbound)
            {
                Worker.RecordFailure(Outbound.error());
                continue;
            }
            Inbound->reset();
            Outbound->reset();
            const auto Snapshot = Worker.Active.Load();
            if ((Snapshot.Inbound && Snapshot.Inbound != Worker.First &&
                 Snapshot.Inbound != Worker.Second) ||
                (Snapshot.Outbound && Snapshot.Outbound != Worker.First &&
                 Snapshot.Outbound != Worker.Second))
            {
                Worker.RecordFailure(Failure{Preview::Fault::Code::InvalidArgument});
            }
        }
    }

    TEST(ActiveTransports, ConcurrentStoreAndLoadKeepsTransmissionOwnership)
    {
        boost::asio::io_context IoContext;
        auto First = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        auto Second = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        std::weak_ptr<Preview::PreviewMockTransport> FirstOwner = First;
        std::weak_ptr<Preview::PreviewMockTransport> SecondOwner = Second;
        Preview::Runtime::ActiveTransports Active;
        std::atomic_bool Failed{false};
        std::atomic<int> FirstFailureCode{-1};
        std::vector<std::thread> Threads;
        auto Work = Net::make_work_guard(IoContext);
        std::thread IoRunner([&IoContext] { IoContext.run(); });

        for (int Index = 0; Index < 4; ++Index)
        {
            Threads.emplace_back(RunActiveTransportWorker, ActiveTransportWorker{
                Active, First, Second, Failed, FirstFailureCode, Index});
        }

        for (auto &Thread : Threads)
        {
            Thread.join();
        }
        Work.reset();
        IoRunner.join();

        EXPECT_FALSE(Failed.load(std::memory_order_acquire))
            << "first_failure_code=" << FirstFailureCode.load(std::memory_order_acquire);
        auto Final = Active.Load();
        EXPECT_TRUE(Final.Inbound);
        EXPECT_TRUE(Final.Outbound);
        Final = Preview::Runtime::ActiveTransportSnapshot{};
        EXPECT_FALSE(First->IsClosed());
        EXPECT_FALSE(Second->IsClosed());
        First.reset();
        Second.reset();

        std::expected<void, Failure> Finalized;
        std::exception_ptr Fatal;
        IoContext.restart();
        boost::asio::co_spawn(
            IoContext, Active.Finalize(),
            [&Fatal, &Finalized](std::exception_ptr Error, std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                Finalized = std::move(Result);
            });
        IoContext.run();

        EXPECT_FALSE(Fatal);
        std::string FinalizeDiagnostic;
        if (!Finalized)
        {
            FinalizeDiagnostic = std::string("code=") +
                std::to_string(static_cast<int>(Finalized.error().Code)) +
                " native=" + Finalized.error().Native.category().name() + "/" +
                std::to_string(Finalized.error().Native.value());
        }
        EXPECT_TRUE(Finalized) << FinalizeDiagnostic;
        EXPECT_TRUE(FirstOwner.expired());
        EXPECT_TRUE(SecondOwner.expired());
    }

    TEST(ActiveTransports, RejectsTransmissionExecutorThatDisagreesWithActivity)
    {
        Net::io_context ActivityContext;
        Net::io_context ReportedContext;
        auto Value = std::make_shared<MismatchedExecutorTransport>(
            ActivityContext.get_executor(), ReportedContext.get_executor());
        const auto Domain = Preview::Runtime::CarrierDomain::Create(
            Value->Activity()->Executor(), Value->Activity());
        ASSERT_TRUE(Domain);

        Preview::Runtime::ActiveTransports Active;
        const auto Stored = Active.StoreInbound(Value, *Domain);

        ASSERT_FALSE(Stored);
        EXPECT_EQ(Stored.error().Code, Preview::Fault::Code::InvalidArgument);
        EXPECT_TRUE(Value->IsOpen());
    }

    TEST(ActiveTransports, ClosingStoreRetainsOutboundUntilNativeDrainRetry)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<NativeDrainState>(NativeError);
        auto Outbound = std::make_shared<RetryableDrainTransmission>(Executor, State);
        std::weak_ptr<RetryableDrainTransmission> WeakOutbound = Outbound;
        const auto Domain = Preview::Runtime::CarrierDomain::Create(
            Outbound->Executor(), Outbound->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Preview::Runtime::ActiveTransports>();
        ASSERT_TRUE(Active->RequestClose());
        const auto Stored = Active->StoreOutbound(std::move(Outbound), *Domain);
        ASSERT_FALSE(Stored);
        EXPECT_EQ(Stored.error().Code, Preview::Fault::Code::Canceled);
        EXPECT_FALSE(Outbound);

        Context->Io.run();

        EXPECT_EQ(State->Attempts.load(std::memory_order_relaxed), 1U);
        EXPECT_FALSE(WeakOutbound.expired());
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_TRUE(State->FailedOnce.load(std::memory_order_acquire));

        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_GE(State->Attempts.load(std::memory_order_relaxed), 2U);
        EXPECT_EQ(Storage->Pending(), 0U);
        Active.reset();
        EXPECT_TRUE(WeakOutbound.expired());
    }

    TEST(ActiveTransports, RetriesNativeCloseBeforeReleasingResource)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<RetryableCloseState>(NativeError);
        auto Datagram = std::make_shared<RetryableCloseDatagram>(Executor, State);
        std::weak_ptr<RetryableCloseDatagram> WeakDatagram = Datagram;
        auto Domain = Preview::Runtime::CarrierDomain::Create(Executor, Datagram->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Preview::Runtime::ActiveTransports>();
        auto Stored = Active->StoreDatagram(Datagram, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        Datagram.reset();

        std::expected<void, Failure> Finalized;
        std::exception_ptr Fatal;
        Net::co_spawn(
            Context->Io, Active->Finalize(),
            [&Fatal, &Finalized](std::exception_ptr Error, std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                Finalized = std::move(Result);
            });
        Context->Io.run();

        ASSERT_FALSE(Fatal);
        ASSERT_FALSE(Finalized);
        EXPECT_EQ(Finalized.error().Native, NativeError);
        EXPECT_EQ(State->CancelAttempts.load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(State->CloseAttempts.load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(State->DrainAttempts.load(std::memory_order_relaxed), 1U);
        EXPECT_FALSE(State->NativeClosed.load(std::memory_order_acquire));
        EXPECT_FALSE(Storage->IsSealed());

        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_EQ(State->CancelAttempts.load(std::memory_order_relaxed), 2U);
        EXPECT_EQ(State->CloseAttempts.load(std::memory_order_relaxed), 2U);
        EXPECT_EQ(State->DrainAttempts.load(std::memory_order_relaxed), 2U);
        EXPECT_TRUE(State->NativeClosed.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), 0U);

        Active.reset();
        EXPECT_TRUE(WeakDatagram.expired());
    }

    TEST(ListenerConnectionDrain, RetriesNativeActivityFailureWithoutBlockingQuota)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<NativeDrainState>(NativeError);
        auto Transport = std::make_shared<RetryableDrainTransmission>(Executor, State);
        std::weak_ptr<RetryableDrainTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Preview::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Drain = Preview::Runtime::Detail::ListenerConnectionDrain::Make(
            {Transport, Reservation, {}, {}});
        Transport.reset();

        Drain->Start();
        Context->Io.run();

        EXPECT_FALSE(Drain->IsRetired());
        EXPECT_FALSE(Drain->IsDispatchUnavailable());
        EXPECT_FALSE(Storage->IsSealed());
        EXPECT_TRUE(Quota->Drain.IsBlocked());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 1U);
        ASSERT_EQ(State->Attempts.load(std::memory_order_relaxed), 1U);
        auto RetainedTransport = WeakTransport.lock();
        ASSERT_TRUE(RetainedTransport);
        EXPECT_EQ(RetainedTransport->CloseCalls.load(std::memory_order_relaxed), 1U);

        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_TRUE(Drain->IsRetired());
        EXPECT_FALSE(Drain->IsDispatchUnavailable());
        EXPECT_TRUE(Quota->Drain.IsBlocked());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(Quota->Drain.Active(), 0U);
        EXPECT_EQ(State->Attempts.load(std::memory_order_relaxed), 2U);
        EXPECT_EQ(Storage->Pending(), 0U);
        RetainedTransport.reset();
        Drain.reset();
        EXPECT_TRUE(WeakTransport.expired());
    }

    TEST(ListenerConnectionDrain, AcceptsCanceledDrainAfterPhysicalRetirement)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto Receipt = std::make_shared<CanceledRetirementReceipt>();
        auto Transport = std::make_shared<RetiredCanceledTransmission>(Executor, Receipt);
        std::weak_ptr<RetiredCanceledTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Preview::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Session = std::make_shared<Preview::Runtime::Detail::SessionAdmissionState>();
        Session->Started.store(true, std::memory_order_release);
        Session->Drained.store(true, std::memory_order_release);
        auto Drain = Preview::Runtime::Detail::ListenerConnectionDrain::Make(
            {Transport, Reservation, {}, Session});
        Transport.reset();

        Drain->Start();
        Context->Io.run();
        Storage->Collect();

        EXPECT_TRUE(Receipt->ReturnedCanceled.load(std::memory_order_acquire));
        EXPECT_TRUE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_TRUE(Drain->IsRetired());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(Quota->Drain.Active(), 0U);
        EXPECT_EQ(Storage->Pending(), 0U);

        Reservation.reset();
        Drain.reset();
        EXPECT_TRUE(WeakTransport.expired());
    }

    TEST(ListenerConnectionDrain, RetainsCanceledDrainUntilPhysicalRetirement)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto Receipt = std::make_shared<CanceledRetirementReceipt>();
        Receipt->AllowRetirement.store(false, std::memory_order_release);
        auto Transport = std::make_shared<RetiredCanceledTransmission>(Executor, Receipt);
        std::weak_ptr<RetiredCanceledTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Preview::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Preview::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Session = std::make_shared<Preview::Runtime::Detail::SessionAdmissionState>();
        Session->Started.store(true, std::memory_order_release);
        Session->Drained.store(true, std::memory_order_release);
        auto Drain = Preview::Runtime::Detail::ListenerConnectionDrain::Make(
            {Transport, Reservation, {}, Session});
        Transport.reset();

        Drain->Start();
        Context->Io.run();

        EXPECT_FALSE(Drain->IsRetired());
        EXPECT_FALSE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 1U);
        EXPECT_GT(Storage->Pending(), 0U);

        Receipt->AllowRetirement.store(true, std::memory_order_release);
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_TRUE(Receipt->ReturnedCanceled.load(std::memory_order_acquire));
        EXPECT_TRUE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_TRUE(Drain->IsRetired());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(Storage->Pending(), 0U);

        Reservation.reset();
        Drain.reset();
        EXPECT_TRUE(Quota->Drain.IsBlocked());
        EXPECT_TRUE(WeakTransport.expired());
    }

    /** @brief 拒绝数据报的 session owner；carrier 仅在真实 Run 活动退出后关闭。 */
    class RejectedDatagramActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        explicit RejectedDatagramActivity(std::shared_ptr<Preview::MemoryStream> Inbound)
            : Inbound_(std::move(Inbound)),
              RunActivity_(std::make_shared<Preview::Protocols::ProtocolActivity>(Inbound_->Executor())),
              InboundActivity_(Inbound_->Activity())
        {
        }

        [[nodiscard]] auto TryBegin()
            -> std::expected<Preview::Protocols::ProtocolActivity::Reservation, Failure>
        {
            return RunActivity_->TryBegin();
        }

        auto Seal() noexcept -> void override { RunActivity_->Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return RunActivity_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return RunActivity_->IsRetired() && !Inbound_->IsOpen() &&
                InboundActivity_ && InboundActivity_->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            const auto RunDrained = co_await RunActivity_->Drain();
            if (!RunDrained) co_return std::unexpected(RunDrained.error());
            const auto Closed = Inbound_->Close();
            if (!Closed) co_return std::unexpected(Closed.error());
            InboundActivity_->Seal();
            const auto CarrierDrained = co_await InboundActivity_->Drain();
            if (!CarrierDrained) co_return std::unexpected(CarrierDrained.error());
            if (!InboundActivity_->IsRetired())
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            co_return std::expected<void, Failure>{};
        }

    private:
        std::shared_ptr<Preview::MemoryStream> Inbound_;
        std::shared_ptr<Preview::Protocols::ProtocolActivity> RunActivity_;
        std::shared_ptr<Preview::Contract::CarrierActivity> InboundActivity_;
    };

    /** @brief 验证拒绝的数据报根只 Cancel/Close/Drain，不进入 Run。 */
    class RejectedDatagramProbe final : public Preview::Contract::DatagramSession
    {
    public:
        RejectedDatagramProbe(std::shared_ptr<Preview::MemoryStream> Inbound,
                              std::shared_ptr<ByteChannel> Closed)
            : Activity_(std::make_shared<RejectedDatagramActivity>(std::move(Inbound))),
              Closed_(std::move(Closed))
        {
        }

        auto Run() -> Net::awaitable<std::expected<void, Failure>> override
        {
            RunCalled = true;
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        auto Cancel() noexcept -> void override
        {
            CancelCalled = true;
            Activity_->Seal();
        }

        auto Close() noexcept -> void override
        {
            CloseCalled = true;
            Activity_->Seal();
            (void)Closed_->try_send(boost::system::error_code{});
        }

        bool RunCalled{false};
        bool CancelCalled{false};
        bool CloseCalled{false};
        [[nodiscard]] auto TryBegin()
            -> std::expected<Preview::Protocols::ProtocolActivity::Reservation, Failure>
        {
            return Activity_->TryBegin();
        }
        std::shared_ptr<RejectedDatagramActivity> Activity_;

    private:
        std::shared_ptr<ByteChannel> Closed_;
    };

    struct RejectedDatagramState final
    {
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Inbound;
        std::shared_ptr<RejectedDatagramProbe> Datagram;
        std::shared_ptr<ByteChannel> Closed;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<Preview::Account::AccountRuntime> Runtime;
        std::optional<Preview::Protocols::ProtocolActivity::Reservation> Reservation;
        Preview::Contract::ProtocolDataPlane Plane;
        std::optional<Preview::Contract::AcceptOutcome> Outcome;
        std::uint32_t ActiveDuringDrain{0};
        std::uint32_t ActiveAfterDrain{0};
        bool ReservationReady{false};
        bool InboundOpenDuringDrain{false};
        bool InboundOpenAfterDrain{true};
        bool PlaneLeaseHeldAfterAdmission{false};
        bool AdmissionOwnerFound{false};
        bool AdmissionRetiredAfterDrain{false};
        bool AdmissionDispatchUnavailableAfterDrain{false};
        bool SessionActivityRetiredAfterDrain{false};
        bool InboundActivityRetiredAfterDrain{false};
    };

    auto RunRejectedDatagram(std::shared_ptr<RejectedDatagramState> State)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(State->Inbound);
        if (!Prepared)
        {
            (void)State->Closed->try_send(boost::system::error_code{});
        }
        else
        {
            auto Admission = std::move(*Prepared);
            State->Outcome = co_await Admission.Admit(std::move(State->Plane));
            State->PlaneLeaseHeldAfterAdmission = static_cast<bool>(State->Plane.AccountLease);
            const auto Owner = std::dynamic_pointer_cast<Preview::Executor::ClosingResource>(
                Admission.RootCreateOwner());
            State->AdmissionOwnerFound = static_cast<bool>(Owner);
            State->AdmissionRetiredAfterDrain = Owner && Owner->IsRetired();
            State->AdmissionDispatchUnavailableAfterDrain = Owner && Owner->IsDispatchUnavailable();
        }
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunRejectedDatagramAdmission(Net::io_context &Io,
        std::shared_ptr<RejectedDatagramState> State) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = Preview::MakeMemoryPair(Io.get_executor());
        State->Client = std::make_shared<Preview::MemoryStream>(std::move(Client));
        State->Inbound = std::make_shared<Preview::MemoryStream>(std::move(Inbound));
        State->Closed = MakeReleaseChannel(Io.get_executor());
        State->Finished = MakeReleaseChannel(Io.get_executor());
        State->Datagram = std::make_shared<RejectedDatagramProbe>(
            State->Inbound, State->Closed);

        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password("rejected-datagram"),
            Preview::AccountId{7112}, {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7112});
        if (!Record) co_return;
        State->Runtime = Record->Runtime();
        auto AuthResult = Directory->Authenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Password("rejected-datagram"),
            .Rate = {}});
        if (!AuthResult || !*AuthResult) co_return;

        State->Plane.ProtocolAuthenticated = true;
        State->Plane.AccountLease = std::move(*AuthResult);
        State->Plane.Root = Preview::Contract::DatagramDataPlane{
            State->Inbound, State->Datagram};
        auto Reservation = State->Datagram->TryBegin();
        if (Reservation)
        {
            State->ReservationReady = true;
            State->Reservation.emplace(std::move(*Reservation));
        }

        Net::co_spawn(Io, RunRejectedDatagram(State), Net::detached);
        boost::system::error_code Error;
        co_await State->Closed->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        State->ActiveDuringDrain = State->Runtime->ActiveConnections();
        State->InboundOpenDuringDrain = State->Inbound->IsOpen();
        if (State->Reservation)
        {
            State->Reservation->Complete();
            State->Reservation.reset();
        }
        Error.clear();
        co_await State->Finished->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        State->ActiveAfterDrain = State->Runtime->ActiveConnections();
        State->InboundOpenAfterDrain = State->Inbound->IsOpen();
        State->SessionActivityRetiredAfterDrain = State->Datagram->Activity_->IsRetired();
        const auto InboundActivity = State->Inbound->Activity();
        State->InboundActivityRetiredAfterDrain = InboundActivity && InboundActivity->IsRetired();
    }

    TEST(ActiveTransports, RejectedDatagramDrainsWithoutRunAndRetainsLease)
    {
        Net::io_context Io;
        auto State = std::make_shared<RejectedDatagramState>();
        Preview::Testing::RunCoro(Io, RunRejectedDatagramAdmission(Io, State));

        ASSERT_TRUE(State->ReservationReady);
        EXPECT_TRUE(State->Datagram->CancelCalled);
        EXPECT_TRUE(State->Datagram->CloseCalled);
        EXPECT_FALSE(State->Datagram->RunCalled);
        EXPECT_EQ(State->ActiveDuringDrain, 1U);
        EXPECT_TRUE(State->InboundOpenDuringDrain);
        ASSERT_TRUE(State->Outcome);
        ASSERT_FALSE(*State->Outcome);
        EXPECT_EQ(State->Outcome->error().Code, Preview::Fault::Code::AuthFailed);
        EXPECT_FALSE(State->Outcome->error().Native);
        EXPECT_FALSE(State->PlaneLeaseHeldAfterAdmission);
        EXPECT_TRUE(State->AdmissionOwnerFound);
        EXPECT_TRUE(State->AdmissionRetiredAfterDrain);
        EXPECT_FALSE(State->AdmissionDispatchUnavailableAfterDrain);
        EXPECT_TRUE(State->SessionActivityRetiredAfterDrain);
        EXPECT_TRUE(State->InboundActivityRetiredAfterDrain);
        EXPECT_EQ(State->ActiveAfterDrain, 0U);
        EXPECT_FALSE(State->InboundOpenAfterDrain);
    }

} // namespace
