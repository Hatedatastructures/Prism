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

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;

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
    class RetryableCloseActivity final : public Prism::Contract::CarrierActivity
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
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (!State_->NativeClosed.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Prism::Fault::FromNative(State_->NativeFailure));
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<RetryableCloseState> State_;
        std::atomic<bool> Sealed_{false};
    };

    /** @brief 复现 typed Run 与可重试 Activity close 的真实失败 owner。 */
    class RetryableCloseDatagram final : public Prism::Contract::DatagramSession
    {
    public:
        RetryableCloseDatagram(Net::any_io_executor Executor,
                               std::shared_ptr<RetryableCloseState> State)
            : State_(std::move(State)),
              Activity_(std::make_shared<RetryableCloseActivity>(std::move(Executor), State_))
        {
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
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
    class FailOnceNativeActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        FailOnceNativeActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Inner,
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
                co_return std::unexpected(Prism::Fault::FromNative(State_->NativeError));
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Inner_;
        std::shared_ptr<NativeDrainState> State_;
    };

    /** @brief 通过真实 Transmission control/Activity owner 测试 listener drain 的可重试边界。 */
    class RetryableDrainTransmission final : public Prism::Transmission
    {
    public:
        RetryableDrainTransmission(Net::any_io_executor Executor,
                                   std::shared_ptr<NativeDrainState> State)
            : Prism::Transmission(std::move(Executor)),
              Activity_(std::make_shared<FailOnceNativeActivity>(
                  Prism::Transmission::Activity(), std::move(State)))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Activity_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
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
            Prism::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0, {Prism::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
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


    TEST(ActiveTransports, ClosingStoreRetainsOutboundUntilNativeDrainRetry)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<NativeDrainState>(NativeError);
        auto Outbound = std::make_shared<RetryableDrainTransmission>(Executor, State);
        std::weak_ptr<RetryableDrainTransmission> WeakOutbound = Outbound;
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Outbound->Executor(), Outbound->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
        ASSERT_TRUE(Active->RequestClose());
        const auto Stored = Active->StoreOutbound(std::move(Outbound), *Domain);
        ASSERT_FALSE(Stored);
        EXPECT_EQ(Stored.error().Code, Prism::Fault::Code::Canceled);
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
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<RetryableCloseState>(NativeError);
        auto Datagram = std::make_shared<RetryableCloseDatagram>(Executor, State);
        std::weak_ptr<RetryableCloseDatagram> WeakDatagram = Datagram;
        auto Domain = Prism::Runtime::CarrierDomain::Create(Executor, Datagram->Activity());
        ASSERT_TRUE(Domain);

        auto Active = std::make_unique<Prism::Runtime::ActiveTransports>();
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
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        const auto NativeError = std::make_error_code(std::errc::connection_reset);
        auto State = std::make_shared<NativeDrainState>(NativeError);
        auto Transport = std::make_shared<RetryableDrainTransmission>(Executor, State);
        std::weak_ptr<RetryableDrainTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Prism::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Drain = Prism::Runtime::Detail::ListenerConnectionDrain::Make(
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

} // namespace
