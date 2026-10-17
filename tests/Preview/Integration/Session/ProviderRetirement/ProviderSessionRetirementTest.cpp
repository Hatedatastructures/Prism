/**
 * @file ProviderSessionRetirementTest.cpp
 * @brief 验证 provider 关闭会释放 Runtime Finalize 所等待的入站 view。
 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Protocols/Common/ProviderBindingLifecycle.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Runtime/ActiveTransports.hpp>
#include <Preview/Runtime/CarrierDomain.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace Preview::Testing
{
    namespace Net = boost::asio;

    class ProviderRetirementTestGeneration final : public Preview::Foundation::GenerationLifetime
    {
    public:
        [[nodiscard]] auto Id() const noexcept -> Preview::GenerationId override { return {}; }
    };

    struct ProviderRetirementTestMaterial final
    {
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
        Net::any_io_executor Executor;
    };

    using ProviderRetirementTestBinding =
        Preview::Protocols::ProviderBindingLifecycle<ProviderRetirementTestMaterial>;

    /** @brief 记录 provider 正常退休时是否把关闭误发成显式取消。 */
    class ProviderRetirementMuxSession final : public Preview::Contract::MuxSession
    {
    public:
        explicit ProviderRetirementMuxSession(
            std::shared_ptr<Preview::PreviewMockTransport> Transport)
            : Transport_(std::move(Transport)), Activity_(Transport_->Activity())
        {
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }
        [[nodiscard]] auto Run(Preview::Contract::MuxRootRequest)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Activity_ && Activity_->IsRetired();
        }
        auto Cancel() noexcept -> void override { ++CancelCalls_; }
        auto Close() noexcept -> void override
        {
            ++CloseCalls_;
            (void)Transport_->Close();
        }

        [[nodiscard]] auto CancelCalls() const noexcept -> std::size_t { return CancelCalls_; }
        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t { return CloseCalls_; }

    private:
        std::shared_ptr<Preview::PreviewMockTransport> Transport_;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
        std::size_t CancelCalls_{0U};
        std::size_t CloseCalls_{0U};
    };

    struct ProviderRetirementRetryGate final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        explicit ProviderRetirementRetryGate(Net::any_io_executor Executor)
            : FirstDrainEntered(Executor, 1U), ReleaseFirstDrain(Executor, 1U),
              SecondDrainEntered(std::move(Executor), 1U) {}

        Signal FirstDrainEntered;
        Signal ReleaseFirstDrain;
        Signal SecondDrainEntered;
        std::atomic<std::size_t> DrainCalls{0U};
        std::atomic<bool> Retired{false};
    };

    /** @brief 首次 drain 可控地先取消后未退休，下一次 drain 才发布物理回执。 */
    class ProviderRetirementRetryActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        explicit ProviderRetirementRetryActivity(
            std::shared_ptr<ProviderRetirementRetryGate> Gate)
            : Gate_(std::move(Gate)) {}

        auto Seal() noexcept -> void override {}

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Gate_->FirstDrainEntered.get_executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Gate_->Retired.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            const auto Call = Gate_->DrainCalls.fetch_add(1U, std::memory_order_acq_rel) + 1U;
            if (Call == 1U)
            {
                (void)Gate_->FirstDrainEntered.try_send(boost::system::error_code{});
                boost::system::error_code Error;
                co_await Gate_->ReleaseFirstDrain.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return std::unexpected(
                        Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            Gate_->Retired.store(true, std::memory_order_release);
            (void)Gate_->SecondDrainEntered.try_send(boost::system::error_code{});
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        std::shared_ptr<ProviderRetirementRetryGate> Gate_;
    };

    /** @brief 同一 owner 已退休时仍报告的取消不应变成永久 drain failure。 */
    class ProviderRetirementCanceledRetiredActivity final
        : public Preview::Contract::CarrierActivity
    {
    public:
        explicit ProviderRetirementCanceledRetiredActivity(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)) {}

        auto Seal() noexcept -> void override
        { Retired_.store(true, std::memory_order_release); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Retired_.load(std::memory_order_acquire); }
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Canceled});
        }

    private:
        Net::any_io_executor Executor_;
        std::atomic<bool> Retired_{false};
    };

    /** @brief 真实退休回执仍保留的 inbound I/O drain 错误。 */
    class ProviderRetirementIoErrorActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        explicit ProviderRetirementIoErrorActivity(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)) {}

        auto Seal() noexcept -> void override
        {
            Sealed_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Sealed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::IoError});
        }

    private:
        Net::any_io_executor Executor_;
        std::atomic<bool> Sealed_{false};
    };

    /** @brief 把固定 inbound carrier activity 注入 provider ticket 测试。 */
    class ProviderRetirementTestTransmission final : public Preview::Transmission
    {
    public:
        explicit ProviderRetirementTestTransmission(
            Net::any_io_executor Executor,
            std::shared_ptr<Preview::Contract::CarrierActivity> Activity = {})
            : Preview::Transmission(Executor), Executor_(std::move(Executor)),
              Activity_(Activity ? std::move(Activity) :
                  std::make_shared<ProviderRetirementIoErrorActivity>(Executor_)) {}

        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler),
                {0U, {Preview::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler),
                {0U, {Preview::Fault::Code::Eof}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            Activity_->Seal();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
        bool Closed_{false};
    };

    class ProviderRetirementDatagramProbe final : public Preview::Contract::DatagramSession
    {
    public:
        explicit ProviderRetirementDatagramProbe(
            std::shared_ptr<Preview::Contract::CarrierActivity> Activity)
            : Activity_(std::move(Activity)) {}

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

        auto Cancel() noexcept -> void override { ++CancelCalls_; }
        auto Close() noexcept -> void override { ++CloseCalls_; }

        [[nodiscard]] auto CancelCalls() const noexcept -> std::size_t { return CancelCalls_; }
        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t { return CloseCalls_; }

    private:
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
        std::size_t CancelCalls_{0U};
        std::size_t CloseCalls_{0U};
    };

    struct ProviderRetirementRetryScenario final
    {
        using Ticket = ProviderRetirementTestBinding::Ticket;

        std::shared_ptr<Ticket> Owner;
        std::shared_ptr<ProviderRetirementRetryGate> Gate;
        std::shared_ptr<Net::steady_timer> Deadline;
        bool TimedOut{false};
    };

    [[nodiscard]] auto TimeoutProviderRetirementRetry(
        const std::shared_ptr<ProviderRetirementRetryScenario>& State)
        -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await State->Deadline->async_wait(
            Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            (void)State->Gate->FirstDrainEntered.try_send(boost::asio::error::timed_out);
            (void)State->Gate->ReleaseFirstDrain.try_send(boost::asio::error::timed_out);
            (void)State->Gate->SecondDrainEntered.try_send(boost::asio::error::timed_out);
        }
    }

    [[nodiscard]] auto RunProviderRetirementRetry(
        const std::shared_ptr<ProviderRetirementRetryScenario>& State)
        -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::co_spawn(Executor, TimeoutProviderRetirementRetry(State), Net::detached);
        boost::system::error_code Error;
        co_await State->Gate->FirstDrainEntered.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->TimedOut = true;
            co_return;
        }
        State->Owner->RequestRetirement();
        (void)State->Gate->ReleaseFirstDrain.try_send(boost::system::error_code{});
        co_await State->Gate->SecondDrainEntered.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        State->TimedOut = static_cast<bool>(Error);
        State->Deadline->cancel();
        co_await Net::post(Executor, Net::use_awaitable);
    }

    struct ProviderRetirementAttemptState final
    {
        using Attempt = ProviderRetirementTestBinding::AcceptAttempt;

        std::optional<Attempt> Value;
        std::shared_ptr<ProviderRetirementTestBinding::Ticket> Ticket;
        bool RetiredBeforeComplete{false};
        bool DrainFailedBeforeComplete{false};
        bool DrainBeforeComplete{false};
        bool DrainSucceeded{false};
    };

    [[nodiscard]] auto CompleteAttemptAfterYield(
        const std::shared_ptr<ProviderRetirementAttemptState>& State) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        co_await Net::post(Executor, Net::use_awaitable);
        State->RetiredBeforeComplete = State->Ticket->IsRetired();
        State->DrainFailedBeforeComplete = State->Ticket->DrainFailure().Failed();
        if (State->DrainBeforeComplete)
        {
            const auto Drained = co_await State->Ticket->Drain();
            State->DrainSucceeded = Drained.has_value();
        }
        State->Value->Complete();
    }

    static auto RunProviderRetirementScenario(
        const bool CloseBeforeComplete, const bool AbandonMuxRoot = false) -> void
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        Preview::Protocols::ProviderBindingLifecycle<ProviderRetirementTestMaterial> Binding(Material);
        Preview::Runtime::ActiveTransports Active;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Executor);
        const auto Domain = Preview::Runtime::CarrierDomain::Create(Executor, Transport->Activity());
        ASSERT_TRUE(Domain);

        Preview::SharedTransmission RootTransport = Transport;
        auto Inbound = Active.StoreInbound(std::move(Transport), *Domain);
        ASSERT_TRUE(Inbound);
        auto Attempt = Binding.Begin(std::move(*Inbound));
        ASSERT_TRUE(Attempt);
        auto State = std::make_shared<ProviderRetirementAttemptState>();
        State->Ticket = Attempt->Owner();
        State->Value.emplace(std::move(*Attempt));
        const auto Ticket = State->Ticket;
        ASSERT_EQ(UseState->Outstanding(), 1U);
        if (AbandonMuxRoot)
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::MuxRootDataPlane{RootTransport, {}};
            auto Prepared = Preview::Contract::MuxRootCreateRequest::Prepare(
                std::static_pointer_cast<Preview::Contract::MuxRootCreateOwner>(Ticket),
                UseState, std::move(Plane));
            ASSERT_TRUE(Prepared);
            std::optional<Preview::Contract::MuxRootCreateRequest> Request;
            Request.emplace(std::move(*Prepared));
            Request.reset();
        }

        std::optional<std::expected<void, Preview::Fault::Failure>> ActiveResult;
        std::exception_ptr ActiveException;
        std::exception_ptr CompletionException;
        if (CloseBeforeComplete)
        {
            if (!AbandonMuxRoot) Binding.Close();
            if (AbandonMuxRoot)
            {
                State->DrainBeforeComplete = true;
                State->Value->FinishProtocol();
            }
            else State->Value->FinishProtocol();
            Net::co_spawn(Context->Io, CompleteAttemptAfterYield(State),
                [&CompletionException](std::exception_ptr Error)
                { CompletionException = std::move(Error); });
        }
        else
        {
            State->Value->FinishProtocol();
            State->Value->Complete();
            Binding.Close();
        }
        EXPECT_FALSE(Ticket->IsRetired());

        Net::co_spawn(Context->Io, Active.Finalize(),
            [&ActiveResult, &ActiveException](std::exception_ptr Error, auto Result)
            {
                ActiveException = std::move(Error);
                ActiveResult.emplace(std::move(Result));
            });
        Context->Io.run();

        EXPECT_FALSE(CompletionException);
        if (CloseBeforeComplete) EXPECT_FALSE(State->RetiredBeforeComplete);
        if (CloseBeforeComplete) EXPECT_FALSE(State->DrainFailedBeforeComplete);
        if (AbandonMuxRoot) EXPECT_TRUE(State->DrainSucceeded);
        ASSERT_FALSE(ActiveException);
        ASSERT_TRUE(ActiveResult.has_value());
        ASSERT_TRUE(*ActiveResult);
        EXPECT_TRUE(Ticket->IsRetired());
        EXPECT_EQ(UseState->Outstanding(), 0U);

        Context->Io.restart();
        bool ProviderDrainCompleted = false;
        bool ProviderDrainSucceeded = false;
        std::exception_ptr ProviderException;
        Net::co_spawn(Context->Io, Binding.Drain(),
            [&ProviderDrainCompleted, &ProviderDrainSucceeded, &ProviderException]
            (std::exception_ptr Error, auto Result)
            {
                ProviderException = std::move(Error);
                ProviderDrainSucceeded = Result.has_value();
                ProviderDrainCompleted = true;
            });
        Context->Io.run();

        EXPECT_FALSE(ProviderException);
        EXPECT_TRUE(ProviderDrainCompleted);
        EXPECT_TRUE(ProviderDrainSucceeded);
        EXPECT_TRUE(Binding.IsRetired());
    }

    TEST(ProviderSessionRetirement, ProviderCloseBeforeAttemptCompleteReleasesPinnedInbound)
    {
        RunProviderRetirementScenario(true);
    }

    TEST(ProviderSessionRetirement, AttemptCompleteBeforeProviderCloseReleasesPinnedInbound)
    {
        RunProviderRetirementScenario(false, false);
    }

    TEST(ProviderSessionRetirement, AbandonedMuxRootWaitsForAttemptCompletion)
    {
        RunProviderRetirementScenario(true, true);
    }

    TEST(ProviderSessionRetirement, NormalOwnerRetirementClosesMuxWithoutCancelingIt)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        ProviderRetirementTestBinding Binding(Material);
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Executor);
        auto Attempt = Binding.Begin(Transport);
        ASSERT_TRUE(Attempt);
        auto Ticket = Attempt->Owner();
        auto Mux = std::make_shared<ProviderRetirementMuxSession>(Transport);
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::MuxRootDataPlane{Transport, Mux};
        const auto Published = Ticket->Publish(Plane);
        ASSERT_TRUE(Published);
        Attempt->FinishProtocol();
        Attempt->Complete();

        std::optional<std::expected<void, Preview::Fault::Failure>> DrainResult;
        std::exception_ptr DrainException;
        Net::co_spawn(Context->Io, Ticket->Drain(),
            [&DrainResult, &DrainException](std::exception_ptr Error, auto Result)
            {
                DrainException = std::move(Error);
                DrainResult.emplace(std::move(Result));
            });
        Context->Io.run();

        EXPECT_FALSE(DrainException);
        ASSERT_TRUE(DrainResult.has_value());
        EXPECT_TRUE(*DrainResult);
        EXPECT_TRUE(Ticket->IsRetired());
        EXPECT_EQ(UseState->Outstanding(), 0U);
        EXPECT_EQ(Mux->CancelCalls(), 0U);
        EXPECT_GE(Mux->CloseCalls(), 1U);
        EXPECT_FALSE(Transport->IsCancelled());
        EXPECT_TRUE(Transport->IsClosed());
    }

    TEST(ProviderSessionRetirement, CoalescedRetryReleasesInboundAfterCanceledDrain)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        ProviderRetirementTestBinding Binding(Material);
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Executor);
        std::weak_ptr<Preview::PreviewMockTransport> WeakTransport = Transport;
        auto Attempt = Binding.Begin(Transport);
        ASSERT_TRUE(Attempt);
        auto Ticket = Attempt->Owner();

        auto Gate = std::make_shared<ProviderRetirementRetryGate>(Executor);
        auto Activity = std::make_shared<ProviderRetirementRetryActivity>(Gate);
        auto Datagram = std::make_shared<ProviderRetirementDatagramProbe>(Activity);
        auto RootTransport = std::make_shared<Preview::Vless::Conn<>>(
            Transport, std::array<std::uint8_t, Preview::Vless::UuidLen>{});
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::DatagramDataPlane{RootTransport, Datagram};
        ASSERT_TRUE(Ticket->Publish(Plane));
        Plane = {};
        RootTransport.reset();
        Attempt->FinishProtocol();
        Attempt->Complete();
        Binding.Close();

        auto Scenario = std::make_shared<ProviderRetirementRetryScenario>();
        Scenario->Owner = Ticket;
        Scenario->Gate = Gate;
        Scenario->Deadline = std::make_shared<Net::steady_timer>(Executor);
        Scenario->Deadline->expires_after(std::chrono::seconds(2));
        std::exception_ptr Exception;
        Net::co_spawn(Context->Io, RunProviderRetirementRetry(Scenario),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Context->Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Scenario->TimedOut);
        EXPECT_EQ(Gate->DrainCalls.load(std::memory_order_acquire), 2U);
        EXPECT_TRUE(Ticket->IsRetired());
        EXPECT_TRUE(Ticket->DrainFailure().Succeeded());
        EXPECT_EQ(Datagram->CancelCalls(), 0U);
        EXPECT_GE(Datagram->CloseCalls(), 1U);
        EXPECT_FALSE(Transport->IsCancelled());
        EXPECT_TRUE(Transport->IsClosed());
        Transport.reset();
        EXPECT_TRUE(WeakTransport.expired());
        EXPECT_EQ(UseState->Outstanding(), 0U);

        Context->Io.restart();
        std::optional<Preview::Protocols::ProviderRetirementResult> BindingDrain;
        std::exception_ptr BindingException;
        Net::co_spawn(Context->Io, Binding.Drain(),
            [&BindingDrain, &BindingException](std::exception_ptr Error, auto Result)
            {
                BindingException = std::move(Error);
                BindingDrain.emplace(std::move(Result));
            });
        Context->Io.run();
        EXPECT_FALSE(BindingException);
        ASSERT_TRUE(BindingDrain.has_value());
        EXPECT_TRUE(*BindingDrain);
        EXPECT_TRUE(Binding.IsRetired());
    }

    TEST(ProviderSessionRetirement, AcceptsCanceledRootDrainAfterItsOwnRetirement)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        ProviderRetirementTestBinding Binding(Material);
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Executor);
        auto Attempt = Binding.Begin(Transport);
        ASSERT_TRUE(Attempt);
        auto Ticket = Attempt->Owner();
        auto Activity = std::make_shared<ProviderRetirementCanceledRetiredActivity>(Executor);
        auto Datagram = std::make_shared<ProviderRetirementDatagramProbe>(Activity);
        auto RootTransport = std::make_shared<Preview::Vless::Conn<>>(
            Transport, std::array<std::uint8_t, Preview::Vless::UuidLen>{});
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::DatagramDataPlane{RootTransport, Datagram};
        ASSERT_TRUE(Ticket->Publish(Plane));
        Plane = {};
        RootTransport.reset();
        Attempt->FinishProtocol();
        Attempt->Complete();
        Binding.Close();

        std::optional<Preview::Protocols::ProviderRetirementResult> DrainResult;
        std::exception_ptr DrainException;
        Net::co_spawn(Context->Io, Ticket->Drain(),
            [&DrainResult, &DrainException](std::exception_ptr Error, auto Result)
            {
                DrainException = std::move(Error);
                DrainResult.emplace(std::move(Result));
            });
        Context->Io.run();

        EXPECT_FALSE(DrainException);
        ASSERT_TRUE(DrainResult.has_value());
        EXPECT_TRUE(*DrainResult);
        EXPECT_TRUE(Ticket->IsRetired());
        EXPECT_TRUE(Ticket->DrainFailure().Succeeded());
        EXPECT_EQ(Datagram->CancelCalls(), 0U);
        EXPECT_GE(Datagram->CloseCalls(), 1U);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }

    TEST(ProviderSessionRetirement, RetryableRootCancellationDoesNotHideInboundIoError)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        ProviderRetirementTestBinding Binding(Material);
        auto Transport = std::make_shared<ProviderRetirementTestTransmission>(Executor);
        auto Attempt = Binding.Begin(Transport);
        ASSERT_TRUE(Attempt);
        auto Ticket = Attempt->Owner();
        auto Gate = std::make_shared<ProviderRetirementRetryGate>(Executor);
        auto Activity = std::make_shared<ProviderRetirementRetryActivity>(Gate);
        auto Datagram = std::make_shared<ProviderRetirementDatagramProbe>(Activity);
        auto RootTransport = std::make_shared<Preview::Vless::Conn<>>(
            Transport, std::array<std::uint8_t, Preview::Vless::UuidLen>{});
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::DatagramDataPlane{RootTransport, Datagram};
        ASSERT_TRUE(Ticket->Publish(Plane));
        Plane = {};
        RootTransport.reset();
        Attempt->FinishProtocol();
        Attempt->Complete();
        Binding.Close();

        auto Scenario = std::make_shared<ProviderRetirementRetryScenario>();
        Scenario->Owner = Ticket;
        Scenario->Gate = Gate;
        Scenario->Deadline = std::make_shared<Net::steady_timer>(Executor);
        Scenario->Deadline->expires_after(std::chrono::seconds(2));
        std::exception_ptr RetryException;
        Net::co_spawn(Context->Io, RunProviderRetirementRetry(Scenario),
            [&RetryException](std::exception_ptr Error) { RetryException = std::move(Error); });
        Context->Io.run();

        EXPECT_FALSE(RetryException);
        EXPECT_FALSE(Scenario->TimedOut);
        EXPECT_GE(Gate->DrainCalls.load(std::memory_order_acquire), 2U);
        EXPECT_TRUE(Ticket->IsRetired());
        EXPECT_EQ(Ticket->DrainFailure().Code, Preview::Fault::Code::IoError);

        Context->Io.restart();
        std::optional<Preview::Protocols::ProviderRetirementResult> BindingDrain;
        std::exception_ptr BindingException;
        Net::co_spawn(Context->Io, Binding.Drain(),
            [&BindingDrain, &BindingException](std::exception_ptr Error, auto Result)
            {
                BindingException = std::move(Error);
                BindingDrain.emplace(std::move(Result));
            });
        Context->Io.run();
        EXPECT_FALSE(BindingException);
        ASSERT_TRUE(BindingDrain.has_value());
        ASSERT_FALSE(*BindingDrain);
        EXPECT_EQ(BindingDrain->error().Code, Preview::Fault::Code::IoError);
        EXPECT_TRUE(Binding.IsRetired());
    }

    TEST(ProviderSessionRetirement, CanceledCloseCommandDoesNotFailAfterPhysicalRetirement)
    {
        auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
        const auto Context = Preview::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const ProviderRetirementTestMaterial>(
            ProviderRetirementTestMaterial{
                std::make_shared<ProviderRetirementTestGeneration>(), UseState, Executor});
        auto Activity = std::make_shared<ProviderRetirementCanceledRetiredActivity>(Executor);
        auto Transport = std::make_shared<ProviderRetirementTestTransmission>(Executor, Activity);
        Preview::Protocols::ProviderSessionResources Resources(Transport);
        Activity->Seal();
        EXPECT_TRUE(Resources.IsRetired(nullptr));

        auto Ticket = std::make_shared<ProviderRetirementTestBinding::Ticket>(
            Transport, Material, Preview::Foundation::GenerationUseLease{});
        Ticket->RecordDrainAttemptFailure(
            Preview::Fault::Failure{Preview::Fault::Code::Canceled});
        EXPECT_TRUE(Ticket->DrainFailure().Succeeded());
        Ticket->RecordDrainAttemptFailure(
            Preview::Fault::Failure{Preview::Fault::Code::IoError});
        EXPECT_EQ(Ticket->DrainFailure().Code, Preview::Fault::Code::IoError);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }

}
