/** @file ActiveTransportsMuxCloseTest.cpp @brief 验证 Mux 正常退休与拒绝取消的分流。 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <utility>

#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>

namespace
{
    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;

    struct MuxCloseState final
    {
        std::atomic<std::size_t> CancelCalls{0U};
        std::atomic<std::size_t> CloseCalls{0U};
        std::atomic<bool> Sealed{false};
        std::atomic<bool> Retired{false};
    };

    class MuxCloseActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        MuxCloseActivity(Net::any_io_executor Executor,
            std::shared_ptr<MuxCloseState> State)
            : Executor_(std::move(Executor)), State_(std::move(State)) {}

        auto Seal() noexcept -> void override
        { State_->Sealed.store(true, std::memory_order_release); }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return State_->Retired.load(std::memory_order_acquire); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return Executor_; }

        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Failure>> override
        {
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            if (!State_->Sealed.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            State_->Retired.store(true, std::memory_order_release);
            co_return std::expected<void, Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<MuxCloseState> State_;
    };

    class MuxCloseProbe final : public Prism::Contract::MuxSession
    {
    public:
        MuxCloseProbe(Net::any_io_executor Executor,
            std::shared_ptr<MuxCloseState> State)
            : State_(std::move(State)),
              Activity_(std::make_shared<MuxCloseActivity>(std::move(Executor), State_)) {}

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        { return Activity_; }

        [[nodiscard]] auto Run(Prism::Contract::MuxRootRequest Request)
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            (void)Request;
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Activity_->IsRetired(); }

        auto Cancel() noexcept -> void override
        { State_->CancelCalls.fetch_add(1U, std::memory_order_relaxed); }

        auto Close() noexcept -> void override
        { State_->CloseCalls.fetch_add(1U, std::memory_order_relaxed); }

    private:
        std::shared_ptr<MuxCloseState> State_;
        std::shared_ptr<MuxCloseActivity> Activity_;
    };

    TEST(ActiveTransportsMuxClose, FinalizeClosesWithoutRequestingCancellation)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<MuxCloseState>();
        auto Mux = std::make_shared<MuxCloseProbe>(Context->Io.get_executor(), State);
        const auto Activity = Mux->Activity();
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Activity->Executor(), Activity);
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        auto Stored = Active.StoreMux(Mux, *Domain);
        ASSERT_TRUE(Stored);
        Stored->reset();
        auto Outcome = std::expected<void, Failure>{
            std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        std::exception_ptr Exception;
        Net::co_spawn(Context->Io, Active.Finalize(),
            [&Outcome, &Exception](std::exception_ptr Error, std::expected<void, Failure> Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Context->Io.run();

        EXPECT_FALSE(Exception);
        ASSERT_TRUE(Outcome);
        EXPECT_EQ(State->CancelCalls.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
        EXPECT_TRUE(Mux->IsRetired());
    }

    TEST(ActiveTransportsMuxClose, RejectedMuxStillReceivesCancellation)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto RejectedState = std::make_shared<MuxCloseState>();
        auto DomainState = std::make_shared<MuxCloseState>();
        auto Rejected = std::make_shared<MuxCloseProbe>(Context->Io.get_executor(), RejectedState);
        auto DomainMux = std::make_shared<MuxCloseProbe>(Context->Io.get_executor(), DomainState);
        const auto DomainActivity = DomainMux->Activity();
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            DomainActivity->Executor(), DomainActivity);
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        const auto Stored = Active.StoreMux(Rejected, *Domain);
        ASSERT_FALSE(Stored);
        EXPECT_EQ(Stored.error().Code, Prism::Fault::Code::InvalidArgument);
        Context->Io.run();

        EXPECT_EQ(RejectedState->CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_EQ(RejectedState->CloseCalls.load(std::memory_order_acquire), 1U);
        EXPECT_TRUE(Rejected->IsRetired());
        EXPECT_EQ(DomainState->CancelCalls.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(DomainState->CloseCalls.load(std::memory_order_acquire), 0U);
    }
}
