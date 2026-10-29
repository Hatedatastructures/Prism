/** @file ReplayCloseTest.cpp @brief Replay 接管关闭时传播底层失败并保持 drain 责任。 */
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Activity/Io.hpp>
#include <Prism/Transport/Replay.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

#include "../Core/Resources.hpp"

namespace
{
    namespace Net = boost::asio;
    using Result = std::expected<void, Prism::Fault::Failure>;

    class ChildDrainProbe final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit ChildDrainProbe(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}
        auto Seal() noexcept -> void override {}
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }
        [[nodiscard]] auto Drain() -> Net::awaitable<Result> override
        {
            ++DrainCalls_;
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        [[nodiscard]] auto DrainCalls() const noexcept -> std::size_t { return DrainCalls_; }
    private:
        Net::any_io_executor Executor_;
        std::size_t DrainCalls_{0};
    };

    struct InnerCloseState final
    {
        Prism::Fault::Failure Failure{Prism::Fault::FromNative(
            std::make_error_code(std::errc::connection_reset))};
        std::atomic<std::size_t> CloseCalls{0};
        std::atomic<bool> Open{true};
    };

    class FailingInnerTransmission final : public Prism::Transmission
    {
    public:
        FailingInnerTransmission(Net::any_io_executor Executor,
            std::shared_ptr<InnerCloseState> State, std::shared_ptr<ChildDrainProbe> Activity)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              State_(std::move(State)), Activity_(std::move(Activity)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        { return State_->CloseCalls.load(std::memory_order_acquire); }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {0, {Prism::Fault::Code::Eof}}); }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {Buffer.size(), {}}); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {}); }
        [[nodiscard]] auto IsOpen() const -> bool override
        { return State_->Open.load(std::memory_order_acquire); }
    protected:
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Call = State_->CloseCalls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (Call == 1) return std::unexpected(State_->Failure);
            State_->Open.store(false, std::memory_order_release);
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }
    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<InnerCloseState> State_;
        std::shared_ptr<ChildDrainProbe> Activity_;
    };

    struct ReplayCloseScenario final
    {
        std::shared_ptr<Prism::Transport::ReplayTransmission> Replay;
        std::shared_ptr<FailingInnerTransmission> Inner;
        std::shared_ptr<ChildDrainProbe> ChildActivity;
        Prism::Fault::Failure Expected;
        std::optional<Prism::Transmission::ControlResult> CloseResult;
        std::optional<Result> ParentDrain;
    };

    auto RunAcceptedInnerCloseFailure(std::shared_ptr<ReplayCloseScenario> Scenario)
        -> Net::awaitable<void>
    {
        Scenario->CloseResult.emplace(co_await Scenario->Replay->CloseUnderlying());
        EXPECT_FALSE(*Scenario->CloseResult);
        if (*Scenario->CloseResult)
        {
            ADD_FAILURE() << "CloseUnderlying reported success after the accepted inner close failed";
            co_return;
        }
        EXPECT_EQ(Scenario->CloseResult->error().Code, Scenario->Expected.Code);
        EXPECT_EQ(Scenario->CloseResult->error().Native, Scenario->Expected.Native);
        EXPECT_EQ(Scenario->Inner->CloseCalls(), 1U);

        // 只退休 wrapper parent，检查失败 child 是否被错误登记为 Replay 的关闭责任。
        auto Parent = std::dynamic_pointer_cast<Prism::Transport::Detail::IoActivity>(
            Scenario->Replay->Prism::Transmission::Activity());
        if (!Parent)
        {
            ADD_FAILURE() << "Replay parent activity was unavailable";
            co_return;
        }
        Parent->RecordCloseAccepted();
        Parent->Seal();
        Parent->RecordCloseDelivered();
        Scenario->ParentDrain.emplace(co_await Scenario->Replay->Activity()->Drain());
    }
}

TEST(Snapshot, AcceptedInnerCloseFailurePreservesNativeCauseWithoutChildDrain)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<InnerCloseState>();
    auto ChildActivity = std::make_shared<ChildDrainProbe>(Context->Io.get_executor());
    auto Inner = std::make_shared<FailingInnerTransmission>(
        Context->Io.get_executor(), State, ChildActivity);
    const auto Expected = State->Failure;
    auto Replay = Prism::Transport::ReplayTransmission::Create(
        Inner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                Prism::Testing::MakeTransportBytes()}).value();
    auto Scenario = std::make_shared<ReplayCloseScenario>(
        ReplayCloseScenario{Replay, Inner, ChildActivity, Expected, {}, {}});

    std::exception_ptr Exception;
    Net::co_spawn(Context->Io, RunAcceptedInnerCloseFailure(Scenario),
        [&Exception, Context](std::exception_ptr Error)
        {
            Exception = std::move(Error);
            Context->Io.stop();
        });
    // 子载体关闭失败后会保留到显式重试，完成回调处停止本轮调度。
    Context->Io.run();

    ASSERT_EQ(Exception, nullptr);
    ASSERT_TRUE(Scenario->CloseResult.has_value());
    ASSERT_FALSE(*Scenario->CloseResult);
    EXPECT_EQ(Scenario->CloseResult->error().Native, Expected.Native);
    ASSERT_TRUE(Scenario->ParentDrain.has_value());
    EXPECT_TRUE(*Scenario->ParentDrain);
    EXPECT_EQ(ChildActivity->DrainCalls(), 0U);
    EXPECT_TRUE(Replay->Activity()->IsRetired());
    EXPECT_EQ(Inner->CloseCalls(), 1U);

    Context->Io.restart();
    Storage->Retry();
    Context->Io.run();
    EXPECT_EQ(Inner->CloseCalls(), 2U);
    EXPECT_FALSE(Inner->IsOpen());
    EXPECT_EQ(Storage->Pending(), 0U);
}
