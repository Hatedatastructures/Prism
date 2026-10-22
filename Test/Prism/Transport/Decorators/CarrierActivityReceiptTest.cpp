/** @file CarrierActivityReceiptTest.cpp @brief 真实 Run 回执与历史错误相互独立的组合回归。 */
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>
#include <Prism/Transport/Detail/TransmissionControl.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Result = std::expected<void, Prism::Fault::Failure>;
    /** @brief 证明组合器拒绝 Drain 成功但无物理退休回执的成员。 */
    class DrainOnlyActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit DrainOnlyActivity(Net::any_io_executor Executor,
            Prism::Fault::Failure Failure = {}) : Executor_(std::move(Executor)), Failure_(Failure) {}
        auto Seal() noexcept -> void override { ++SealCalls; }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }
        [[nodiscard]] auto Drain() -> Net::awaitable<Result> override
        {
            ++DrainCalls;
            Seal();
            if (Failure_.Failed()) co_return std::unexpected(Failure_);
            co_return Result{};
        }
        std::size_t SealCalls{0}, DrainCalls{0};
    private:
        Net::any_io_executor Executor_;
        Prism::Fault::Failure Failure_;
    };
    /** @brief 注入历史结果但不伪造底层 ProtocolActivity 的物理回执。 */
    class HistoricalActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        HistoricalActivity(std::shared_ptr<Prism::Protocols::ProtocolActivity> Inner,
            Prism::Fault::Failure Failure) : Inner_(std::move(Inner)), Failure_(Failure) {}
        auto Seal() noexcept -> void override { Inner_->Seal(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Inner_->Executor(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Inner_->IsRetired(); }
        [[nodiscard]] auto Drain() -> Net::awaitable<Result> override
        {
            ++DrainCalls;
            const auto Drained = co_await Inner_->Drain();
            if (Failure_.Failed()) co_return std::unexpected(Failure_);
            co_return Drained;
        }
        std::size_t DrainCalls{0};
    private:
        std::shared_ptr<Prism::Protocols::ProtocolActivity> Inner_;
        Prism::Fault::Failure Failure_;
    };
    /** @brief 驱动真实异步 Drain 到 completion，完整等待全部协程退栈。 */
    auto Drain(Net::io_context& Io, std::shared_ptr<Prism::Contract::CarrierActivity> Activity) -> Result
    {
        std::optional<Result> Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, Activity->Drain(), [&](std::exception_ptr Error, Result Value)
        { Exception = std::move(Error); Outcome.emplace(std::move(Value)); });
        Io.run();
        EXPECT_EQ(Exception, nullptr);
        EXPECT_TRUE(Outcome.has_value());
        if (!Outcome) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        return *Outcome;
    }

    enum class CloseAction : std::uint8_t { Succeed, ReturnFailure, Throw };

    struct CloseActionState final
    {
        CloseAction First{CloseAction::Succeed};
        Prism::Fault::Failure Failure{Prism::Fault::FromNative(
            std::make_error_code(std::errc::connection_reset))};
        std::atomic<std::size_t> Calls{0};
        std::atomic<bool> Open{true};
    };

    class CloseReceiptProbe final : public Prism::Transmission
    {
    public:
        CloseReceiptProbe(Net::any_io_executor Executor, std::shared_ptr<CloseActionState> State)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }
        [[nodiscard]] auto Receipt() const -> std::shared_ptr<Prism::Contract::CarrierCloseReceipt>
        { return CloseReceipt(); }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {0, {Prism::Fault::Code::Eof}}); }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {0, {}}); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor_, std::move(Handler), {}); }
        [[nodiscard]] auto IsOpen() const -> bool override
        { return State_->Open.load(std::memory_order_acquire); }
    protected:
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Call = State_->Calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (Call == 1 && State_->First == CloseAction::ReturnFailure)
                return std::unexpected(State_->Failure);
            if (Call == 1 && State_->First == CloseAction::Throw)
                throw std::runtime_error("close action failed");
            State_->Open.store(false, std::memory_order_release);
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }
    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<CloseActionState> State_;
    };

    struct CloseReceiptWait final
    {
        std::optional<Result> Value;
        std::exception_ptr Exception;
        std::size_t Completions{0};
    };

    auto StartCloseReceiptWaiter(Net::io_context& Io,
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt,
        CloseReceiptWait& Wait) -> void
    {
        Net::co_spawn(Io, Receipt->AwaitCloseDispatch(), [&Wait](std::exception_ptr Error, Result Value)
        {
            ++Wait.Completions;
            Wait.Exception = std::move(Error);
            Wait.Value.emplace(std::move(Value));
        });
    }

    auto AwaitCloseReceiptNow(Net::io_context& Io,
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt) -> CloseReceiptWait
    {
        CloseReceiptWait Wait;
        Io.restart();
        StartCloseReceiptWaiter(Io, std::move(Receipt), Wait);
        Io.run();
        return Wait;
    }

    auto VerifyRejectedCloseReceipt(Prism::Fault::Failure Expected) -> void
    {
        Net::io_context Io;
        auto State = std::make_shared<CloseActionState>();
        auto Carrier = std::make_shared<CloseReceiptProbe>(Io.get_executor(), State);
        Carrier->Activity()->Seal();
        const auto Closed = Carrier->Close();
        ASSERT_FALSE(Closed);
        EXPECT_EQ(Closed.error().Code, Expected.Code);
        CloseReceiptWait Wait;
        Net::io_context WaitIo;
        Wait = AwaitCloseReceiptNow(WaitIo, Carrier->Receipt());
        ASSERT_EQ(Wait.Completions, 1U);
        ASSERT_TRUE(Wait.Value.has_value());
        ASSERT_FALSE(*Wait.Value);
        EXPECT_EQ(Wait.Value->error().Code, Expected.Code);
        EXPECT_EQ(Wait.Value->error().Native, Expected.Native);
        EXPECT_EQ(State->Calls.load(std::memory_order_acquire), 0U);
    }

    auto VerifyFailedCloseReceipt(CloseAction First, Prism::Fault::Failure Expected) -> void
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<CloseActionState>();
        State->First = First;
        State->Failure = Expected;
        auto Carrier = std::make_shared<CloseReceiptProbe>(Context->Io.get_executor(), State);
        const auto Closed = Carrier->Close();
        ASSERT_TRUE(Closed);
        // 失败关闭按设计保留 owner 和预约供显式重试，run() 会等待该保留工作；
        // 这里只驱动已投递的关闭交付，再验证首因回执。
        Context->Io.poll();

        Net::io_context WaitIo;
        auto Wait = AwaitCloseReceiptNow(WaitIo, Carrier->Receipt());
        ASSERT_EQ(Wait.Completions, 1U);
        ASSERT_EQ(Wait.Exception, nullptr);
        ASSERT_TRUE(Wait.Value.has_value());
        ASSERT_FALSE(*Wait.Value);
        EXPECT_EQ(Wait.Value->error().Code, Expected.Code);
        EXPECT_EQ(Wait.Value->error().Native, Expected.Native);

        auto Owner = std::dynamic_pointer_cast<Prism::Transport::Detail::TransmissionControlOwner>(
            Carrier->Receipt());
        ASSERT_TRUE(Owner);
        Context->Io.restart();
        Storage->Retry();
        while (Owner->CloseAttempt.load(std::memory_order_acquire) ==
                   Prism::Transport::Detail::TransmissionControlOwner::CloseAttemptPhase::Terminal &&
               Context->Io.poll_one() != 0U)
        {
        }
        EXPECT_EQ(Owner->CloseAttempt.load(std::memory_order_acquire),
            Prism::Transport::Detail::TransmissionControlOwner::CloseAttemptPhase::Posting);
        CloseReceiptWait RetryWait;
        Net::io_context RetryIo;
        StartCloseReceiptWaiter(RetryIo, Carrier->Receipt(), RetryWait);
        ASSERT_EQ(RetryIo.poll_one(), 1U);
        EXPECT_EQ(Owner->CloseAttemptWaiters.load(std::memory_order_acquire), 1U);
        Context->Io.run();
        RetryIo.run();
        EXPECT_EQ(State->Calls.load(std::memory_order_acquire), 2U);
        ASSERT_EQ(RetryWait.Completions, 1U);
        ASSERT_TRUE(RetryWait.Value.has_value());
        ASSERT_FALSE(*RetryWait.Value);
        EXPECT_EQ(RetryWait.Value->error().Code, Expected.Code);
        EXPECT_EQ(RetryWait.Value->error().Native, Expected.Native);
        Wait = AwaitCloseReceiptNow(WaitIo, Carrier->Receipt());
        ASSERT_EQ(Wait.Completions, 1U);
        ASSERT_TRUE(Wait.Value.has_value());
        ASSERT_FALSE(*Wait.Value);
        EXPECT_EQ(Wait.Value->error().Code, Expected.Code);
        EXPECT_EQ(Wait.Value->error().Native, Expected.Native);
        EXPECT_EQ(Storage->Pending(), 0U);
    }
}

TEST(CarrierActivityReceipt, GroupDrainsAllChildrenAndPreservesHistoricalNativeFailure)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto ParentRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto LastRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto Reservation = ChildRun->TryBegin();
    ASSERT_TRUE(Reservation);
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Prism::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Prism::Fault::Failure{});
    auto Last = std::make_shared<HistoricalActivity>(LastRun, Prism::Fault::Failure{});
    auto Group = Prism::Transport::MakeActivityGroup(Parent,
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{Child, Last});
    Group->Seal();
    EXPECT_FALSE(Group->IsRetired());
    Reservation->Complete();
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_EQ(Parent->DrainCalls, 1U);
    EXPECT_EQ(Child->DrainCalls, 1U);
    EXPECT_EQ(Last->DrainCalls, 1U);
    EXPECT_TRUE(Group->IsRetired());
}

TEST(CarrierActivityReceipt, UnknownChildBlocksRetirementAndRemainingChildStillDrains)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    auto ParentRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto LastRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    ChildRun->Block();
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Prism::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Prism::Fault::Failure{});
    auto Last = std::make_shared<HistoricalActivity>(LastRun, Prism::Fault::Failure{});
    auto Group = Prism::Transport::MakeActivityGroup(Parent,
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{Child, Last});
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_FALSE(Group->IsRetired());
    EXPECT_EQ(Last->DrainCalls, 1U);
    EXPECT_TRUE(Last->IsRetired());
}

/** @brief 组合Drain不能把成员缺少的物理退休回执折叠为成功。 */
TEST(CarrierActivityReceipt, GroupDrainRejectsSuccessWithoutRetirement)
{
    Net::io_context Io;
    auto Parent = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto Child = std::make_shared<DrainOnlyActivity>(Io.get_executor());
    auto Group = Prism::Transport::MakeActivityGroup(Parent,
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{Child});
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_FALSE(Group->IsRetired());
}

/** @brief 未退休的 Parent 仍可启动子 I/O，Group 必须先保留 Child 准入。 */
TEST(CarrierActivityReceipt, ParentWithoutRetirementKeepsChildrenUnsealed)
{
    Net::io_context Io;
    auto Parent = std::make_shared<DrainOnlyActivity>(Io.get_executor());
    auto Child = std::make_shared<DrainOnlyActivity>(Io.get_executor());
    auto Group = Prism::Transport::MakeActivityGroup(Parent,
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{Child});
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(Parent->DrainCalls, 1U);
    EXPECT_EQ(Child->SealCalls, 0U);
    EXPECT_EQ(Child->DrainCalls, 0U);
}

/** @brief Parent 未退休且报告首因时保留该错误，并让 Child 继续准入。 */
TEST(CarrierActivityReceipt, ParentFailureWithoutRetirementPreservesCause)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_aborted);
    auto Parent = std::make_shared<DrainOnlyActivity>(
        Io.get_executor(), Prism::Fault::FromNative(Native));
    auto Child = std::make_shared<DrainOnlyActivity>(Io.get_executor());
    auto Group = Prism::Transport::MakeActivityGroup(Parent,
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{Child});
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_EQ(Child->SealCalls, 0U);
    EXPECT_EQ(Child->DrainCalls, 0U);
}

TEST(CarrierActivityReceipt, ForwardedCloseDrainsChildDespiteHistoricalParentFailure)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_aborted);
    auto ParentRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Prism::Protocols::ProtocolActivity>(Io.get_executor());
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Prism::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Prism::Fault::Failure{});
    Prism::Transport::ForwardActivityOwner Forward(Parent, Child);
    Forward.RequireChildDrain();
    const auto Outcome = Drain(Io, Forward.Activity());
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_EQ(Child->DrainCalls, 1U);
    EXPECT_TRUE(Forward.Activity()->IsRetired());
}

/** @brief 已受理的关闭尚未交付时，成功 Drain 必须等待关闭回执。 */
TEST(CarrierActivityReceipt, AcceptedCloseWaitsForDeliveryBeforeSuccessfulDrain)
{
    Net::io_context Io;
    auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(Io.get_executor());
    Activity->RecordCloseAccepted();
    Activity->Seal();
    std::optional<Result> Outcome;
    std::exception_ptr Exception;
    bool RetiredAtReturn = false;
    Net::co_spawn(Io, Activity->Drain(), [&](std::exception_ptr Error, Result Value)
    {
        Exception = std::move(Error);
        Outcome.emplace(std::move(Value));
        RetiredAtReturn = Activity->IsRetired();
    });
    ASSERT_EQ(Io.run_one(), 1U);
    EXPECT_FALSE(Outcome.has_value());
    EXPECT_FALSE(Activity->IsRetired());
    Activity->RecordCloseDelivered();
    Io.run();
    EXPECT_EQ(Exception, nullptr);
    ASSERT_TRUE(Outcome.has_value());
    EXPECT_TRUE(*Outcome);
    EXPECT_TRUE(RetiredAtReturn);
}

/** @brief 只排空借用层操作时，不要求它执行或等待底层关闭。 */
TEST(CarrierActivityReceipt, DrainWithoutCloseRequestDoesNotWaitForCloseReceipt)
{
    Net::io_context Io;
    auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(Io.get_executor());
    Activity->Seal();
    const auto Outcome = Drain(Io, Activity);
    ASSERT_TRUE(Outcome);
    EXPECT_FALSE(Activity->IsRetired());
}

/** @brief TLS操作活动等全部预约退栈即可退休，不需要伪造底层关闭回执。 */
TEST(CarrierActivityReceipt, OperationsDrainedActivityWaitsForOperationsAndRetires)
{
    Net::io_context Io;
    using ActivityType = Prism::Transport::Detail::IoActivity;
    auto Activity = std::make_shared<ActivityType>(Io.get_executor(),
        ActivityType::RetirementPolicy::OperationsDrained);
    auto Acquired = Activity->TryAcquire(std::make_shared<int>(1));
    ASSERT_TRUE(Acquired);
    std::optional<ActivityType::Operation> Operation{std::move(*Acquired)};
    Activity->Seal();
    std::optional<Result> Outcome;
    std::exception_ptr Exception;
    Net::co_spawn(Io, Activity->Drain(), [&](std::exception_ptr Error, Result Value)
    {
        Exception = std::move(Error);
        Outcome.emplace(std::move(Value));
    });
    ASSERT_EQ(Io.run_one(), 1U);
    EXPECT_FALSE(Outcome.has_value());
    EXPECT_FALSE(Activity->IsRetired());
    Operation->Returned();
    Operation.reset();
    Io.run();
    EXPECT_EQ(Exception, nullptr);
    ASSERT_TRUE(Outcome.has_value());
    EXPECT_TRUE(*Outcome);
    EXPECT_TRUE(Activity->IsRetired());
}


/** @brief 转交关闭的 child 回执未到时，ForwardActivity 不得宣称整条链退休。 */
TEST(CarrierActivityReceipt, ForwardedChildWaitsForAcceptedCloseDelivery)
{
    Net::io_context Io;
    auto Parent = std::make_shared<Prism::Transport::Detail::IoActivity>(Io.get_executor());
    auto Child = std::make_shared<Prism::Transport::Detail::IoActivity>(Io.get_executor());
    Parent->RecordCloseAccepted();
    Parent->Seal();
    Parent->RecordCloseDelivered();
    Child->RecordCloseAccepted();
    Child->Seal();
    Prism::Transport::ForwardActivityOwner Forward(Parent, Child);
    Forward.RequireChildDrain();
    std::optional<Result> Outcome;
    std::exception_ptr Exception;
    Net::co_spawn(Io, Forward.Activity()->Drain(), [&](std::exception_ptr Error, Result Value)
    {
        Exception = std::move(Error);
        Outcome.emplace(std::move(Value));
    });
    ASSERT_EQ(Io.run_one(), 1U);
    EXPECT_FALSE(Outcome.has_value());
    EXPECT_TRUE(Parent->IsRetired());
    EXPECT_FALSE(Child->IsRetired());
    Child->RecordCloseDelivered();
    Io.run();
    EXPECT_EQ(Exception, nullptr);
    ASSERT_TRUE(Outcome.has_value());
    EXPECT_TRUE(*Outcome);
    EXPECT_TRUE(Forward.Activity()->IsRetired());
}

TEST(CarrierCloseReceipt, IdleReceiptIsImmediateAndTerminalFailureBroadcasts)
{
    Net::io_context Io;
    auto Activity = std::make_shared<Prism::Transport::Detail::IoActivity>(Io.get_executor());
    auto Owner = std::make_shared<Prism::Transport::Detail::TransmissionControlOwner>(
        Io.get_executor(), Activity);
    std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt = Owner;
    const auto Idle = AwaitCloseReceiptNow(Io, Receipt);
    ASSERT_EQ(Idle.Completions, 1U);
    ASSERT_TRUE(Idle.Value.has_value());
    EXPECT_TRUE(*Idle.Value);

    Io.restart();
    ASSERT_TRUE(Owner->BeginCloseAttempt());
    CloseReceiptWait First, Second, Late;
    StartCloseReceiptWaiter(Io, Receipt, First);
    ASSERT_EQ(Io.poll_one(), 1U);
    EXPECT_EQ(Owner->CloseAttemptWaiters.load(std::memory_order_acquire), 1U);
    StartCloseReceiptWaiter(Io, Receipt, Second);
    ASSERT_EQ(Io.poll_one(), 1U);
    EXPECT_EQ(Owner->CloseAttemptWaiters.load(std::memory_order_acquire), 2U);

    const auto Native = std::make_error_code(std::errc::connection_reset);
    Owner->CompleteCloseAttempt(Prism::Fault::FromNative(Native));
    Owner->CompleteCloseAttempt({Prism::Fault::Code::Blocked});
    Io.run();
    for (const auto* Wait : std::array{&First, &Second})
    {
        ASSERT_EQ(Wait->Completions, 1U);
        ASSERT_EQ(Wait->Exception, nullptr);
        ASSERT_TRUE(Wait->Value.has_value());
        ASSERT_FALSE(*Wait->Value);
        EXPECT_EQ(Wait->Value->error().Native, Native);
    }

    Late = AwaitCloseReceiptNow(Io, Receipt);
    ASSERT_EQ(Late.Completions, 1U);
    ASSERT_TRUE(Late.Value.has_value());
    ASSERT_FALSE(*Late.Value);
    EXPECT_EQ(Late.Value->error().Native, Native);
}

TEST(CarrierCloseReceipt, SynchronousCloseRejectionsAreSticky)
{
    const Prism::Fault::Failure NoOwner{Prism::Fault::Code::InvalidArgument};
    VerifyRejectedCloseReceipt({Prism::Fault::Code::Canceled});

    Net::io_context Io;
    auto State = std::make_shared<CloseActionState>();
    CloseReceiptProbe StackCarrier(Io.get_executor(), State);
    const auto Rejected = StackCarrier.Close();
    ASSERT_FALSE(Rejected);
    EXPECT_EQ(Rejected.error().Code, NoOwner.Code);
    Net::io_context WaitIo;
    const auto Wait = AwaitCloseReceiptNow(WaitIo, StackCarrier.Receipt());
    ASSERT_EQ(Wait.Completions, 1U);
    ASSERT_TRUE(Wait.Value.has_value());
    ASSERT_FALSE(*Wait.Value);
    EXPECT_EQ(Wait.Value->error().Code, NoOwner.Code);
    EXPECT_EQ(State->Calls.load(std::memory_order_acquire), 0U);
}

TEST(CarrierCloseReceipt, NativeCloseFailureRemainsFirstAfterSuccessfulRetry)
{
    const auto Failure = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    VerifyFailedCloseReceipt(CloseAction::ReturnFailure, Failure);
}

TEST(CarrierCloseReceipt, ThrownCloseActionPublishesBlockedAndRemainsSticky)
{
    VerifyFailedCloseReceipt(CloseAction::Throw, {Prism::Fault::Code::Blocked});
}

TEST(CarrierCloseReceipt, AcceptedQuarantinedDeliveryWakesPendingWaiter)
{
    // quarantine 是进程终态保留；使用终态 storage，避免测试结束时析构真实保留的 executor owner。
    auto Storage = Prism::Executor::ClosingStorage::ProcessStorage();
    const auto RetainedBefore = Storage->Pending();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<CloseActionState>();
    auto Carrier = std::make_shared<CloseReceiptProbe>(Context->Io.get_executor(), State);
    auto Activity = std::dynamic_pointer_cast<Prism::Transport::Detail::IoActivity>(
        Carrier->Activity());
    ASSERT_TRUE(Activity);
    auto Owner = std::make_shared<Prism::Transport::Detail::TransmissionControlOwner>(
        Context->Io.get_executor(), Activity);
    ASSERT_TRUE(Owner->BeginCloseAttempt());
    std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt = Owner;
    CloseReceiptWait Wait;
    Net::io_context WaitIo;
    StartCloseReceiptWaiter(WaitIo, Receipt, Wait);
    ASSERT_EQ(WaitIo.poll_one(), 1U);
    EXPECT_EQ(Owner->CloseAttemptWaiters.load(std::memory_order_acquire), 1U);

    const auto Submitted = Owner->Submit(Carrier,
        Prism::Transport::Detail::TransmissionControlOwner::CloseFlag);
    ASSERT_TRUE(Submitted);
    Owner->Reclaimer->Quarantine();
    // quarantine 后动作被隔离、owner 按设计保留；只排空当前就绪隔离动作。
    Context->Io.poll();
    WaitIo.run();
    ASSERT_EQ(Wait.Completions, 1U);
    ASSERT_TRUE(Wait.Value.has_value());
    ASSERT_FALSE(*Wait.Value);
    EXPECT_EQ(Wait.Value->error().Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(State->Calls.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(Storage->Pending(), RetainedBefore + 2U);
    EXPECT_TRUE(Storage->IsSealed());
}

TEST(CarrierCloseReceipt, AcceptedCloseWaitsForResumedExecutor)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<CloseActionState>();
    auto Carrier = std::make_shared<CloseReceiptProbe>(Context->Io.get_executor(), State);
    ASSERT_TRUE(Carrier->Close());
    Context->Io.stop();

    Net::io_context WaitIo;
    CloseReceiptWait Wait;
    StartCloseReceiptWaiter(WaitIo, Carrier->Receipt(), Wait);
    ASSERT_EQ(WaitIo.poll_one(), 1U);
    EXPECT_EQ(Wait.Completions, 0U);

    Context->Io.restart();
    Context->Io.run();
    WaitIo.run();
    ASSERT_EQ(Wait.Completions, 1U);
    ASSERT_EQ(Wait.Exception, nullptr);
    ASSERT_TRUE(Wait.Value.has_value());
    EXPECT_TRUE(*Wait.Value);
    EXPECT_EQ(State->Calls.load(std::memory_order_acquire), 1U);
    EXPECT_EQ(Storage->Pending(), 0U);
}
