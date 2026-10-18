/** @file CarrierActivityReceiptTest.cpp @brief 真实 Run 回执与历史错误相互独立的组合回归。 */
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Transport/Detail/ActivityGroup.hpp>
#include <Prism/Transport/Detail/ForwardActivity.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
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
    auto Group = std::make_shared<Prism::Transport::Detail::ActivityGroup>(Parent,
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
    auto Group = std::make_shared<Prism::Transport::Detail::ActivityGroup>(Parent,
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
    auto Group = std::make_shared<Prism::Transport::Detail::ActivityGroup>(Parent,
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
    auto Group = std::make_shared<Prism::Transport::Detail::ActivityGroup>(Parent,
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
    auto Group = std::make_shared<Prism::Transport::Detail::ActivityGroup>(Parent,
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
    auto Forward = std::make_shared<Prism::Transport::Detail::ForwardActivity>(Parent, Child);
    Forward->RequireChildDrain();
    const auto Outcome = Drain(Io, Forward);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_EQ(Child->DrainCalls, 1U);
    EXPECT_TRUE(Forward->IsRetired());
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
    auto Forward = std::make_shared<Prism::Transport::Detail::ForwardActivity>(Parent, Child);
    Forward->RequireChildDrain();
    std::optional<Result> Outcome;
    std::exception_ptr Exception;
    Net::co_spawn(Io, Forward->Drain(), [&](std::exception_ptr Error, Result Value)
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
    EXPECT_TRUE(Forward->IsRetired());
}
