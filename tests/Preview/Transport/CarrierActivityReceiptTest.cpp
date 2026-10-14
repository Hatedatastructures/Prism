/** @file CarrierActivityReceiptTest.cpp @brief 真实 Run 回执与历史错误相互独立的组合回归。 */
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <Preview/Transport/Detail/ActivityGroup.hpp>
#include <Preview/Transport/Detail/ForwardActivity.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>

namespace
{
    namespace Net = boost::asio;
    using Result = std::expected<void, Preview::Fault::Failure>;
    /** @brief 注入历史结果但不伪造底层 ProtocolActivity 的物理回执。 */
    class HistoricalActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        HistoricalActivity(std::shared_ptr<Preview::Protocols::ProtocolActivity> Inner,
            Preview::Fault::Failure Failure) : Inner_(std::move(Inner)), Failure_(Failure) {}
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
        std::shared_ptr<Preview::Protocols::ProtocolActivity> Inner_;
        Preview::Fault::Failure Failure_;
    };
    /** @brief 驱动真实异步 Drain 到 completion，完整等待全部协程退栈。 */
    auto Drain(Net::io_context& Io, std::shared_ptr<Preview::Contract::CarrierActivity> Activity) -> Result
    {
        std::optional<Result> Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, Activity->Drain(), [&](std::exception_ptr Error, Result Value)
        { Exception = std::move(Error); Outcome.emplace(std::move(Value)); });
        Io.run();
        EXPECT_EQ(Exception, nullptr);
        EXPECT_TRUE(Outcome.has_value());
        if (!Outcome) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        return *Outcome;
    }
}

TEST(CarrierActivityReceipt, GroupDrainsAllChildrenAndPreservesHistoricalNativeFailure)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto ParentRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto LastRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto Reservation = ChildRun->TryBegin();
    ASSERT_TRUE(Reservation);
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Preview::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Preview::Fault::Failure{});
    auto Last = std::make_shared<HistoricalActivity>(LastRun, Preview::Fault::Failure{});
    auto Group = std::make_shared<Preview::Transport::Detail::ActivityGroup>(Parent,
        std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>>{Child, Last});
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
    auto ParentRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto LastRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    ChildRun->Block();
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Preview::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Preview::Fault::Failure{});
    auto Last = std::make_shared<HistoricalActivity>(LastRun, Preview::Fault::Failure{});
    auto Group = std::make_shared<Preview::Transport::Detail::ActivityGroup>(Parent,
        std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>>{Child, Last});
    const auto Outcome = Drain(Io, Group);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_FALSE(Group->IsRetired());
    EXPECT_EQ(Last->DrainCalls, 1U);
    EXPECT_TRUE(Last->IsRetired());
}

TEST(CarrierActivityReceipt, ForwardedCloseDrainsChildDespiteHistoricalParentFailure)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_aborted);
    auto ParentRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto ChildRun = std::make_shared<Preview::Protocols::ProtocolActivity>(Io.get_executor());
    auto Parent = std::make_shared<HistoricalActivity>(ParentRun, Preview::Fault::FromNative(Native));
    auto Child = std::make_shared<HistoricalActivity>(ChildRun, Preview::Fault::Failure{});
    auto Forward = std::make_shared<Preview::Transport::Detail::ForwardActivity>(Parent, Child);
    Forward->RequireChildDrain();
    const auto Outcome = Drain(Io, Forward);
    ASSERT_FALSE(Outcome);
    EXPECT_EQ(Outcome.error().Native, Native);
    EXPECT_EQ(Child->DrainCalls, 1U);
    EXPECT_TRUE(Forward->IsRetired());
}
