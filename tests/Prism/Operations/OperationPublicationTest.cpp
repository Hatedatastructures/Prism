/** @file OperationPublicationTest.cpp @brief 终态提交事实与等待者通知失败的独立回执。 */
#include <gtest/gtest.h>
#include <Prism/Operations/Router.hpp>
#include <boost/asio/io_context.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Operations = Prism::Operations;

    /** @brief 创建真正 Router 状态并预登记同一命令，不启动业务或 HTTP 进程。 */
    auto PrepareOperation(Operations::Detail::State &State) -> void
    {
        State.Operations_.emplace(1U, Operations::CommandResult::Accepted(
            Prism::RequestId{73U}, Operations::OperationId{1U}));
    }
}

TEST(OperationPublication, CommittedTerminalCarriesIndependentWaiterSignalFailure)
{
    Net::io_context Io;
    Operations::Detail::State State(Io.get_executor(), {}, {});
    PrepareOperation(State);
    // 活动等待者没有已注册 timer wait，实际 cancel 回执为零，应保留通知失败。
    State.OperationWaiterActive_ = true;
    auto Result = Operations::Detail::CompleteOperation(State, Operations::OperationId{1U},
        Operations::CommandResult::Completed(Prism::RequestId{91U}));

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->WaiterSignalFailure.Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(State.Operations_.at(1U).Status, Operations::CommandStatus::Completed);
    EXPECT_EQ(State.Operations_.at(1U).Correlation, Prism::RequestId{73U});
    EXPECT_EQ(State.Operations_.at(1U).Operation, Operations::OperationId{1U});
    auto Repeated = Operations::Detail::CompleteOperation(State, Operations::OperationId{1U},
        Operations::CommandResult::Completed(Prism::RequestId{91U}));
    ASSERT_FALSE(Repeated);
    EXPECT_EQ(Repeated.error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_EQ(State.Operations_.at(1U).Status, Operations::CommandStatus::Completed);
}

TEST(OperationPublication, InvalidTerminalDoesNotCommitOrNotify)
{
    Net::io_context Io;
    Operations::Detail::State State(Io.get_executor(), {}, {});
    PrepareOperation(State);
    State.OperationWaiterActive_ = true;
    auto Result = Operations::Detail::CompleteOperation(State, Operations::OperationId{1U},
        Operations::CommandResult::Accepted(Prism::RequestId{91U}, Operations::OperationId{1U}));

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_EQ(State.Operations_.at(1U).Status, Operations::CommandStatus::Accepted);
    EXPECT_FALSE(State.OperationSignalFailure_);
}
