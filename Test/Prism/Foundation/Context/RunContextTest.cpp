/** @file RunContextTest.cpp @brief 线程入口保留首个 handler 异常。 */
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Foundation/Executor/RunContext.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <gtest/gtest.h>

#include <exception>
#include <stdexcept>
#include <string>

namespace
{

    namespace Net = boost::asio;

    [[nodiscard]] auto ExceptionMessage(const std::exception_ptr& Error) -> std::string
    {
        try
        {
            if (Error)
            {
                std::rethrow_exception(Error);
            }
        }
        catch (const std::exception& Failure)
        {
            return Failure.what();
        }
        return {};
    }

} // namespace

TEST(PrismExecutorRunContext, ReturnsAndPreservesFirstFatalException)
{
    Net::io_context Context;
    const auto State = Prism::Executor::FatalState::Bind(Context);
    const auto FirstFailure = std::make_exception_ptr(std::runtime_error("first handler failure"));
    const auto LaterFailure = std::make_exception_ptr(std::runtime_error("later handler failure"));
    Net::post(Context, [FirstFailure] { std::rethrow_exception(FirstFailure); });

    const auto FirstResult = Prism::Executor::RunContext(Context);
    ASSERT_EQ(ExceptionMessage(FirstResult), "first handler failure");
    ASSERT_TRUE(State->HasFailure());
    EXPECT_EQ(ExceptionMessage(State->Error()), "first handler failure");

    State->Publish(LaterFailure);
    EXPECT_EQ(ExceptionMessage(FirstResult), "first handler failure");
    EXPECT_EQ(ExceptionMessage(State->Error()), "first handler failure");
}
