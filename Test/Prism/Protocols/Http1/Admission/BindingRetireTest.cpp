/** @file BindingRetireTest.cpp @brief HTTP/1 binding 等待活动接入真实退栈。 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Prism/Protocols/Http1/Binding.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include "../Core/HttpTestSupport.hpp"

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using AcceptOutcome = Prism::Contract::AcceptOutcome;
    using DrainOutcome = std::expected<void, Prism::Fault::Failure>;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct Observation final
    {
        explicit Observation(Net::any_io_executor Executor)
            : Completed(std::make_shared<CompletionChannel>(std::move(Executor), 2U))
        {
        }

        std::shared_ptr<CompletionChannel> Completed;
        std::optional<AcceptOutcome> Accepted;
        std::optional<DrainOutcome> Drained;
        std::exception_ptr AcceptException;
        std::exception_ptr DrainException;
    };

    [[nodiscard]] auto FinishActiveAccept(
        const std::shared_ptr<Prism::Http11::Binding>& Binding,
        const std::shared_ptr<Prism::PrismMockTransport>& Inbound,
        const std::shared_ptr<Observation>& Result)
        -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Ready(Executor);
        Ready.expires_after(std::chrono::milliseconds(1));
        co_await Ready.async_wait(Net::use_awaitable);
        EXPECT_EQ(Inbound->ReadsDone, 1U);
        Binding->Close();
        auto Completion = [Result](std::exception_ptr Error, DrainOutcome Value)
        {
            Result->DrainException = std::move(Error);
            Result->Drained = std::move(Value);
            (void)Result->Completed->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, Binding->Drain(), std::move(Completion));
        co_await Net::post(Executor, Net::use_awaitable);
        EXPECT_FALSE(Result->Drained.has_value());
        Inbound->InjectRead({'x', '\r', '\n', '\r', '\n'});
        co_await Result->Completed->async_receive(Net::use_awaitable);
        co_await Result->Completed->async_receive(Net::use_awaitable);
    }
}

TEST(Http11Binding, DrainWaitsForActiveAdmissionAndThenReleasesFactory)
{
    Net::io_context Io;
    auto Binding = Prism::Testing::MakeHttp1Binding("http-retirement", Io.get_executor());
    auto Inbound = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    auto Result = std::make_shared<Observation>(Io.get_executor());
    auto Input = Prism::Contract::StreamAcceptInput{
        Inbound, {}, Prism::Testing::Http11::MakeBytePool()};
    auto AcceptCompletion = [Result](std::exception_ptr Error, AcceptOutcome Value)
    {
        Result->AcceptException = std::move(Error);
        Result->Accepted = std::move(Value);
        (void)Result->Completed->try_send(boost::system::error_code{});
    };
    Net::co_spawn(Io, Binding->Accept(std::move(Input)), std::move(AcceptCompletion));
    Net::co_spawn(Io, FinishActiveAccept(Binding, Inbound, Result), Net::detached);
    Io.run();

    ASSERT_FALSE(Result->AcceptException);
    ASSERT_TRUE(Result->Accepted);
    EXPECT_FALSE(*Result->Accepted);
    EXPECT_EQ(Result->Accepted->error().Code, Prism::Fault::Code::BadMessage);
    ASSERT_FALSE(Result->DrainException);
    ASSERT_TRUE(Result->Drained);
    EXPECT_TRUE(*Result->Drained);
    EXPECT_TRUE(Binding->IsRetired());

    auto LateInbound = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    std::optional<AcceptOutcome> LateResult;
    std::exception_ptr LateException;
    auto LateInput = Prism::Contract::StreamAcceptInput{
        LateInbound, {}, Prism::Testing::Http11::MakeBytePool()};
    Io.restart();
    Net::co_spawn(Io, Binding->Accept(std::move(LateInput)),
        [&LateResult, &LateException](std::exception_ptr Error, AcceptOutcome Value)
        {
            LateException = std::move(Error);
            LateResult = std::move(Value);
        });
    Io.run();

    ASSERT_FALSE(LateException);
    ASSERT_TRUE(LateResult);
    ASSERT_FALSE(*LateResult);
    EXPECT_EQ(LateResult->error().Code, Prism::Fault::Code::Canceled);
    EXPECT_TRUE(LateInbound->IsClosed());
    EXPECT_TRUE(Binding->IsRetired());
}
