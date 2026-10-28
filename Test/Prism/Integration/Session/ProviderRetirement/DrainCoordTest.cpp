/** @file DrainCoordTest.cpp @brief 验证并发 provider drain 共用一次 attempt。 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <utility>

#include <Prism/Protocols/Common/Provider/Drain/Attempt.hpp>

namespace Prism::Testing
{
    namespace Net = boost::asio;

    struct ProviderDrainCoordinatorTestState final
    {
        using Coordinator = Prism::Protocols::Detail::ProviderSessionDrainCoordinator;
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        explicit ProviderDrainCoordinatorTestState(Net::any_io_executor Executor)
            : Value(std::make_shared<Coordinator>()), Ready(std::move(Executor), 3U) {}

        std::shared_ptr<Coordinator> Value;
        Signal Ready;
        std::optional<Coordinator::DrainTurn> Owner;
        std::size_t NewOwners{0U};
        std::size_t Completed{0U};
        std::array<std::optional<Prism::Fault::Failure>, 3U> JoinAcquireFailures;
        std::exception_ptr Exception;
    };

    [[nodiscard]] auto JoinProviderDrain(
        const std::shared_ptr<ProviderDrainCoordinatorTestState>& State,
        const std::size_t Index) -> Net::awaitable<void>
    {
        (void)State->Ready.try_send(boost::system::error_code{});
        auto Acquired = co_await State->Value->Acquire();
        if (!Acquired)
        {
            State->JoinAcquireFailures[Index] = Acquired.error();
            ++State->Completed;
            co_return;
        }
        if (Acquired->IsOwner()) ++State->NewOwners;
        ++State->Completed;
    }

    [[nodiscard]] auto HoldProviderDrainAndRelease(
        const std::shared_ptr<ProviderDrainCoordinatorTestState>& State) -> Net::awaitable<void>
    {
        auto Acquired = co_await State->Value->Acquire();
        if (!Acquired || !Acquired->IsOwner()) co_return;
        State->Owner.emplace(std::move(*Acquired));
        const auto Executor = co_await Net::this_coro::executor;
        for (std::size_t Index = 0; Index < 3U; ++Index)
        {
            Net::co_spawn(Executor, JoinProviderDrain(State, Index),
                [State, Index](std::exception_ptr Error)
                { if (Error) State->Exception = std::move(Error); });
        }
        for (std::size_t Index = 0; Index < 3U; ++Index)
        {
            boost::system::error_code Error;
            co_await State->Ready.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
        }
        State->Owner->SetResult(std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::IoError}));
        State->Owner.reset();
    }

    TEST(ProviderSessionDrainCoordinator, ConcurrentDrainCallsJoinOneActiveAttempt)
    {
        auto Context = Net::io_context{};
        auto State = std::make_shared<ProviderDrainCoordinatorTestState>(
            Context.get_executor());
        std::exception_ptr Exception;
        Net::co_spawn(Context, HoldProviderDrainAndRelease(State),
            [&Exception](std::exception_ptr Error)
            { Exception = std::move(Error); });
        Context.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(State->Exception);
        EXPECT_EQ(State->NewOwners, 0U);
        EXPECT_EQ(State->Completed, 3U);
        for (std::size_t Index = 0; Index < State->JoinAcquireFailures.size(); ++Index)
        {
            const auto& Failure = State->JoinAcquireFailures[Index];
            ASSERT_TRUE(Failure.has_value());
            EXPECT_EQ(Failure->Code, Prism::Fault::Code::IoError);
        }
    }
}
