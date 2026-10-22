/** @file MuxResetFailureTest.cpp @brief Mux 子流取消派发失败与真实退休回执。 */
#include <gtest/gtest.h>

#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/CancellationDomain.hpp>
#include <Prism/Lifecycle/TaskRetirementReceipt.hpp>
#include <Prism/Lifecycle/TaskState.hpp>
#include <Prism/Protocols/Mux/Detail/RootChildOwner.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Prism::Lifecycle
{
    /** @brief 仅供该测试构造不经过 Registry 的受控任务句柄。 */
    class TaskHandleTestAccess final
    {
    public:
        [[nodiscard]] static auto Make(std::shared_ptr<TaskState> State) -> TaskHandle
        {
            return TaskHandle(std::move(State));
        }
    };
}

namespace
{
    namespace Net = boost::asio;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;
    using ResetResult = std::expected<void, Prism::Fault::Failure>;

    struct ManualTask final
    {
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        std::shared_ptr<Prism::Lifecycle::TaskState> State;
        std::shared_ptr<Prism::Lifecycle::TaskRetirementReceipt> Receipt;
        Prism::Lifecycle::TaskHandle Handle;
    };

    auto MakeManualTask(Net::any_io_executor Executor, Prism::Lifecycle::TaskCancelFn Cancel = {})
        -> ManualTask
    {
        auto Reclaimer = std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor);
        auto Domain = std::make_shared<Prism::Lifecycle::CancellationDomain>(Executor, Reclaimer);
        auto Receipt = std::make_shared<Prism::Lifecycle::TaskRetirementReceipt>();
        auto State = std::make_shared<Prism::Lifecycle::TaskState>(
            Prism::Lifecycle::TaskState::Options{
                .Identity = {}, .Domain = std::move(Domain), .Cancel = std::move(Cancel),
                .StartOnSubmit = true, .IdentityObserver = {}, .Retirement = Receipt});
        auto Handle = Prism::Lifecycle::TaskHandleTestAccess::Make(State);
        return {std::move(Reclaimer), std::move(State), std::move(Receipt), std::move(Handle)};
    }

    auto MakeResetOwner(Prism::Lifecycle::TaskHandle Task)
        -> std::shared_ptr<Prism::Contract::Ingress::StreamResetOwner>
    {
        return Prism::Mux::Detail::CreateStreamResetTaskOwner(
            std::move(Task), std::make_shared<Prism::Fault::FailureState>(), {});
    }

    auto CompleteManualTask(const std::shared_ptr<Prism::Lifecycle::TaskState> &State,
        const std::shared_ptr<Prism::Lifecycle::TaskRetirementReceipt> &Receipt) -> void
    {
        (void)State->Complete(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        Receipt->Publish();
    }

    TEST(MuxRootResetOwner, DispatchFailureReturnsBlockedWithoutRetiringTask)
    {
        Net::io_context Io;
        auto CancelCalls = std::make_shared<std::atomic<std::size_t>>(0U);
        auto Task = MakeManualTask(Io.get_executor(), [CancelCalls]
            { CancelCalls->fetch_add(1U, std::memory_order_relaxed); });
        Task.Reclaimer->Quarantine();
        auto Owner = MakeResetOwner(std::move(Task.Handle));
        std::optional<ResetResult> Result;
        std::exception_ptr Exception;
        bool Done = false;
        bool TimedOut = false;
        Net::steady_timer Watchdog(Io);
        Watchdog.expires_after(std::chrono::seconds(5));
        Net::co_spawn(Io, Owner->ResetAndDrain({}),
            [&](std::exception_ptr Error, ResetResult Value)
            {
                Exception = Error;
                if (!Error) Result = std::move(Value);
                Done = true;
                Watchdog.cancel();
            });
        Watchdog.async_wait([&](boost::system::error_code Error)
            {
                if (Error) return;
                TimedOut = true;
                CompleteManualTask(Task.State, Task.Receipt);
            });
        Io.run();

        EXPECT_FALSE(TimedOut);
        ASSERT_TRUE(Done);
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::Blocked);
        const auto Observation = Task.State->Observation();
        EXPECT_TRUE(Observation.CancelRequested);
        EXPECT_TRUE(Observation.DrainBlocked);
        EXPECT_EQ(Observation.DrainFailure.Code, Prism::Fault::Code::Blocked);
        EXPECT_TRUE(Task.State->IsCancelDispatchFailed());
        EXPECT_FALSE(Task.State->IsCompleted());
        EXPECT_EQ(CancelCalls->load(std::memory_order_relaxed), 0U);

        CompleteManualTask(Task.State, Task.Receipt);
        EXPECT_TRUE(Task.State->IsCompleted());
    }

    struct NormalResetProbe final
    {
        std::shared_ptr<Signal> CancelObserved;
        std::shared_ptr<Prism::Lifecycle::TaskState> State;
        std::shared_ptr<Prism::Lifecycle::TaskRetirementReceipt> Receipt;
        bool *OwnerDone{};
        bool CancelReceived{false};
        bool OwnerCompletedBeforeReceipt{false};
    };

    auto ReleaseTaskAfterCancel(std::shared_ptr<NormalResetProbe> Probe)
        -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        (void)co_await Probe->CancelObserved->async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        Probe->CancelReceived = !Error;
        Probe->OwnerCompletedBeforeReceipt = *Probe->OwnerDone || Probe->State->IsCompleted();
        CompleteManualTask(Probe->State, Probe->Receipt);
    }

    TEST(MuxRootResetOwner, SuccessfulCancellationWaitsForRetirementReceipt)
    {
        Net::io_context Io;
        auto CancelObserved = std::make_shared<Signal>(Io, 1U);
        auto Task = MakeManualTask(Io.get_executor(), [CancelObserved]
            { (void)CancelObserved->try_send(boost::system::error_code{}); });
        auto Owner = MakeResetOwner(std::move(Task.Handle));
        auto Probe = std::make_shared<NormalResetProbe>(NormalResetProbe{
            CancelObserved, Task.State, Task.Receipt});
        std::optional<ResetResult> Result;
        std::exception_ptr Exception;
        bool OwnerDone = false;
        bool ProbeDone = false;
        bool TimedOut = false;
        Probe->OwnerDone = &OwnerDone;
        Net::steady_timer Watchdog(Io);
        Watchdog.expires_after(std::chrono::seconds(5));
        Net::co_spawn(Io, Owner->ResetAndDrain({}),
            [&](std::exception_ptr Error, ResetResult Value)
            {
                Exception = Error;
                if (!Error) Result = std::move(Value);
                OwnerDone = true;
                Watchdog.cancel();
            });
        Net::co_spawn(Io, ReleaseTaskAfterCancel(Probe),
            [&](std::exception_ptr Error)
            {
                if (Error) Exception = Error;
                ProbeDone = true;
            });
        Watchdog.async_wait([&](boost::system::error_code Error)
            {
                if (Error) return;
                TimedOut = true;
                (void)CancelObserved->try_send(Net::error::operation_aborted);
                CompleteManualTask(Task.State, Task.Receipt);
            });
        Io.run();

        EXPECT_FALSE(TimedOut);
        EXPECT_TRUE(ProbeDone);
        EXPECT_TRUE(Probe->CancelReceived);
        EXPECT_FALSE(Probe->OwnerCompletedBeforeReceipt);
        EXPECT_FALSE(Task.State->Observation().DrainBlocked);
        ASSERT_TRUE(OwnerDone);
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        EXPECT_TRUE(*Result);
    }
}
