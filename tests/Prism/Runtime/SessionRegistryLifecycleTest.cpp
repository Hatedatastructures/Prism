/**
 * @file SessionRegistryLifecycleTest.cpp
 * @brief 会话注册表排空与停机生命周期测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>

namespace
{

    namespace net = boost::asio;
}

namespace Prism::Runtime
{
    class SessionRegistryLifecycleTestAccess final
    {
    public:
        static auto FailNextErrorHookWithRuntimeError(SessionControl &Control) -> void
        {
            Control.State_->ErrorHookFailureInjection.store(
                SessionControl::State::HookFailureInjection::RuntimeError,
                std::memory_order_release);
        }

        static auto FailNextErrorHookWithAllocation(SessionControl &Control) -> void
        {
            Control.State_->ErrorHookFailureInjection.store(
                SessionControl::State::HookFailureInjection::AllocationFailure,
                std::memory_order_release);
        }

        static auto FailNextMetricsHookWithRuntimeError(SessionControl &Control) -> void
        {
            Control.State_->MetricsHookFailureInjection.store(
                SessionControl::State::HookFailureInjection::RuntimeError,
                std::memory_order_release);
        }

        static auto FailNextMetricsHookWithAllocation(SessionControl &Control) -> void
        {
            Control.State_->MetricsHookFailureInjection.store(
                SessionControl::State::HookFailureInjection::AllocationFailure,
                std::memory_order_release);
        }

        static auto Contains(SessionRegistry &Registry, const std::uint64_t Id) -> bool
        {
            const auto Records = Registry.State_->Records.load(std::memory_order_acquire);
            return Records->contains(Id);
        }

        static auto RequestShutdown(SessionRegistry &Registry) -> void
        {
            Registry.RequestShutdown();
        }
    };
}

namespace
{

    auto make_info(std::uint64_t Id) -> Prism::Runtime::SessionInfo
    {
        Prism::Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.AccountId = Prism::AccountId{Id};
        Info.AccountRuntime = Prism::Account::AccountRuntime{Info.AccountId, 1}.RuntimeIdentity();
        Info.identity = "user-" + std::to_string(Id);
        Info.peer = "127.0.0.1";
        Info.Target = "example.com:443";
        Info.Protocol = 1;
        Info.StartedAt = Id * 100;
        return Info;
    }

    class RetiringStreamOwner final : public Prism::Contract::Ingress::StreamResetOwner
    {
    public:
        RetiringStreamOwner(
            std::weak_ptr<Prism::Contract::Ingress::StreamCatalog> Catalog,
            Prism::Contract::Ingress::StreamResetRequest Scope)
            : Catalog_(std::move(Catalog)), Scope_(Scope)
        {
        }

        auto ResetAndDrain(Prism::Contract::Ingress::StreamResetRequest Request)
            -> net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (Request != Scope_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Called = true;
            const auto Catalog = Catalog_.lock();
            if (!Catalog || !Catalog->Retire(Request.Identity))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        bool Called{false};

    private:
        std::weak_ptr<Prism::Contract::Ingress::StreamCatalog> Catalog_;
        Prism::Contract::Ingress::StreamResetRequest Scope_;
    };

    TEST(SessionRegistry, StreamLookupUsesExactParentAndCatalogRetirement)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        auto Info = make_info(401U);
        Info.Worker = Prism::WorkerId{2};
        Info.Generation = Prism::GenerationId{3};
        auto Registration = Registry.Register(Info, Control);
        ASSERT_TRUE(Registration);
        ASSERT_TRUE(Control->SetIdentity({
            .TaskId = Prism::TaskId{701},
            .SessionId = Prism::SessionId{401},
            .WorkerId = Prism::WorkerId{2},
            .Generation = Prism::GenerationId{3}}));

        const Prism::Contract::Ingress::StreamIdentity Identity{
            Prism::SessionId{401}, Prism::WorkerId{2}, Prism::GenerationId{3},
            Prism::StreamId{71}};
        EXPECT_EQ(Registry.FindStream(Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable);

        auto Catalog = std::make_shared<Prism::Contract::Ingress::StreamCatalog>();
        ASSERT_TRUE(Control->AttachStreamCatalog(Catalog));
        EXPECT_EQ(Registry.FindStream(Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable);
        ASSERT_TRUE(Catalog->Enable(2U));
        const Prism::Contract::Ingress::StreamResetRequest ResetScope{
            Identity, Prism::TaskId{702}, Prism::TaskId{701}};
        auto ResetOwner = std::make_shared<RetiringStreamOwner>(Catalog, ResetScope);
        ASSERT_TRUE(Catalog->Register({
            .Identity = Identity,
            .Task = ResetScope.Task,
            .ParentTask = ResetScope.ParentTask,
            .Account = Info.AccountId,
            .Protocol = Prism::Contract::Ingress::StreamProtocol::Smux},
            {.Owner = ResetOwner}));

        const auto Active = Registry.FindStream(Identity);
        ASSERT_EQ(Active.Status, Prism::Contract::Ingress::StreamCatalogStatus::Found);
        EXPECT_EQ(Active.Value.Identity, Identity);
        EXPECT_EQ(Active.Value.State, Prism::Contract::Ingress::StreamState::Active);
        EXPECT_EQ(Active.Value.Account, Info.AccountId);
        EXPECT_EQ(Active.Value.Protocol, Prism::Contract::Ingress::StreamProtocol::Smux);

        auto WrongParent = Identity;
        WrongParent.Generation = Prism::GenerationId{4};
        EXPECT_EQ(Registry.FindStream(WrongParent).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
        ASSERT_TRUE(Catalog->MarkDraining(Identity));
        const auto Draining = Registry.FindStream(Identity);
        ASSERT_EQ(Draining.Status, Prism::Contract::Ingress::StreamCatalogStatus::Found);
        EXPECT_EQ(Draining.Value.State, Prism::Contract::Ingress::StreamState::Draining);
        ASSERT_TRUE(Catalog->Retire(Identity));
        EXPECT_EQ(Registry.FindStream(Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::NotFound);

        Registration.Reset();
        EXPECT_EQ(Registry.FindStream(Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
    }

    TEST(SessionRegistry, StreamResetRequiresExactRootTaskAndWaitsForRetirement)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        auto Info = make_info(402U);
        Info.Worker = Prism::WorkerId{2};
        Info.Generation = Prism::GenerationId{3};
        auto Registration = Registry.Register(Info, Control);
        ASSERT_TRUE(Registration);
        ASSERT_TRUE(Control->SetIdentity({
            .TaskId = Prism::TaskId{701},
            .SessionId = Prism::SessionId{402},
            .WorkerId = Prism::WorkerId{2},
            .Generation = Prism::GenerationId{3}}));

        auto Catalog = std::make_shared<Prism::Contract::Ingress::StreamCatalog>();
        ASSERT_TRUE(Control->AttachStreamCatalog(Catalog));
        ASSERT_TRUE(Catalog->Enable(2U));
        const Prism::Contract::Ingress::StreamResetRequest Scope{
            .Identity = {Prism::SessionId{402}, Prism::WorkerId{2},
                Prism::GenerationId{3}, Prism::StreamId{72}},
            .Task = Prism::TaskId{702},
            .ParentTask = Prism::TaskId{701}};
        auto Owner = std::make_shared<RetiringStreamOwner>(Catalog, Scope);
        ASSERT_TRUE(Catalog->Register(
            {.Identity = Scope.Identity, .Task = Scope.Task, .ParentTask = Scope.ParentTask,
                .Account = Info.AccountId,
                .Protocol = Prism::Contract::Ingress::StreamProtocol::Yamux},
            {.Owner = Owner}));

        auto WrongParent = Scope;
        WrongParent.ParentTask = Prism::TaskId{700};
        auto Rejected = boost::asio::co_spawn(
            Io, Registry.ResetStreamAndDrain(WrongParent), boost::asio::use_future);
        Io.run();
        const auto RejectedResult = Rejected.get();
        EXPECT_FALSE(RejectedResult);
        EXPECT_FALSE(Owner->Called);
        EXPECT_EQ(Registry.FindStream(Scope.Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::Found);

        Io.restart();
        auto Reset = boost::asio::co_spawn(
            Io, Registry.ResetStreamAndDrain(Scope), boost::asio::use_future);
        Io.run();
        const auto ResetResult = Reset.get();
        ASSERT_TRUE(ResetResult);
        EXPECT_TRUE(Owner->Called);
        EXPECT_EQ(Registry.FindStream(Scope.Identity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
    }

    auto WaitForTimer(std::shared_ptr<net::steady_timer> Timer,
                      std::atomic<bool> &Completed) -> net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Timer->async_wait(net::redirect_error(net::use_awaitable, Error));
        Completed.store(true, std::memory_order_release);
    }

    auto WaitForCancellation(std::shared_ptr<net::steady_timer> Timer,
                             std::promise<void> &Started,
                             std::atomic<bool> &Completed) -> net::awaitable<void>
    {
        Started.set_value();
        boost::system::error_code Error;
        co_await Timer->async_wait(net::redirect_error(net::use_awaitable, Error));
        Completed.store(Error == net::error::operation_aborted, std::memory_order_release);
    }

    auto DrainAndReportEarly(Prism::Runtime::SessionRegistry &Registry,
                             const std::atomic<bool> &OperationCompleted) -> net::awaitable<bool>
    {
        co_await Registry.Drain();
        co_return !OperationCompleted.load(std::memory_order_acquire);
    }

    TEST(SessionRegistry, DrainWaitsForStillRegisteredControlAfterOtherRemoval)
    {
        Prism::Runtime::SessionRegistry Registry;
        std::atomic<bool> OperationCompleted{false};
        std::atomic<bool> WatchdogExpired{false};
        boost::asio::io_context Io;
        auto Removed = Registry.Register(
            make_info(81), std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor()));
        ASSERT_TRUE(Removed);
        Removed.Reset();

        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        auto Registration = Registry.Register(make_info(82), Control);
        ASSERT_TRUE(Registration);

        auto Timer = std::make_shared<net::steady_timer>(Io);
        Timer->expires_after(std::chrono::milliseconds(10));
        ASSERT_TRUE(Control->Start(Prism::Lifecycle::TaskRequest{},
                                   WaitForTimer(Timer, OperationCompleted)));
        ASSERT_EQ(Control->Metrics().Active, 1U);

        auto Watchdog = std::make_shared<net::steady_timer>(Io);
        Watchdog->expires_after(std::chrono::seconds(1));
        Watchdog->async_wait(
            [&Io, &WatchdogExpired](const boost::system::error_code &Error)
            {
                if (!Error)
                {
                    WatchdogExpired.store(true, std::memory_order_release);
                    Io.stop();
                }
            });

        bool DrainCompleted = false;
        bool DrainReturnedEarly = true;
        std::exception_ptr DrainFailure;
        net::co_spawn(
            Io, DrainAndReportEarly(Registry, OperationCompleted),
            [&](std::exception_ptr Failure, bool ReturnedEarly)
            {
                DrainFailure = std::move(Failure);
                DrainReturnedEarly = ReturnedEarly;
                DrainCompleted = true;
                (void)Watchdog->cancel();
            });
        Io.run();

        EXPECT_TRUE(DrainCompleted) << "Drain did not complete before the 1 s watchdog";
        EXPECT_FALSE(WatchdogExpired.load(std::memory_order_acquire));
        EXPECT_EQ(DrainFailure, nullptr);
        EXPECT_FALSE(DrainReturnedEarly);
        EXPECT_TRUE(OperationCompleted.load(std::memory_order_acquire));
        EXPECT_EQ(Control->Metrics().Active, 0U);
        Registration.Reset();
    }

    TEST(SessionRegistry, ShutdownCancelsAndDrainsStillRegisteredControl)
    {
        Prism::Runtime::SessionRegistry Registry;
        std::promise<void> Started;
        auto StartedFuture = Started.get_future();
        std::atomic<bool> OperationCancelled{false};
        std::atomic<bool> CancelHookInvoked{false};
        std::atomic<bool> WatchdogExpired{false};
        bool ShutdownCompleted = false;
        std::exception_ptr ShutdownFailure;
        Prism::Fault::Failure ShutdownResult{Prism::Fault::Code::GenericError};
        boost::asio::io_context Io;
        auto Removed = Registry.Register(
            make_info(91), std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor()));
        ASSERT_TRUE(Removed);
        Removed.Reset();

        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        auto Registration = Registry.Register(make_info(92), Control);
        ASSERT_TRUE(Registration);

        auto Timer = std::make_shared<net::steady_timer>(Io);
        Timer->expires_after(std::chrono::milliseconds(500));
        Prism::Lifecycle::TaskRequest Request;
        Request.Cancel = [Timer, &CancelHookInvoked]
        {
            CancelHookInvoked.store(true, std::memory_order_release);
            (void)Timer->cancel();
        };
        ASSERT_TRUE(Control->Start(std::move(Request),
                                   WaitForCancellation(Timer, Started, OperationCancelled)));

        auto Watchdog = std::make_shared<net::steady_timer>(Io);
        Watchdog->expires_after(std::chrono::seconds(2));
        Watchdog->async_wait(
            [&Io, &WatchdogExpired](const boost::system::error_code &Error)
            {
                if (!Error)
                {
                    WatchdogExpired.store(true, std::memory_order_release);
                    Io.stop();
                }
            });

        std::thread IoThread([&Io] { Io.run(); });
        if (StartedFuture.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
        {
            Io.stop();
            IoThread.join();
            ADD_FAILURE() << "Control operation did not start before the 1 s deadline";
            return;
        }

        net::co_spawn(
            Io, Registry.Shutdown(),
            [&](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                ShutdownFailure = std::move(Failure);
                ShutdownResult = Result ? Prism::Fault::Failure{} : Result.error();
                ShutdownCompleted = true;
                (void)Watchdog->cancel();
            });
        IoThread.join();

        EXPECT_TRUE(ShutdownCompleted) << "Shutdown did not complete before the 2 s watchdog";
        EXPECT_FALSE(WatchdogExpired.load(std::memory_order_acquire));
        EXPECT_EQ(ShutdownFailure, nullptr);
        EXPECT_TRUE(ShutdownResult.Succeeded());
        EXPECT_TRUE(CancelHookInvoked.load(std::memory_order_acquire));
        EXPECT_TRUE(OperationCancelled.load(std::memory_order_acquire))
            << "timer did not complete through operation_aborted before the 500 ms watchdog";
        EXPECT_EQ(Control->Metrics().Active, 0U);
        EXPECT_EQ(Registry.Size(), 0U);
    }

    TEST(SessionRegistry, PublishedRegistrationRollsBackAfterErrorHookThrow)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        Prism::Runtime::SessionRegistryLifecycleTestAccess::FailNextErrorHookWithRuntimeError(
            *Control);

        auto Registration = Registry.Register(make_info(501U), Control);

        EXPECT_FALSE(Registration);
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Registry.PendingRemovals(), 0U);
        EXPECT_FALSE(
            Prism::Runtime::SessionRegistryLifecycleTestAccess::Contains(Registry, 501U));
    }

    TEST(SessionRegistry, PublishedRegistrationRollsBackAfterErrorHookBadAlloc)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        Prism::Runtime::SessionRegistryLifecycleTestAccess::FailNextErrorHookWithAllocation(
            *Control);

        auto Registration = Registry.Register(make_info(502U), Control);

        EXPECT_FALSE(Registration);
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Registry.PendingRemovals(), 0U);
        EXPECT_FALSE(
            Prism::Runtime::SessionRegistryLifecycleTestAccess::Contains(Registry, 502U));
    }

    TEST(SessionRegistry, PublishedRegistrationRollsBackAfterMetricsHookThrow)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        Prism::Runtime::SessionRegistryLifecycleTestAccess::FailNextMetricsHookWithRuntimeError(
            *Control);

        auto Registration = Registry.Register(make_info(503U), Control);

        EXPECT_FALSE(Registration);
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Registry.PendingRemovals(), 0U);
        EXPECT_FALSE(
            Prism::Runtime::SessionRegistryLifecycleTestAccess::Contains(Registry, 503U));
    }

    TEST(SessionRegistry, PublishedRegistrationRollsBackAfterMetricsHookBadAlloc)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        Prism::Runtime::SessionRegistryLifecycleTestAccess::FailNextMetricsHookWithAllocation(
            *Control);

        auto Registration = Registry.Register(make_info(504U), Control);

        EXPECT_FALSE(Registration);
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Registry.PendingRemovals(), 0U);
        EXPECT_FALSE(
            Prism::Runtime::SessionRegistryLifecycleTestAccess::Contains(Registry, 504U));
    }

    TEST(SessionRegistry, RequestShutdownRejectsLaterRegistrationWithoutCancellation)
    {
        boost::asio::io_context Io;
        Prism::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());

        Prism::Runtime::SessionRegistryLifecycleTestAccess::RequestShutdown(Registry);
        auto Registration = Registry.Register(make_info(505U), Control);

        EXPECT_FALSE(Registration);
        EXPECT_FALSE(Control->IsCancelled());
        EXPECT_EQ(Registry.Size(), 0U);
    }

} // namespace
