/**
 * @file SessionRegistryTest.cpp
 * @brief 会话注册表测试（T5-7 O6）
 * @details 覆盖：
 *          - Register/Remove/Find/数量
 *          - 值拷贝快照隔离（快照不受后续修改影响）
 *          - 快照遍历安全（独立拷贝，无 L3 引用）
 *          - 批量注册/移除
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <future>
#include <memory>
#include <new>
#include <string>
#include <thread>
#include <vector>

#include <Preview/Runtime/SessionRegistry.hpp>

namespace Preview::Runtime
{

    class SessionRegistryTestAccess final
    {
    public:
        static auto FailNextRemovalCompaction(SessionRegistry &Registry) -> void
        {
            Registry.State_->FailNextRemovalCompaction.store(1, std::memory_order_release);
        }

        static auto FailNextMetricsHookInstallation(SessionRegistry &Registry) -> void
        {
            Registry.State_->FailNextMetricsHookInstallation.store(1, std::memory_order_release);
        }

        static auto BlockDrain(SessionControl &Control) -> bool
        {
            const auto Binding = Control.State_->Bound.load(std::memory_order_acquire);
            if (!Binding || !Binding->Tasks)
            {
                return false;
            }
            Binding->Tasks->Block();
            return true;
        }
    };

} // namespace Preview::Runtime

namespace
{

    namespace net = boost::asio;

    /** @brief 每个纯 metadata 测试拥有本地执行器，并在控制对象析构后驱动其退休命令。 */
    struct SessionRegistryTestExecutor final
    {
        net::io_context Io;

        ~SessionRegistryTestExecutor()
        {
            if (Io.stopped()) Io.restart();
            Io.run();
        }
    };

    auto MakeInfo(std::uint64_t Id) -> Preview::Runtime::SessionInfo
    {
        Preview::Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.AccountId = Preview::AccountId{Id};
        Info.AccountRuntime = Preview::Account::AccountRuntime{Info.AccountId, 1}.RuntimeIdentity();
        Info.identity = "user-" + std::to_string(Id);
        Info.peer = "127.0.0.1";
        Info.Target = "example.com:443";
        Info.Protocol = 1;
        Info.StartedAt = Id * 100;
        return Info;
    }

    auto RegisterForTest(Preview::Runtime::SessionRegistry &Registry,
                         net::io_context &Io,
                         Preview::Runtime::SessionInfo Info)
        -> Preview::Runtime::SessionRegistry::Registration
    {
        return Registry.Register(std::move(Info),
            std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor()));
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

    auto DrainAndReportEarly(Preview::Runtime::SessionRegistry &Registry,
                             const std::atomic<bool> &OperationCompleted) -> net::awaitable<bool>
    {
        co_await Registry.Drain();
        co_return !OperationCompleted.load(std::memory_order_acquire);
    }

    /**
     * @brief 并发更新 admission metadata，并记录任一不完整观察。
     */
    struct AdmissionUpdateRequest final
    {
        Preview::Runtime::SessionRegistry &Registry;
        std::vector<Preview::Runtime::SessionRegistry::Registration> &Registrations;
        std::barrier<> &Start;
        std::atomic<std::size_t> &Incomplete;
        std::size_t Writer;
        std::size_t Rounds;
    };

    auto RunAdmissionUpdate(AdmissionUpdateRequest Request) -> void
    {
        const auto Id = static_cast<std::uint64_t>(Request.Writer + 1);
        for (std::size_t Round = 0; Round < Request.Rounds; ++Round)
        {
            auto Info = MakeInfo(Id);
            const auto Label = std::to_string(Id) + "-" + std::to_string(Round);
            Info.identity = "account-" + Label;
            Info.peer = "peer-" + Label;
            Info.Target = "target-" + Label + ":443";
            Info.Worker = Preview::WorkerId{Id};
            Info.Generation = Preview::GenerationId{9};
            Request.Start.arrive_and_wait();
            const auto Updated = Request.Registrations[Request.Writer].Update(Info);
            Preview::Runtime::SessionInfo Found;
            const auto Present = Request.Registry.Find(Id, Found);
            if (!Updated || !Present || Found.identity != Info.identity ||
                Found.peer != Info.peer || Found.Target != Info.Target ||
                Found.AccountId != Info.AccountId || Found.Worker != Info.Worker ||
                Found.Generation != Info.Generation)
            {
                Request.Incomplete.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    /**
     * @brief 并发注册独立会话记录并保存每个 worker 的 Registration owner。
     */
    struct ConcurrentRegisterRequest final
    {
        Preview::Runtime::SessionRegistry &Registry;
        std::barrier<> &StartGate;
        std::vector<Preview::Runtime::SessionRegistry::Registration> &Registrations;
        net::io_context &Io;
        std::size_t Index;
    };

    auto RunConcurrentRegister(ConcurrentRegisterRequest Request) -> void
    {
        const auto Id = static_cast<std::uint64_t>(Request.Index + 1);
        auto Info = MakeInfo(Id);
        Info.identity = "identity-" + std::to_string(Id) + std::string(64, 'i');
        Info.peer = "peer-" + std::to_string(Id) + std::string(64, 'p');
        Info.Target = "target-" + std::to_string(Id) + std::string(64, 't');
        Info.Protocol = static_cast<std::uint16_t>(100 + Request.Index);
        Info.StartedAt = 100000 + Id;

        Request.StartGate.arrive_and_wait();
        Request.Registrations[Request.Index] = Request.Registry.Register(
            std::move(Info), std::make_shared<Preview::Runtime::SessionControl>(Request.Io.get_executor()));
    }

    TEST(SessionRegistry, RegisterFindRemove)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto First = RegisterForTest(Registry, Execution.Io, MakeInfo(1));
        auto Second = RegisterForTest(Registry, Execution.Io, MakeInfo(2));
        ASSERT_TRUE(First);
        ASSERT_TRUE(Second);

        EXPECT_EQ(Registry.Size(), 2);
        Preview::Runtime::SessionInfo Found;
        EXPECT_TRUE(Registry.Find(1, Found));
        EXPECT_EQ(Found.identity, "user-1");
        EXPECT_TRUE(Registry.Find(2, Found));
        EXPECT_EQ(Found.peer, "127.0.0.1");

        EXPECT_FALSE(Registry.Find(99, Found));

        EXPECT_TRUE(Registry.Remove(1));
        EXPECT_FALSE(Registry.Find(1, Found));
        EXPECT_EQ(Registry.Size(), 1);
        EXPECT_FALSE(Registry.Remove(1));
    }

    TEST(SessionRegistry, SnapshotIsolation)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto First = RegisterForTest(Registry, Execution.Io, MakeInfo(1));
        ASSERT_TRUE(First);

        auto Before = Registry.Snapshot();
        auto Second = RegisterForTest(Registry, Execution.Io, MakeInfo(2)); // 后续修改
        ASSERT_TRUE(Second);
        Registry.Remove(1);

        // 旧快照不受影响（值拷贝隔离）
        ASSERT_EQ(Before->size(), 1);
        EXPECT_EQ(Before->at(1).identity, "user-1");
        EXPECT_EQ(Registry.Size(), 1);
    }

    TEST(SessionRegistry, SnapshotTraversalSafe)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        std::vector<Preview::Runtime::SessionRegistry::Registration> Registrations;
        Registrations.reserve(10);
        for (std::uint64_t Index = 1; Index <= 10; ++Index)
        {
            auto Registration = RegisterForTest(Registry, Execution.Io, MakeInfo(Index));
            ASSERT_TRUE(Registration);
            Registrations.push_back(std::move(Registration));
        }

        const auto Snapshot = Registry.Snapshot();
        std::uint64_t SumIds = 0;
        for (const auto &[Id, Info] : *Snapshot)
        {
            SumIds += Id;
            EXPECT_EQ(Info.StartedAt, Id * 100);
        }
        EXPECT_EQ(SumIds, 55);

        // 快照与注册表解耦（修改注册表不影响遍历中的快照）
        Registry.Remove(5);
        EXPECT_EQ(Snapshot->size(), 10);
        EXPECT_EQ(Registry.Size(), 9);
    }

    TEST(SessionRegistry, RegistrationUpdatePublishesAdmissionMetadataAndKeepsSnapshot)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto Initial = MakeInfo(7);
        Initial.Worker = Preview::WorkerId{2};
        Initial.Generation = Preview::GenerationId{9};
        auto Registration = RegisterForTest(Registry, Execution.Io, std::move(Initial));
        ASSERT_TRUE(Registration);
        const auto Before = Registry.Snapshot();

        Preview::Runtime::SessionInfo Update;
        Update.Id = 7;
        Update.AccountId = Preview::AccountId{42};
        Update.AccountRuntime = Preview::Account::AccountRuntime{Update.AccountId, 1}.RuntimeIdentity();
        Update.identity = "admitted-account";
        Update.peer = "127.0.0.2";
        Update.Target = "127.0.0.1:8080";
        Update.Protocol = 4;
        Update.Worker = Preview::WorkerId{2};
        Update.Generation = Preview::GenerationId{9};
        ASSERT_TRUE(Registration.Update(std::move(Update)));

        Preview::Runtime::SessionInfo Found;
        ASSERT_TRUE(Registry.Find(7, Found));
        EXPECT_EQ(Found.AccountId, Preview::AccountId{42});
        EXPECT_TRUE(Found.AccountRuntime.IsValid());
        EXPECT_EQ(Found.identity, "admitted-account");
        EXPECT_EQ(Found.Target, "127.0.0.1:8080");
        EXPECT_EQ(Found.Protocol, 4U);
        EXPECT_EQ(Found.Worker, Preview::WorkerId{2});
        EXPECT_EQ(Found.Generation, Preview::GenerationId{9});
        EXPECT_EQ(Found.StartedAt, 700U);
        EXPECT_EQ(Before->at(7).AccountId, Preview::AccountId{7});
        EXPECT_EQ(Before->at(7).Target, "example.com:443");

        Preview::Runtime::SessionInfo Stale;
        Stale.Id = 7;
        Stale.AccountId = Preview::AccountId{99};
        Stale.AccountRuntime = Preview::Account::AccountRuntime{Stale.AccountId, 1}.RuntimeIdentity();
        Stale.Generation = Preview::GenerationId{8};
        EXPECT_FALSE(Registration.Update(std::move(Stale)));

        auto ZeroGeneration = Found;
        ZeroGeneration.Generation = Preview::GenerationId{};
        EXPECT_FALSE(Registration.Update(std::move(ZeroGeneration)));
        auto OtherWorker = Found;
        OtherWorker.Worker = Preview::WorkerId{3};
        EXPECT_FALSE(Registration.Update(std::move(OtherWorker)));

        Registration.Reset();
        Preview::Runtime::SessionInfo Late;
        Late.Id = 7;
        Late.AccountId = Preview::AccountId{99};
        Late.AccountRuntime = Preview::Account::AccountRuntime{Late.AccountId, 1}.RuntimeIdentity();
        EXPECT_FALSE(Registration.Update(std::move(Late)));
    }

    TEST(SessionRegistry, ConcurrentAdmissionUpdatesPreserveCompleteMetadata)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        constexpr std::size_t Writers = 4;
        constexpr std::size_t Rounds = 100;
        std::vector<Preview::Runtime::SessionRegistry::Registration> Registrations;
        for (std::uint64_t Id = 1; Id <= 64; ++Id)
        {
            auto Info = MakeInfo(Id);
            Info.Worker = Preview::WorkerId{Id};
            Info.Generation = Preview::GenerationId{9};
            auto Registration = RegisterForTest(Registry, Execution.Io, std::move(Info));
            ASSERT_TRUE(Registration);
            Registrations.push_back(std::move(Registration));
        }
        const auto Before = Registry.Snapshot();
        std::barrier Start(static_cast<std::ptrdiff_t>(Writers));
        std::atomic<std::size_t> Incomplete{0};
        std::vector<std::thread> Threads;
        for (std::size_t Writer = 0; Writer < Writers; ++Writer)
        {
            Threads.emplace_back(RunAdmissionUpdate,
                AdmissionUpdateRequest{
                    Registry, Registrations, Start, Incomplete, Writer, Rounds});
        }
        for (auto &Thread : Threads) Thread.join();
        EXPECT_EQ(Incomplete.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(Registry.Size(), 64U);
        EXPECT_EQ(Before->at(1).identity, "user-1");
        EXPECT_EQ(Before->at(1).Target, "example.com:443");
    }

    TEST(SessionRegistry, BulkRegisterRemove)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        std::vector<Preview::Runtime::SessionRegistry::Registration> Registrations;
        Registrations.reserve(1000);
        for (std::uint64_t Index = 1; Index <= 1000; ++Index)
        {
            auto Registration = RegisterForTest(Registry, Execution.Io, MakeInfo(Index));
            ASSERT_TRUE(Registration);
            Registrations.push_back(std::move(Registration));
        }
        EXPECT_EQ(Registry.Size(), 1000);

        for (std::uint64_t Index = 1; Index <= 1000; Index += 2)
        {
            Registry.Remove(Index);
        }
        EXPECT_EQ(Registry.Size(), 500);
    }

    TEST(SessionRegistry, RejectsDuplicateId)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto First = RegisterForTest(Registry, Execution.Io, MakeInfo(1));
        ASSERT_TRUE(First);
        auto ReplacementInfo = MakeInfo(1);
        ReplacementInfo.Target = "updated";
        auto Duplicate = RegisterForTest(Registry, Execution.Io, std::move(ReplacementInfo));

        EXPECT_FALSE(Duplicate);
        EXPECT_EQ(Registry.Size(), 1);
        Preview::Runtime::SessionInfo Found;
        EXPECT_TRUE(Registry.Find(1, Found));
        EXPECT_EQ(Found.Target, "example.com:443");
    }

    TEST(SessionRegistry, ConcurrentRegisterPreservesCompleteInfoAndSnapshots)
    {
        constexpr std::size_t RegistrationCount = 32;
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        std::barrier StartGate(static_cast<std::ptrdiff_t>(RegistrationCount + 1));
        std::vector<Preview::Runtime::SessionRegistry::Registration> Registrations(
            RegistrationCount);
        std::vector<std::thread> Threads;
        Threads.reserve(RegistrationCount);

        for (std::size_t Index = 0; Index < RegistrationCount; ++Index)
        {
            Threads.emplace_back(RunConcurrentRegister,
                ConcurrentRegisterRequest{Registry, StartGate, Registrations, Execution.Io, Index});
        }

        StartGate.arrive_and_wait();
        for (auto &Thread : Threads)
        {
            Thread.join();
        }

        ASSERT_EQ(Registry.Size(), RegistrationCount);
        const auto Snapshot = Registry.Snapshot();
        ASSERT_EQ(Snapshot->size(), RegistrationCount);

        for (std::size_t Index = 0; Index < RegistrationCount; ++Index)
        {
            const auto Id = static_cast<std::uint64_t>(Index + 1);
            const auto Identity = "identity-" + std::to_string(Id) + std::string(64, 'i');
            const auto Peer = "peer-" + std::to_string(Id) + std::string(64, 'p');
            const auto Target = "target-" + std::to_string(Id) + std::string(64, 't');
            Preview::Runtime::SessionInfo Found;

            ASSERT_TRUE(Registrations[Index]);
            ASSERT_TRUE(Registry.Find(Id, Found));
            EXPECT_EQ(Found.Id, Id);
            EXPECT_EQ(Found.AccountId, Preview::AccountId{Id});
            EXPECT_EQ(Found.identity, Identity);
            EXPECT_EQ(Found.peer, Peer);
            EXPECT_EQ(Found.Target, Target);
            EXPECT_EQ(Found.Protocol, static_cast<std::uint16_t>(100 + Index));
            EXPECT_EQ(Found.StartedAt, 100000 + Id);

            const auto SnapshotIt = Snapshot->find(Id);
            ASSERT_NE(SnapshotIt, Snapshot->end());
            EXPECT_EQ(SnapshotIt->second.AccountId, Found.AccountId);
            EXPECT_EQ(SnapshotIt->second.identity, Found.identity);
            EXPECT_EQ(SnapshotIt->second.peer, Found.peer);
            EXPECT_EQ(SnapshotIt->second.Target, Found.Target);
            EXPECT_EQ(SnapshotIt->second.Protocol, Found.Protocol);
            EXPECT_EQ(SnapshotIt->second.StartedAt, Found.StartedAt);
        }

        for (auto &Registration : Registrations)
        {
            Registration.Reset();
        }
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Snapshot->size(), RegistrationCount);
    }

    TEST(SessionRegistry, RegisteredControlCancelsAndClosesBeforeTokenRemoval)
    {
        boost::asio::io_context Io;
        Preview::Runtime::SessionRegistry Registry;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        std::size_t CancelCalls = 0;
        std::size_t CloseCalls = 0;
        ASSERT_TRUE(Control->AddCancelHook([&CancelCalls] { ++CancelCalls; }));
        ASSERT_TRUE(Control->SetCloseAction([&CloseCalls]()
            -> std::expected<void, Preview::Fault::Failure>
        {
            ++CloseCalls;
            return {};
        }));

        auto Registration = Registry.Register(MakeInfo(41), Control);
        ASSERT_TRUE(Registration);
        Io.run();

        Io.restart();
        EXPECT_TRUE(Registry.Cancel(41));
        EXPECT_TRUE(Control->IsCancelled());
        EXPECT_EQ(Control->Metrics().CancelRequests, 1U);
        Preview::Runtime::SessionInfo Found;
        EXPECT_TRUE(Registry.Find(41, Found));

        EXPECT_TRUE(Control->CloseOnce());
        EXPECT_TRUE(Control->CloseOnce());
        Io.restart();
        Io.run();
        EXPECT_EQ(CancelCalls, 1U);
        EXPECT_EQ(CloseCalls, 1U);
        EXPECT_TRUE(Control->IsClosed());

        Registration.Reset();
        EXPECT_FALSE(Registry.Find(41, Found));
        EXPECT_EQ(Registry.Size(), 0U);
        Io.restart();
        Io.run();
    }

    TEST(SessionRegistry, OldRegistrationCannotRemoveReusedId)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto OldRegistration = Registry.Register(
            MakeInfo(71),
            std::make_shared<Preview::Runtime::SessionControl>(Execution.Io.get_executor()));
        ASSERT_TRUE(OldRegistration);

        EXPECT_TRUE(Registry.Remove(71));
        auto NewRegistration = Registry.Register(
            MakeInfo(71),
            std::make_shared<Preview::Runtime::SessionControl>(Execution.Io.get_executor()));
        ASSERT_TRUE(NewRegistration);

        OldRegistration.Reset();

        Preview::Runtime::SessionInfo Found;
        EXPECT_TRUE(Registry.Find(71, Found));
        EXPECT_EQ(Found.identity, "user-71");
        EXPECT_EQ(Registry.Size(), 1U);

        NewRegistration.Reset();
    }

    TEST(SessionRegistry, ResetKeepsLogicalRemovalWhenCompactionAllocationFails)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto RemovedControl = std::make_shared<Preview::Runtime::SessionControl>(Execution.Io.get_executor());
        auto LiveControl = std::make_shared<Preview::Runtime::SessionControl>(Execution.Io.get_executor());
        auto Removed = Registry.Register(MakeInfo(73), RemovedControl);
        auto Live = Registry.Register(MakeInfo(74), LiveControl);
        ASSERT_TRUE(Removed);
        ASSERT_TRUE(Live);
        const auto OldSnapshot = Registry.Snapshot();

        Preview::Runtime::SessionRegistryTestAccess::FailNextRemovalCompaction(Registry);
        Removed.Reset();

        Preview::Runtime::SessionInfo Found;
        EXPECT_FALSE(Registry.Find(73, Found));
        EXPECT_EQ(Registry.Size(), 1U);
        EXPECT_EQ(Registry.PendingRemovals(), 1U);
        EXPECT_FALSE(Registry.Cancel(73));
        EXPECT_TRUE(Registry.Cancel(74));
        EXPECT_EQ(LiveControl->Metrics().CancelRequests, 1U);
        EXPECT_TRUE(Registry.Find(74, Found));
        EXPECT_EQ(Found.identity, "user-74");
        ASSERT_EQ(OldSnapshot->size(), 2U);
        EXPECT_EQ(OldSnapshot->at(73).identity, "user-73");
        EXPECT_EQ(OldSnapshot->at(74).identity, "user-74");

        auto Inserted = RegisterForTest(Registry, Execution.Io, MakeInfo(75));
        ASSERT_TRUE(Inserted);

        EXPECT_EQ(Registry.PendingRemovals(), 0U);
        EXPECT_EQ(Registry.Size(), 2U);
        EXPECT_FALSE(Registry.Find(73, Found));
        EXPECT_TRUE(Registry.Find(74, Found));
        EXPECT_TRUE(Registry.Find(75, Found));
        EXPECT_EQ(OldSnapshot->size(), 2U);

        Live.Reset();
        EXPECT_EQ(Registry.Size(), 1U);
        Inserted.Reset();
        EXPECT_EQ(Registry.Size(), 0U);
    }

    TEST(SessionRegistry, RetiredGenerationHooksCannotReportForReusedId)
    {
        constexpr std::uint64_t SessionId = 76;
        boost::asio::io_context Io;
        Preview::Runtime::SessionRegistry Registry;
        std::atomic<std::size_t> ErrorReports{0};
        std::atomic<std::size_t> MetricsReports{0};
        Registry.SetErrorHook(
            [&ErrorReports](std::uint64_t, Preview::Fault::Failure)
            { ErrorReports.fetch_add(1, std::memory_order_relaxed); });
        Registry.SetMetricsHook(
            [&MetricsReports](std::uint64_t, const Preview::Runtime::SessionMetrics &)
            { MetricsReports.fetch_add(1, std::memory_order_relaxed); });

        auto OldControl = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto OldRegistration = Registry.Register(MakeInfo(SessionId), OldControl);
        ASSERT_TRUE(OldRegistration);
        EXPECT_TRUE(Registry.Remove(SessionId));

        auto NewControl = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto NewRegistration = Registry.Register(MakeInfo(SessionId), NewControl);
        ASSERT_TRUE(NewRegistration);

        OldControl->ReportError(Preview::Fault::Failure{Preview::Fault::Code::IoError});
        OldControl->Cancel();
        Io.run();

        EXPECT_EQ(ErrorReports.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(MetricsReports.load(std::memory_order_relaxed), 0U);
        Preview::Runtime::SessionInfo Found;
        EXPECT_TRUE(Registry.Find(SessionId, Found));

        OldRegistration.Reset();
        EXPECT_TRUE(Registry.Find(SessionId, Found));
        NewRegistration.Reset();
    }

    TEST(SessionRegistry, HookInstallFailureRetiresPublishedRecord)
    {
        boost::asio::io_context Io;
        Preview::Runtime::SessionRegistry Registry;
        std::atomic<std::size_t> ErrorReports{0};
        Registry.SetErrorHook(
            [&ErrorReports](std::uint64_t, Preview::Fault::Failure)
            { ErrorReports.fetch_add(1, std::memory_order_relaxed); });
        Registry.SetMetricsHook(
            [](std::uint64_t, const Preview::Runtime::SessionMetrics &) {});

        auto FailedControl = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        Preview::Runtime::SessionRegistryTestAccess::FailNextMetricsHookInstallation(Registry);
        const auto FailedRegistration = Registry.Register(MakeInfo(77), FailedControl);
        EXPECT_FALSE(FailedRegistration);

        Preview::Runtime::SessionInfo Found;
        EXPECT_FALSE(Registry.Find(77, Found));
        EXPECT_EQ(Registry.Size(), 0U);
        EXPECT_EQ(Registry.PendingRemovals(), 0U);

        FailedControl->ReportError(Preview::Fault::Failure{Preview::Fault::Code::IoError});
        Io.run();
        EXPECT_EQ(ErrorReports.load(std::memory_order_relaxed), 0U);

        auto Replacement = Registry.Register(
            MakeInfo(77), std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor()));
        ASSERT_TRUE(Replacement);
        Replacement.Reset();
        Io.restart();
        Io.run();
    }

    TEST(SessionRegistry, FindAndSnapshotReturnIndependentValues)
    {
        SessionRegistryTestExecutor Execution;
        Preview::Runtime::SessionRegistry Registry;
        auto Registration = RegisterForTest(Registry, Execution.Io, MakeInfo(72));
        ASSERT_TRUE(Registration);
        const auto Snapshot = Registry.Snapshot();

        Preview::Runtime::SessionInfo Found;
        ASSERT_TRUE(Registry.Find(72, Found));
        Found.identity = "caller-owned";
        Found.peer = "caller-peer";
        Found.Target = "caller-target";

        Preview::Runtime::SessionInfo Current;
        ASSERT_TRUE(Registry.Find(72, Current));
        EXPECT_EQ(Current.identity, "user-72");
        EXPECT_EQ(Current.peer, "127.0.0.1");
        EXPECT_EQ(Current.Target, "example.com:443");

        Registry.Remove(72);
        EXPECT_EQ(Snapshot->at(72).identity, "user-72");
        EXPECT_EQ(Snapshot->at(72).peer, "127.0.0.1");
        EXPECT_EQ(Snapshot->at(72).Target, "example.com:443");
    }

    TEST(SessionRegistry, CancelAndResetOverlapHasOneLinearizedOutcome)
    {
        constexpr std::size_t IterationCount = 16;
        boost::asio::io_context Io;
        Preview::Runtime::SessionRegistry Registry;

        for (std::size_t Index = 0; Index < IterationCount; ++Index)
        {
            const auto Id = static_cast<std::uint64_t>(100 + Index);
            auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
            auto Registration = Registry.Register(MakeInfo(Id), Control);
            ASSERT_TRUE(Registration);

            std::barrier StartGate(3);
            std::atomic<bool> CancelResult{false};
            std::thread CancelThread(
                [&]
                {
                    StartGate.arrive_and_wait();
                    CancelResult.store(Registry.Cancel(Id), std::memory_order_release);
                });
            std::thread ResetThread(
                [&]
                {
                    StartGate.arrive_and_wait();
                    Registration.Reset();
                });

            StartGate.arrive_and_wait();
            CancelThread.join();
            ResetThread.join();

            EXPECT_EQ(CancelResult.load(std::memory_order_acquire), Control->IsCancelled());
            Preview::Runtime::SessionInfo Found;
            EXPECT_FALSE(Registry.Find(Id, Found));
            EXPECT_EQ(Registry.Size(), 0U);
        }

        Io.run();
    }

    TEST(SessionRegistry, ShutdownReturnsBlockedForActiveBlockedDrain)
    {
        Preview::Runtime::SessionRegistry Registry;
        boost::asio::io_context Io;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto Registration = Registry.Register(MakeInfo(93), Control);
        ASSERT_TRUE(Registration);

        std::promise<void> Started;
        auto StartedFuture = Started.get_future();
        std::atomic<bool> OperationCompleted{false};
        auto Timer = std::make_shared<net::steady_timer>(Io);
        Timer->expires_after(std::chrono::hours(1));
        ASSERT_TRUE(Control->Start(
            Preview::Lifecycle::TaskRequest{},
            WaitForCancellation(Timer, Started, OperationCompleted)));

        std::thread IoThread([&Io] { Io.run(); });
        if (StartedFuture.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
        {
            Io.stop();
            IoThread.join();
            ADD_FAILURE() << "Control operation did not start before the 1 s deadline";
            return;
        }

        ASSERT_TRUE(Preview::Runtime::SessionRegistryTestAccess::BlockDrain(*Control));

        auto Watchdog = std::make_shared<net::steady_timer>(Io);
        Watchdog->expires_after(std::chrono::seconds(1));
        std::atomic<bool> WatchdogExpired{false};
        Watchdog->async_wait(
            [&Io, &WatchdogExpired](const boost::system::error_code &Error)
            {
                if (!Error)
                {
                    WatchdogExpired.store(true, std::memory_order_release);
                    Io.stop();
                }
            });

        bool ShutdownCompleted = false;
        std::exception_ptr ShutdownFailure;
        Preview::Fault::Failure ShutdownResult{Preview::Fault::Code::GenericError};
        std::size_t ActiveAtReturn = 0;
        net::co_spawn(
            Io, Registry.Shutdown(),
            [&](std::exception_ptr Failure,
                std::expected<void, Preview::Fault::Failure> Result)
            {
                ShutdownFailure = std::move(Failure);
                ShutdownResult = Result ? Preview::Fault::Failure{} : Result.error();
                ActiveAtReturn = Control->Metrics().Active;
                ShutdownCompleted = true;
                (void)Timer->cancel();
                (void)Watchdog->cancel();
            });
        IoThread.join();

        EXPECT_TRUE(ShutdownCompleted) << "Shutdown did not return a bounded blocked result";
        EXPECT_FALSE(WatchdogExpired.load(std::memory_order_acquire));
        EXPECT_EQ(ShutdownFailure, nullptr);
        EXPECT_EQ(ShutdownResult.Code, Preview::Fault::Code::Blocked);
        EXPECT_EQ(ActiveAtReturn, 1U);
        EXPECT_TRUE(Control->IsCancelled());
        EXPECT_EQ(Control->Metrics().CancelRequests, 1U);
        EXPECT_EQ(Registry.Size(), 1U);
        EXPECT_TRUE(OperationCompleted.load(std::memory_order_acquire));
        Registration.Reset();
    }

} // namespace
