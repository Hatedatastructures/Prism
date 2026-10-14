/**
 * @file SessionDeliveryLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionLifecycleTestSupport.hpp"
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>

namespace
{
    struct PostThenQuarantineResult final
    {
        bool DoneObserved{false};
        bool Ack{true};
        bool TimedOut{false};
        int CompletionCalls{0};
        std::exception_ptr Failure;
        bool DrainBlocked{false};
    };

    struct PostThenQuarantineState final
    {
        Net::io_context Caller;
        Net::io_context Worker;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Registry;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
        std::shared_ptr<ConcurrentSignal> Done;
        bool Ack{true};
        bool DoneObserved{false};
        std::atomic<int> CompletionCalls{0};
        std::atomic<bool> TimedOut{false};
        std::exception_ptr Failure;
        std::thread WorkerThread;

        PostThenQuarantineState()
            : Registry(std::make_shared<Preview::Lifecycle::TaskRegistry>(Worker.get_executor())),
              Reclaimer(Registry->Reclaimer()), Done(MakeConcurrentSignal(Caller.get_executor()))
        {
        }
    };

    auto RunPostThenQuarantineCaller(
        std::shared_ptr<PostThenQuarantineState> State) -> Net::awaitable<void>
    {
        Net::co_spawn(
            State->Caller,
            Preview::Runtime::SessionDelivery::Await(State->Reclaimer, State->Registry),
            [State](std::exception_ptr Error, bool Delivered)
            {
                State->CompletionCalls.fetch_add(1, std::memory_order_acq_rel);
                State->Failure = std::move(Error);
                State->Ack = Delivered;
                (void)State->Done->try_send(boost::system::error_code{});
            });
        co_await Net::post(State->Caller, Net::use_awaitable);
        EXPECT_GT(State->Reclaimer->Pending(), 0U);
        State->Reclaimer->Quarantine();
        State->WorkerThread = std::thread([State] { State->Worker.run(); });
        State->DoneObserved = co_await WaitForSignalOrTimeout(State->Done, State->Caller);
        if (!State->DoneObserved)
        {
            State->TimedOut.store(true, std::memory_order_release);
            State->Caller.stop();
            State->Worker.stop();
        }
    }

    auto RunPostThenQuarantine() -> PostThenQuarantineResult
    {
        auto State = std::make_shared<PostThenQuarantineState>();
        auto WorkerWork = Net::make_work_guard(State->Worker);
        Net::co_spawn(
            State->Caller,
            RunPostThenQuarantineCaller(State),
            [State](std::exception_ptr Error)
            {
                if (Error)
                {
                    State->Failure = std::move(Error);
                }
                State->Caller.stop();
            });
        std::thread CallerThread([State] { State->Caller.run(); });
        CallerThread.join();
        WorkerWork.reset();
        if (State->WorkerThread.joinable())
        {
            State->WorkerThread.join();
        }
        return PostThenQuarantineResult{
            State->DoneObserved,
            State->Ack,
            State->TimedOut.load(std::memory_order_acquire),
            State->CompletionCalls.load(std::memory_order_acquire),
            State->Failure,
            State->Registry->IsDrainBlocked()};
    }

    struct QueuedDropProbe final
    {
        std::atomic<bool> Pending{false};
        std::atomic<bool> Delivered{false};
        std::atomic<int> CompletionCalls{0};
    };

    struct QueuedDropState final
    {
        std::unique_ptr<Net::io_context> Caller{std::make_unique<Net::io_context>()};
        Net::io_context Owner;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Registry;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
        std::shared_ptr<std::promise<void>> ReadyPromise{std::make_shared<std::promise<void>>()};
        std::shared_ptr<QueuedDropProbe> Result{std::make_shared<QueuedDropProbe>()};
        std::thread CallerThread;

        QueuedDropState()
            : Registry(std::make_shared<Preview::Lifecycle::TaskRegistry>(Owner.get_executor())),
              Reclaimer(Registry->Reclaimer())
        {
        }
    };

    auto RunQueuedDropCaller(std::shared_ptr<QueuedDropState> State)
        -> Net::awaitable<void>
    {
        Net::co_spawn(
            *State->Caller,
            Preview::Runtime::SessionDelivery::Await(State->Reclaimer, State->Registry),
            [Result = State->Result](std::exception_ptr, bool Delivered)
            {
                Result->CompletionCalls.fetch_add(1, std::memory_order_acq_rel);
                Result->Delivered.store(Delivered, std::memory_order_release);
            });
        co_await Net::post(*State->Caller, Net::use_awaitable);
        State->Result->Pending.store(
            State->Reclaimer->Pending() > 0U, std::memory_order_release);
        State->ReadyPromise->set_value();
    }

    auto RunQueuedDropGuard() -> std::shared_ptr<QueuedDropProbe>
    {
        auto State = std::make_shared<QueuedDropState>();
        auto ReadyFuture = State->ReadyPromise->get_future();
        Net::co_spawn(
            *State->Caller,
            RunQueuedDropCaller(State),
            [State](std::exception_ptr Error)
            {
                if (Error)
                {
                    State->Caller->stop();
                }
            });
        State->CallerThread = std::thread([State] { State->Caller->run(); });
        const auto Ready = ReadyFuture.wait_for(std::chrono::seconds(2)) ==
            std::future_status::ready;
        EXPECT_TRUE(Ready);
        if (!Ready)
        {
            State->Caller->stop();
            State->CallerThread.join();
            State->Caller.reset();
            return State->Result;
        }
        EXPECT_TRUE(State->Result->Pending.load(std::memory_order_acquire));
        State->Caller->stop();
        State->CallerThread.join();
        State->Caller.reset();
        State->Reclaimer->Quarantine();
        std::thread OwnerThread([State] { State->Owner.run(); });
        OwnerThread.join();
        EXPECT_EQ(State->Reclaimer->Pending(), 0U);
        EXPECT_EQ(State->Reclaimer->QuarantinedCount(), 1U);
        return State->Result;
    }

    struct SharedDependencyState final
    {
        std::weak_ptr<const Preview::Recognition::Profile> WeakProfile;
        std::weak_ptr<Preview::Contract::StreamFactory> WeakFactory;
        std::weak_ptr<Preview::Middleware::Context::PadConfig> WeakPad;
        std::weak_ptr<OwnedTrafficSink> WeakTraffic;
    };

    auto BuildSharedDependencySession(const std::shared_ptr<SharedDependencyState> &State)
        -> std::unique_ptr<Preview::Runtime::Session>
    {
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Preview::Recognition::CandidateSpec Candidate;
        Candidate.Id = 1;
        Candidate.Name = "owned-profile";
        Candidate.Protocol = Preview::Contract::ProtocolType::Socks5;
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const Preview::Recognition::ProbeSnapshot &)
        { return Preview::Recognition::MatchState::Structural; };
        Candidate.Commit = [](Preview::Recognition::CommitContext Context)
            -> Net::awaitable<Preview::Recognition::CommitResult>
        {
            Preview::Recognition::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Transport = std::move(Context.Inbound);
            Result.Status = Preview::Recognition::RecognitionStatus::Accepted;
            co_return Result;
        };
        Preview::Recognition::ProfileSpec Spec;
        Spec.ConfiguredCandidate = Candidate.Id;
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Built = Preview::Recognition::Profile::Compile(std::move(Spec));
        EXPECT_TRUE(Built) << (Built ? "" : Preview::Recognition::ToStringView(Built.error()));
        auto Profile = Built ? *Built : Preview::Recognition::SharedProfile{};
        auto Factory = std::make_shared<Preview::Testing::StreamFactory>(
            [](Preview::SharedTransmission, Preview::Contract::RequestMetadata)
                -> Net::awaitable<Preview::Contract::AcceptOutcome>
            { co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::NotSupported)); });
        auto Pad = std::make_shared<Preview::Middleware::Context::PadConfig>();
        auto Traffic = std::make_shared<OwnedTrafficSink>();
        State->WeakProfile = Profile;
        State->WeakFactory = Factory;
        State->WeakPad = Pad;
        State->WeakTraffic = Traffic;
        Services->Profile = std::move(Profile);
        Services->ResolveCandidate = [Factory = std::move(Factory)](
                                          Preview::Recognition::CandidateId)
            -> std::shared_ptr<Preview::Contract::StreamFactory> { return Factory; };
        Services->Pad = std::move(Pad);
        Services->Traffic = std::move(Traffic);
        Preview::Runtime::SessionOptions Options;
        Options.Services = std::move(Services);
        return std::make_unique<Preview::Runtime::Session>(std::move(Options));
    }

    auto AcceptAfterRelease(
        std::shared_ptr<ByteChannel> Release,
        Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{Inbound};
        co_await WaitForRelease(Release);
        co_return Plane;
    }

    struct ReleaseAcceptFactory final
    {
        std::shared_ptr<ByteChannel> Release;

        auto operator()(Preview::SharedTransmission Inbound,
                        Preview::Contract::RequestMetadata) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AcceptAfterRelease(Release, std::move(Inbound));
        }
    };

    struct ReleaseSessionFactory final
    {
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;

        auto operator()(Preview::Runtime::SessionAdmission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            Preview::Runtime::SessionOptions Options;
            Options.Control = Control;
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                ReleaseAcceptFactory{Release});
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    struct ControlledReleaseSessionFactory final
    {
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<std::shared_ptr<Preview::Runtime::SessionControl>> ActiveControl;

        auto operator()(Preview::Runtime::SessionAdmission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            auto Control = std::make_shared<Preview::Runtime::SessionControl>();
            *ActiveControl = Control;
            Preview::Runtime::SessionOptions Options;
            Options.Control = Control;
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                ReleaseAcceptFactory{Release});
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    auto AwaitListenerShutdown(
        std::shared_ptr<Preview::Runtime::TcpListener> Listener,
        std::shared_ptr<bool> Completed) -> Net::awaitable<void>
    {
        co_await Listener->Shutdown();
        *Completed = true;
    }

    struct ListenerShutdownRequest final
    {
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        Net::any_io_executor Executor;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<bool> ShutdownCompleted;
    };

    auto RunListenerShutdown(ListenerShutdownRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Preview::Fault::Code::Success);
        const auto Port = Request.Listener->LocalEndpoint().port();
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Port});
        Preview::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        const bool ClientReady = Client != nullptr;
        EXPECT_TRUE(ClientReady);
        if (!ClientReady)
        {
            Request.Listener->Stop();
            co_return;
        }

        const std::string Greeting("\x05\x01\x00", 3);
        const auto Write = co_await Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        Net::steady_timer Accepted(Request.Executor);
        Accepted.expires_after(std::chrono::milliseconds(20));
        co_await Accepted.async_wait(Net::use_awaitable);
        EXPECT_EQ(Request.Listener->Registry().Size(), 1U);

        Request.Listener->Stop();
        EXPECT_EQ(Request.Listener->Registry().Size(), 1U);
        Net::co_spawn(
            Request.Executor,
            AwaitListenerShutdown(Request.Listener, Request.ShutdownCompleted),
            Net::detached);
        Net::steady_timer Pending(Request.Executor);
        Pending.expires_after(std::chrono::milliseconds(20));
        co_await Pending.async_wait(Net::use_awaitable);
        EXPECT_FALSE(*Request.ShutdownCompleted);
        (void)Request.Release->try_send(boost::system::error_code{});
        co_await Request.Listener->Shutdown();
        EXPECT_TRUE(*Request.ShutdownCompleted);
        (void)Client->Close();
    }

    struct ListenerDestructorRequest final
    {
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        Net::any_io_executor Executor;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<std::shared_ptr<Preview::Runtime::SessionControl>> ActiveControl;
        std::shared_ptr<Preview::SharedTransmission> Client;
    };

    auto RunListenerDestructorProbe(ListenerDestructorRequest Request)
        -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Preview::Fault::Code::Success);
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        if (Dialed)
        {
            *Request.Client = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        const bool ClientReady = *Request.Client != nullptr;
        EXPECT_TRUE(ClientReady);
        if (!ClientReady)
        {
            co_return;
        }

        const std::string Greeting("\x05\x01\x00", 3);
        const auto Write = co_await (*Request.Client)->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        Net::steady_timer Accepted(Request.Executor);
        Accepted.expires_after(std::chrono::milliseconds(20));
        co_await Accepted.async_wait(Net::use_awaitable);
        EXPECT_NE(*Request.ActiveControl, nullptr);
        if (*Request.ActiveControl)
        {
            EXPECT_EQ(Request.Listener->Registry().Size(), 1U);
        }
    }
}

TEST(SessionDeliveryLifecycle, PostThenQuarantineReturnsFalseWithoutHanging)
    {
        const auto Result = RunPostThenQuarantine();
        EXPECT_FALSE(Result.TimedOut);
        EXPECT_TRUE(Result.DoneObserved);
        EXPECT_FALSE(Result.Ack);
        EXPECT_EQ(Result.CompletionCalls, 1);
        EXPECT_EQ(Result.Failure, nullptr);
        EXPECT_TRUE(Result.DrainBlocked);
    }

TEST(SessionDeliveryLifecycle, QueuedDropGuardSurvivesCallerIoDestruction)
    {
        const auto Result = RunQueuedDropGuard();
        EXPECT_TRUE(Result->Pending.load(std::memory_order_acquire));
        EXPECT_FALSE(Result->Delivered.load(std::memory_order_acquire));
        EXPECT_LE(Result->CompletionCalls.load(std::memory_order_acquire), 1);
    }

TEST(SessionServicesLifecycle, SharedDependenciesOutliveCallerScope)
    {
        auto State = std::make_shared<SharedDependencyState>();
        auto Session = BuildSharedDependencySession(State);

        EXPECT_FALSE(State->WeakProfile.expired());
        EXPECT_FALSE(State->WeakFactory.expired());
        EXPECT_FALSE(State->WeakPad.expired());
        EXPECT_FALSE(State->WeakTraffic.expired());
        Session.reset();
        EXPECT_TRUE(State->WeakProfile.expired());
        EXPECT_TRUE(State->WeakFactory.expired());
        EXPECT_TRUE(State->WeakPad.expired());
        EXPECT_TRUE(State->WeakTraffic.expired());
    }

TEST(TcpListenerLifecycle, StopOnlyStopsAcceptAndControllerShutdownDrainsSessions)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            Preview::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = ReleaseSessionFactory{Release, {}}});
        auto ShutdownCompleted = std::make_shared<bool>(false);

        RunCoro(Ioc, RunListenerShutdown(ListenerShutdownRequest{
                            Listener, Ioc.get_executor(), Release, ShutdownCompleted}));
    }

TEST(TcpListenerLifecycle, DestructorCancelsActiveSessionWithoutBlocking)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto ActiveControl = std::make_shared<std::shared_ptr<Preview::Runtime::SessionControl>>();
        auto Client = std::make_shared<Preview::SharedTransmission>();
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            Preview::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = ControlledReleaseSessionFactory{Release, ActiveControl}});

        RunCoro(Ioc, RunListenerDestructorProbe(
                            ListenerDestructorRequest{
                                Listener, Ioc.get_executor(), Release, ActiveControl, Client}));

        ASSERT_NE(*ActiveControl, nullptr);
        auto Control = *ActiveControl;
        Listener.reset();
        EXPECT_TRUE(Control->IsCancelled());

        Release->try_send(boost::system::error_code{});
        if (*Client)
        {
            (void)(*Client)->Close();
        }
        Ioc.restart();
        RunCoro(
            Ioc,
            [Control]() -> Net::awaitable<void>
            {
                co_await Control->Drain();
            });
        EXPECT_TRUE(Control->IsClosed());
    }

