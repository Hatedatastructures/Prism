/**
 * @file SessionDeliveryTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionLifecycleSupport.hpp"
#include <Prism/Net/Target.hpp>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <boost/asio/this_coro.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace
{
    struct PostThenQuarantineResult final
    {
        bool DoneObserved{false};
        bool Ack{true};
        bool TimedOut{false};
        int CompletionCalls{0};
        std::exception_ptr Failure;
        Prism::Fault::Code DeliveryFailure{Prism::Fault::Code::Success};
    };

    struct PostThenQuarantineState final
    {
        Net::io_context Caller;
        Net::io_context Worker;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        std::shared_ptr<ConcurrentSignal> Done;
        bool Ack{true};
        bool DoneObserved{false};
        std::atomic<int> CompletionCalls{0};
        std::atomic<bool> TimedOut{false};
        std::exception_ptr Failure;
        Prism::Fault::Code DeliveryFailure{Prism::Fault::Code::Success};
        std::thread WorkerThread;

        PostThenQuarantineState()
            : Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Worker.get_executor())),
              Done(MakeConcurrentSignal(Caller.get_executor()))
        {
        }
    };

    auto RunPostThenQuarantineCaller(
        std::shared_ptr<PostThenQuarantineState> State) -> Net::awaitable<void>
    {
        auto Delivery = std::make_shared<Prism::Runtime::SessionDelivery>(State->Reclaimer);
        Net::co_spawn(
            State->Caller,
            Delivery->Await(),
            [State](std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Delivered)
            {
                State->CompletionCalls.fetch_add(1, std::memory_order_acq_rel);
                State->Failure = std::move(Error);
                State->Ack = Delivered.has_value();
                if (!Delivered) State->DeliveryFailure = Delivered.error().Code;
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
            State->DeliveryFailure};
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
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        std::shared_ptr<std::promise<void>> ReadyPromise{std::make_shared<std::promise<void>>()};
        std::shared_ptr<QueuedDropProbe> Result{std::make_shared<QueuedDropProbe>()};
        std::thread CallerThread;

        QueuedDropState()
            : Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Owner.get_executor()))
        {
        }
    };

    auto RunQueuedDropCaller(std::shared_ptr<QueuedDropState> State)
        -> Net::awaitable<void>
    {
        auto Delivery = std::make_shared<Prism::Runtime::SessionDelivery>(State->Reclaimer);
        Net::co_spawn(
            *State->Caller,
            Delivery->Await(),
            [Result = State->Result](std::exception_ptr,
                std::expected<void, Prism::Fault::Failure> Delivered)
            {
                Result->CompletionCalls.fetch_add(1, std::memory_order_acq_rel);
                Result->Delivered.store(Delivered.has_value(), std::memory_order_release);
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
        std::weak_ptr<const Prism::Recognition::Profile> WeakProfile;
        std::weak_ptr<Prism::Contract::StreamFactory> WeakFactory;
        std::weak_ptr<Prism::Middleware::Context::PadConfig> WeakPad;
        std::weak_ptr<OwnedTrafficSink> WeakTraffic;
    };

    auto BuildSharedDependencySession(const std::shared_ptr<SharedDependencyState> &State)
        -> std::unique_ptr<Prism::Runtime::Session>
    {
        auto Services = std::make_shared<Prism::Runtime::SessionServices>();
        Prism::Recognition::CandidateSpec Candidate;
        Candidate.Id = 1;
        Candidate.Name = "owned-profile";
        Candidate.Protocol = Prism::Contract::ProtocolType::Socks5;
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const Prism::Recognition::ProbeSnapshot &)
        { return Prism::Recognition::MatchState::Structural; };
        Candidate.Commit = [](Prism::Recognition::CommitContext Context)
            -> Net::awaitable<Prism::Recognition::CommitResult>
        {
            Prism::Recognition::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Transport = std::move(Context.Inbound);
            Result.Status = Prism::Recognition::RecognitionStatus::Accepted;
            co_return Result;
        };
        Prism::Recognition::ProfileSpec Spec;
        Spec.ConfiguredCandidate = Candidate.Id;
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Built = Prism::Recognition::Profile::Compile(std::move(Spec));
        EXPECT_TRUE(Built) << (Built ? "" : Prism::Recognition::ToStringView(Built.error()));
        auto Profile = Built ? *Built : Prism::Recognition::SharedProfile{};
        auto Factory = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            { co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::Unsupported)); });
        auto Pad = std::make_shared<Prism::Middleware::Context::PadConfig>();
        auto Traffic = std::make_shared<OwnedTrafficSink>();
        State->WeakProfile = Profile;
        State->WeakFactory = Factory;
        State->WeakPad = Pad;
        State->WeakTraffic = Traffic;
        Services->Profile = std::move(Profile);
        Services->ResolveCandidate = [Factory = std::move(Factory)](
                                          Prism::Recognition::CandidateId)
            -> std::shared_ptr<Prism::Contract::StreamFactory> { return Factory; };
        Services->Pad = std::move(Pad);
        Services->Traffic = std::move(Traffic);
        Prism::Runtime::SessionOptions Options;
        Options.Services = std::move(Services);
        return std::make_unique<Prism::Runtime::Session>(std::move(Options));
    }

    auto AcceptAfterRelease(
        std::shared_ptr<ByteChannel> Release,
        std::shared_ptr<ByteChannel> Started,
        Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        Plane.Target = Prism::Network::Target{
            Prism::Network::Host{Prism::Network::Ipv4Bytes{{127U, 0U, 0U, 1U}}}, 443U};
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        EXPECT_TRUE(Started->try_send(boost::system::error_code{}));
        co_await WaitForRelease(Release);
        co_return Plane;
    }

    struct ReleaseAcceptFactory final
    {
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptAfterRelease(Release, Started, std::move(Input));
        }
    };

    struct ReleaseSessionFactory final
    {
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;

        auto operator()(Prism::Runtime::SessionAdmission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            Prism::Runtime::SessionOptions Options;
            Options.Services->Bytes = Prism::Testing::Runtime::MakeListenerTestBytePool();
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                ReleaseAcceptFactory{Release, Started});
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    struct ListenerMemoryDialState final
    {
        explicit ListenerMemoryDialState(Net::any_io_executor Executor)
            : Streams(Prism::MakeMemoryPair(std::move(Executor)))
        {
        }

        std::pair<Prism::MemoryStream, Prism::MemoryStream> Streams;
    };

    auto RunListenerMemoryDial(
        const std::shared_ptr<ListenerMemoryDialState> &State,
        const Prism::Network::Target &Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        (void)Target;
        const auto Shutdown = co_await State->Streams.second.WriteShutdown();
        if (!Shutdown) co_return std::unexpected(Shutdown.error());
        Prism::SharedTransmission Outbound = std::make_shared<Prism::MemoryStream>(
            std::move(State->Streams.first));
        co_return Outbound;
    }

    class SessionCompletionTrafficSink final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit SessionCompletionTrafficSink(
            std::shared_ptr<ByteChannel> Value,
            Prism::Fault::Failure RetirementFailure = {})
            : Finished_(std::move(Value)), RetirementFailure_(RetirementFailure)
        {
        }

        auto Report(Prism::Foundation::TrafficEvent) noexcept -> void override
        {
        }

        auto Retire(Prism::Foundation::TrafficRetirement)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (!Finished_->try_send(boost::system::error_code{}))
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            if (RetirementFailure_.Failed())
                co_return std::unexpected(RetirementFailure_);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        std::shared_ptr<ByteChannel> Finished_;
        Prism::Fault::Failure RetirementFailure_;
    };

    struct ControlledReleaseSessionFactory final
    {
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<std::shared_ptr<Prism::Runtime::SessionControl>> ActiveControl;
        std::shared_ptr<ByteChannel> ErrorReady{};
        std::shared_ptr<std::optional<Prism::Fault::Failure>> ObservedFailure{};
        std::shared_ptr<Prism::Fault::Failure> RetirementFailure{};
        std::shared_ptr<ListenerMemoryDialState> MemoryDial{};
        std::shared_ptr<std::weak_ptr<Prism::Runtime::Session>> ActiveSession{};

        auto operator()(Prism::Runtime::SessionAdmission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            auto Control = std::make_shared<Prism::Runtime::SessionControl>();
            *ActiveControl = Control;
            if (ErrorReady && ObservedFailure)
            {
                Control->SetErrorHook(
                    Prism::Runtime::SessionControl::IdentityErrorHook{
                        [ErrorReady = ErrorReady, ObservedFailure = ObservedFailure](
                            const Prism::Lifecycle::TaskIdentity &,
                            const Prism::Fault::Failure Failure)
                        {
                            *ObservedFailure = Failure;
                            (void)ErrorReady->try_send(boost::system::error_code{});
                        }});
            }
            Prism::Runtime::SessionOptions Options;
            Options.Control = Control;
            Options.Services->Bytes = Prism::Testing::Runtime::MakeListenerTestBytePool();
            Options.Services->Traffic = std::make_shared<SessionCompletionTrafficSink>(
                Finished, RetirementFailure ? *RetirementFailure : Prism::Fault::Failure{});
            if (MemoryDial)
            {
                Options.Services->Dial = [MemoryDial = MemoryDial](
                    const Prism::Network::Target &Target)
                {
                    return RunListenerMemoryDial(MemoryDial, Target);
                };
            }
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                ReleaseAcceptFactory{Release, Started});
            auto SessionOwner = std::make_shared<Prism::Runtime::Session>(std::move(Options));
            if (ActiveSession) *ActiveSession = SessionOwner;
            return SessionOwner;
        }
    };

    auto WaitForAcceptStarted(const std::shared_ptr<ByteChannel>& Started)
        -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Started->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        EXPECT_FALSE(Error);
    }

    auto AwaitListenerShutdown(
        std::shared_ptr<Prism::Runtime::TcpListener> Listener,
        std::shared_ptr<bool> Completed) -> Net::awaitable<void>
    {
        co_await Listener->Shutdown();
        *Completed = true;
    }

    struct ListenerShutdownRequest final
    {
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        Net::any_io_executor Executor;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<bool> ShutdownCompleted;
    };

    auto RunListenerShutdown(ListenerShutdownRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Prism::Fault::Code::Success);
        const auto Port = Request.Listener->LocalEndpoint().port();
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Port});
        Prism::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
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
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            Request.Listener->Stop();
            co_await Request.Listener->Shutdown();
            co_return;
        }
        co_await WaitForAcceptStarted(Request.Started);
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
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        Net::any_io_executor Executor;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<std::shared_ptr<Prism::Runtime::SessionControl>> ActiveControl;
        std::shared_ptr<std::weak_ptr<Prism::Runtime::Session>> SessionOwner;
        std::shared_ptr<Prism::SharedTransmission> Client;
    };

    struct ListenerOwnedShutdownRequest final
    {
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;
    };

    auto RunListenerOwnedShutdown(ListenerOwnedShutdownRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Prism::Fault::Code::Success);
        Prism::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto Dialed = co_await Dialer.Connect({
            Prism::Network::Host{Prism::Network::Ipv4Bytes{{127U, 0U, 0U, 1U}}},
            Request.Listener->LocalEndpoint().port()});
        EXPECT_TRUE(Dialed);
        if (!Dialed) co_return;
        auto Client = std::move(*Dialed);
        constexpr std::array<std::byte, 3> Greeting{
            std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
        EXPECT_TRUE((co_await Client->WriteSome(Greeting)).Failure.Succeeded());
        co_await WaitForAcceptStarted(Request.Started);
        auto Operation = Request.Listener->Shutdown();
        Request.Listener.reset();
        Net::steady_timer Tick(co_await Net::this_coro::executor);
        Tick.expires_after(std::chrono::milliseconds(1));
        co_await Tick.async_wait(Net::use_awaitable);
        EXPECT_TRUE(Request.Release->try_send(boost::system::error_code{}));
        const auto Shutdown = co_await std::move(Operation);
        EXPECT_TRUE(Shutdown);
        (void)Client->Close();
    }

    auto RunListenerDestructorProbe(ListenerDestructorRequest Request)
        -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Prism::Fault::Code::Success);
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        if (Dialed)
        {
            *Request.Client = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
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
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            Request.Listener->Stop();
            co_return;
        }
        co_await WaitForAcceptStarted(Request.Started);
        EXPECT_NE(*Request.ActiveControl, nullptr);
        if (*Request.ActiveControl)
        {
            EXPECT_EQ(Request.Listener->Registry().Size(), 1U);
        }
    }

    auto AwaitListenerCompletionAndDrain(
        std::shared_ptr<ByteChannel> Finished,
        std::shared_ptr<Prism::Runtime::SessionControl> Control,
        std::weak_ptr<Prism::Runtime::Session> SessionOwner) -> Net::awaitable<void>
    {
        co_await WaitForRelease(Finished);
        for (std::size_t Attempt = 0;
             Attempt < 100U && (!SessionOwner.expired() || Control->Metrics().Active != 0U);
             ++Attempt)
        {
            Net::steady_timer Tick(co_await Net::this_coro::executor);
            Tick.expires_after(std::chrono::milliseconds(1));
            co_await Tick.async_wait(Net::use_awaitable);
        }
        EXPECT_TRUE(SessionOwner.expired());
        const auto Drained = co_await Control->Drain();
        EXPECT_TRUE(Drained);
    }

    struct ListenerTrafficRetirementFailureRequest final
    {
        Net::io_context &Ioc;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<ByteChannel> Release;
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<ByteChannel> ErrorReady;
    };

    auto RunListenerTrafficRetirementFailureProbe(
        ListenerTrafficRetirementFailureRequest Request) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Prism::Fault::Code::Success);
        if (StartResult != Prism::Fault::Code::Success) co_return;

        Prism::Network::Dialer::Dialer Dialer(Request.Ioc.get_executor());
        auto Dialed = co_await Dialer.Connect({
            Prism::Network::Host{Prism::Network::Ipv4Bytes{{127U, 0U, 0U, 1U}}},
            Request.Listener->LocalEndpoint().port()});
        EXPECT_TRUE(Dialed);
        if (!Dialed)
        {
            (void)co_await Request.Listener->Shutdown();
            co_return;
        }
        Prism::SharedTransmission Client = std::move(*Dialed);
        constexpr std::array<std::byte, 3> Greeting{
            std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
        const auto Written = co_await Client->WriteSome(Greeting);
        EXPECT_TRUE(Written.Failure.Succeeded());
        if (Written.Failure.Failed())
        {
            (void)co_await Request.Listener->Shutdown();
            co_return;
        }

        const bool AcceptStarted = co_await WaitForSignalOrTimeout(Request.Started, Request.Ioc);
        EXPECT_TRUE(AcceptStarted);
        if (!AcceptStarted)
        {
            (void)Client->Close();
            (void)co_await Request.Listener->Shutdown();
            co_return;
        }
        const auto HalfClosed = co_await Client->WriteShutdown();
        EXPECT_TRUE(HalfClosed);
        if (!HalfClosed)
        {
            (void)Client->Close();
            (void)co_await Request.Listener->Shutdown();
            co_return;
        }
        EXPECT_TRUE(Request.Release->try_send(boost::system::error_code{}));

        const bool TrafficRetirementCompleted =
            co_await WaitForSignalOrTimeout(Request.Finished, Request.Ioc);
        EXPECT_TRUE(TrafficRetirementCompleted);
        if (!TrafficRetirementCompleted)
        {
            (void)Client->Close();
            (void)co_await Request.Listener->Shutdown();
            co_return;
        }
        const bool FailureReported =
            co_await WaitForSignalOrTimeout(Request.ErrorReady, Request.Ioc);
        EXPECT_TRUE(FailureReported);
        (void)Client->Close();
        const auto Shutdown = co_await Request.Listener->Shutdown();
        EXPECT_TRUE(Shutdown);
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
        EXPECT_EQ(Result.DeliveryFailure, Prism::Fault::Code::Blocked);
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
        auto Started = MakeReleaseChannel(Ioc.get_executor());
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            Prism::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Factory = ReleaseSessionFactory{Release, Started},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});
        auto ShutdownCompleted = std::make_shared<bool>(false);

        RunCoro(Ioc, RunListenerShutdown(ListenerShutdownRequest{
                            Listener, Ioc.get_executor(), Release, Started, ShutdownCompleted}));
    }

TEST(TcpListenerLifecycle, DestructorRequestsCancellationWithoutWaitingForDrain)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto Started = MakeReleaseChannel(Ioc.get_executor());
        auto Finished = MakeReleaseChannel(Ioc.get_executor());
        auto ActiveControl = std::make_shared<std::shared_ptr<Prism::Runtime::SessionControl>>();
        auto SessionOwner = std::make_shared<std::weak_ptr<Prism::Runtime::Session>>();
        auto Client = std::make_shared<Prism::SharedTransmission>();
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            Prism::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Factory = ControlledReleaseSessionFactory{
                Release, Started, Finished, ActiveControl, {}, {}, {}, {}, SessionOwner},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});

        RunCoro(Ioc, RunListenerDestructorProbe(
                            ListenerDestructorRequest{
                                Listener, Ioc.get_executor(), Release, Started, Finished,
                                ActiveControl, SessionOwner, Client}));

        ASSERT_NE(*ActiveControl, nullptr);
        ASSERT_FALSE(SessionOwner->expired());
        auto Control = *ActiveControl;
        Listener.reset();
        EXPECT_TRUE(Control->IsCancelled());
        EXPECT_EQ(Control->CancellationReason(),
            Prism::Runtime::SessionCancellationReason::Shutdown);
        EXPECT_FALSE(Control->IsClosed());
        EXPECT_FALSE(SessionOwner->expired());

        Ioc.restart();
        Release->try_send(boost::system::error_code{});
        if (*Client)
        {
            (void)(*Client)->Close();
        }
        RunCoro(Ioc, AwaitListenerCompletionAndDrain(Finished, Control, *SessionOwner));
        EXPECT_TRUE(SessionOwner->expired());
        EXPECT_EQ(Control->Metrics().Active, 0U);
        EXPECT_TRUE(Control->IsClosed());
    }

TEST(TcpListenerLifecycle, ShutdownOwnsLifetimeAcrossListenerDestruction)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto Started = MakeReleaseChannel(Ioc.get_executor());
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            Prism::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Factory = ReleaseSessionFactory{Release, Started},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});

        RunCoro(Ioc, RunListenerOwnedShutdown(
                            ListenerOwnedShutdownRequest{Listener, Release, Started}));
    }

TEST(TcpListenerLifecycle, TrafficRetirementFailureIsReportedAfterNetworkDrain)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto Started = MakeReleaseChannel(Ioc.get_executor());
        auto Finished = MakeReleaseChannel(Ioc.get_executor());
        auto ErrorReady = MakeReleaseChannel(Ioc.get_executor());
        auto ActiveControl = std::make_shared<std::shared_ptr<Prism::Runtime::SessionControl>>();
        auto ObservedFailure = std::make_shared<std::optional<Prism::Fault::Failure>>();
        auto RetirementFailure = std::make_shared<Prism::Fault::Failure>(
            Prism::Fault::Code::ResourceUnavailable);
        auto MemoryDial = std::make_shared<ListenerMemoryDialState>(Ioc.get_executor());
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            Prism::Runtime::TcpListener::Options{
                .Executor = Ioc.get_executor(),
                .Factory = ControlledReleaseSessionFactory{
                    Release, Started, Finished, ActiveControl, ErrorReady,
                    ObservedFailure, RetirementFailure, MemoryDial, {}},
                .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                    Prism::GenerationId{1})});

        RunCoro(Ioc, RunListenerTrafficRetirementFailureProbe(
            ListenerTrafficRetirementFailureRequest{
                Ioc, Listener, Release, Started, Finished, ErrorReady}));

        ASSERT_NE(*ActiveControl, nullptr);
        ASSERT_TRUE(ObservedFailure->has_value());
        EXPECT_EQ((*ObservedFailure)->Code, Prism::Fault::Code::ResourceUnavailable);
    }
