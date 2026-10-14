/**
 * @file ConfiguredModeCommitTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfiguredModeTestSupport.hpp"

namespace
{

    struct SlowPrepareState final
    {
        using Signal = boost::asio::experimental::channel<void(boost::system::error_code)>;

        explicit SlowPrepareState(Net::any_io_executor Executor)
            : Timer(std::make_shared<Net::steady_timer>(Executor)),
              ControlGate(std::make_shared<Signal>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<Net::steady_timer> Timer;
        std::shared_ptr<Signal> ControlGate;
        bool CancelRequested{false};
        bool Completed{false};
        bool PrepareStarted{false};
        std::size_t WaitFactories{0};
        std::size_t PrepareWaits{0};
        std::size_t Commits{0};
    };

    auto RunSlowPrepare(
        std::shared_ptr<SlowPrepareState> State,
        rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
    {
        State->PrepareStarted = true;
        (void)State->ControlGate->try_send(boost::system::error_code{});
        State->Timer->expires_after(std::chrono::milliseconds(150));
        co_await State->Timer->async_wait(Net::use_awaitable);
        State->Completed = true;
        auto Result = AcceptedPrepare(Context.Candidate);
        Result.Status = rec::RecognitionStatus::IoError;
        Result.Error = std::make_error_code(std::errc::operation_canceled);
        co_return Result;
    }

}

TEST(ConfiguredModeTest, InFlightReadCancellationClosesAndReturnsCancelled)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->SetPending();
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7), 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(*WaitCalls, 1U);
        EXPECT_TRUE(Transport->ReadCompleted());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, InFlightReadTimeoutClosesAndReturnsTimedOut)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->SetPending();
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7), 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_FALSE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(*WaitCalls, 1U);
        EXPECT_TRUE(Transport->ReadCompleted());
    }

TEST(ConfiguredModeTest, DeadlineOnlyRaceClosesPendingRead)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->SetPending();
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7), 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        rec::RecognitionControl Control;
        Control.Deadline = rec::RecognitionControl::Clock::now() + std::chrono::milliseconds(1);
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_FALSE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_TRUE(Transport->ReadCompleted());
    }

TEST(ConfiguredModeTest, ProfileDeadlineWinsOverLongWaitForPendingRead)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->SetPending();
        auto WaitCalls = std::make_shared<std::size_t>(0);
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile(
            {CallsState, AcceptedPrepare(7), AcceptedCommit(7), 1, std::chrono::milliseconds(1)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_FALSE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_EQ(*WaitCalls, 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_TRUE(Transport->ReadCompleted());
    }

TEST(ConfiguredModeTest, ControlledPrepareWaitsForLateCompletionBeforeReturning)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto Slow = std::make_shared<SlowPrepareState>(Io.get_executor());

        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        Spec.Budget.Timeout = std::chrono::seconds(1);
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "slow-cancel";
        Candidate.Protocol = Preview::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [Slow](rec::PrepareContext Context)
        { return RunSlowPrepare(Slow, std::move(Context)); };
        Candidate.Commit = [Slow](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++Slow->Commits;
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        rec::ProbeBuffer Buffer(32);
        const auto Prefix = Bytes({0xA1});
        ASSERT_TRUE(Buffer.Seed(Prefix));
        rec::ConfiguredMode Mode(Compiled.value());
        rec::RecognitionControl Control;
        Control.Wait = [Slow]() -> Net::awaitable<rec::RecognitionControlEvent>
        {
            ++Slow->WaitFactories;
            co_await Slow->ControlGate->async_receive(Net::use_awaitable);
            if (Slow->PrepareStarted) ++Slow->PrepareWaits;
            co_return rec::RecognitionControlEvent::Cancelled;
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Slow]
        {
            Slow->CancelRequested = true;
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        const bool CompletedWhenReturned = Slow->Completed;
        if (!CompletedWhenReturned)
        {
            Io.restart();
            Io.run();
        }
        EXPECT_TRUE(CompletedWhenReturned);
        EXPECT_TRUE(Slow->CancelRequested);
        EXPECT_EQ(Slow->PrepareWaits, 1U);
        EXPECT_GE(Slow->WaitFactories, 1U);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Result.Candidate, 7U);
        EXPECT_EQ(Slow->Commits, 0U);
    }

TEST(ConfiguredModeTest, ThrowingControlCancellationJoinsSlowPrepareBeforeRethrow)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto Slow = std::make_shared<SlowPrepareState>(Io.get_executor());

        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        Spec.Budget.Timeout = std::chrono::seconds(1);
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "throwing-cancel";
        Candidate.Protocol = Preview::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [Slow](rec::PrepareContext Context)
        { return RunSlowPrepare(Slow, std::move(Context)); };
        Candidate.Commit = [Slow](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++Slow->Commits;
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        rec::ProbeBuffer Buffer(32);
        const auto Prefix = Bytes({0xA1});
        ASSERT_TRUE(Buffer.Seed(Prefix));
        rec::ConfiguredMode Mode(Compiled.value());
        auto ExpectedFailure = std::make_shared<std::exception_ptr>();
        rec::RecognitionControl Control;
        Control.Wait = [Slow]() -> Net::awaitable<rec::RecognitionControlEvent>
        {
            ++Slow->WaitFactories;
            co_await Slow->ControlGate->async_receive(Net::use_awaitable);
            if (Slow->PrepareStarted) ++Slow->PrepareWaits;
            co_return rec::RecognitionControlEvent::Cancelled;
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Slow, ExpectedFailure]
        {
            Slow->CancelRequested = true;
            *ExpectedFailure = std::make_exception_ptr(
                std::runtime_error("control cancellation failure"));
            std::rethrow_exception(*ExpectedFailure);
        };
        std::exception_ptr Failure;
        try
        {
            RunCoro(Io, [&]() -> Net::awaitable<void>
                    {
                        (void)co_await Mode.Recognize(Transport, Buffer, Control);
                    });
        }
        catch (...)
        {
            Failure = std::current_exception();
        }

        ASSERT_NE(Failure, nullptr);
        ASSERT_NE(*ExpectedFailure, nullptr);
        EXPECT_EQ(Failure, *ExpectedFailure);
        EXPECT_THROW(std::rethrow_exception(Failure), std::runtime_error);
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::runtime_error& Error)
        {
            EXPECT_STREQ(Error.what(), "control cancellation failure");
        }
        EXPECT_TRUE(Slow->CancelRequested);
        EXPECT_TRUE(Slow->Completed);
        EXPECT_EQ(Slow->PrepareWaits, 1U);
        EXPECT_GE(Slow->WaitFactories, 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Slow->Commits, 0U);
    }

TEST(ConfiguredModeTest, CleanupAttemptsCloseAfterCancelFailureAndCleansSibling)
    {
        Net::io_context ReturnedIo;
        Net::io_context InboundIo;
        auto Returned = std::make_shared<ScriptedTransport>(ReturnedIo.get_executor());
        auto Inbound = std::make_shared<ScriptedTransport>(InboundIo.get_executor());
        Returned->ThrowOnCancel();
        Returned->ThrowOnClose();

        const auto Failure = rec::detail::CleanupTransports({Returned, Inbound});

        ASSERT_NE(Failure, nullptr);
        EXPECT_THROW(std::rethrow_exception(Failure), std::runtime_error);
        EXPECT_EQ(Returned->Cancels(), 1U);
        EXPECT_EQ(Returned->Closes(), 1U);
        EXPECT_EQ(Inbound->Cancels(), 1U);
        EXPECT_EQ(Inbound->Closes(), 1U);
    }

TEST(ConfiguredModeTest, WaitWithoutCancellationHookReturnsExplicitUnsupported)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(0), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_not_supported));
        EXPECT_EQ(*WaitCalls, 0U);
        EXPECT_TRUE(Transport->ReadRequests().empty());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, WaitCancellationSafetyFlagIsRequired)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.CancelTransport = [] {};
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_not_supported));
        EXPECT_EQ(*WaitCalls, 0U);
        EXPECT_TRUE(Transport->ReadRequests().empty());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }
