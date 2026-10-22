/**
 * @file ConfiguredAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfiguredModeTestSupport.hpp"

namespace
{

    auto CommitReadsPrefix(
        const std::shared_ptr<Calls> &CallsState,
        rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
    {
        ++CallsState->Commit;
        std::array<std::byte, 1> Prefix{};
        (void)co_await Context.Inbound->ReadSome(Prefix);
        rec::CommitResult Result;
        Result.Candidate = Context.Candidate;
        Result.Status = rec::RecognitionStatus::Accepted;
        Result.Transport = std::move(Context.Inbound);
        co_return Result;
    }

}

TEST(ConfiguredModeTest, InspectsPreparesAndCommitsOnlyConfiguredCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03, 0x04}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Vless);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 1U);
        ASSERT_EQ(Transport->ReadRequests().size(), 1U);
        EXPECT_EQ(Transport->ReadRequests().front(), 3U);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 3> Replay{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Read = co_await Result.transport->ReadSome(Replay);
                    EXPECT_FALSE(Read.Failure.Failed());
                    EXPECT_EQ(Read.Bytes, Replay.size());
                });
        EXPECT_EQ(Replay, (std::array<std::byte, 3>{std::byte{0xA1}, std::byte{0x02}, std::byte{0x03}}));
        std::array<std::byte, 1> Tail{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Read = co_await Result.transport->ReadSome(Tail);
                    EXPECT_EQ(Read.Bytes, Tail.size());
                });
        EXPECT_EQ(Tail.front(), std::byte{0x04});
    }

TEST(ConfiguredModeTest, RejectsProfileWithDifferentMode)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        ConfiguredProfileRequest Request{CallsState, AcceptedPrepare(7), AcceptedCommit(7)};
        Request.Mode = rec::RecognitionMode::Deterministic;
        auto Profile = MakeConfiguredProfile(std::move(Request));
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::Deterministic);
        EXPECT_EQ(CallsState->Inspect, 0U);
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
        EXPECT_TRUE(Transport->ReadRequests().empty());
    }

TEST(ConfiguredModeTest, MixedTrialRejectsConfiguredProfile)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::Configured);
        EXPECT_EQ(CallsState->Inspect, 0U);
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
        EXPECT_TRUE(Transport->ReadRequests().empty());
    }

TEST(ConfiguredModeTest, CredentialFailureDoesNotCommitOrRetry)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Prepare = AcceptedPrepare(7);
        Prepare.Status = rec::RecognitionStatus::NoMatch;
        auto Profile = MakeConfiguredProfile({CallsState, Prepare, AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::NoMatch);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 0U);
        EXPECT_EQ(Transport->Writes(), 0U);
        EXPECT_EQ(Transport->Closes(), 0U);
    }

TEST(ConfiguredModeTest, CommitFailureIsTerminalAndNotRetried)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Commit = AcceptedCommit(7);
        Commit.Status = rec::RecognitionStatus::IoError;
        Commit.Error = std::make_error_code(std::errc::connection_reset);
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), Commit});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(CallsState->Commit, 1U);
        EXPECT_EQ(Transport->Writes(), 0U);
    }

TEST(ConfiguredModeTest, ReturnsBudgetExceededBeforeReadingWhenBufferCannotMeetBoundary)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(2, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::BudgetExceeded);
        EXPECT_TRUE(Transport->ReadRequests().empty());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, PreservesEofAndPollutedPrepareAsTerminalStates)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1}));
        Transport->Push({});
        auto CallsState = std::make_shared<Calls>();
        auto Prepare = AcceptedPrepare(7);
        Prepare.Status = rec::RecognitionStatus::Polluted;
        Prepare.Polluted = true;
        auto Profile = MakeConfiguredProfile({CallsState, Prepare, AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::EndOfStream);
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, PollutedPrepareStopsBeforeCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Prepare = AcceptedPrepare(7);
        Prepare.Status = rec::RecognitionStatus::NoMatch;
        Prepare.Polluted = true;
        auto Profile = MakeConfiguredProfile({CallsState, Prepare, AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Polluted);
        EXPECT_TRUE(Result.Polluted);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, CancellationIsReportedWithoutTouchingTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;
        rec::RecognitionControl Control;
        Control.Cancelled = [] { return true; };

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_TRUE(Transport->ReadRequests().empty());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, EnforcesCallerDeadlineBeforeReading)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognitionControl Control;
        Control.Deadline = rec::RecognitionControl::Clock::now() - std::chrono::milliseconds(1);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_TRUE(Transport->ReadRequests().empty());
        EXPECT_EQ(CallsState->Prepare, 0U);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, PipelineProfilePathUsesConfiguredCoordinator)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        auto BytePool = MakeConfiguredProbeBytePool();
        rec::Pipeline Pipeline(Profile, BytePool);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, BytePool);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::Configured);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 1U);
    }

TEST(ConfiguredModeTest, PreparedCandidateCommitIsOneShot)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        const auto Handle = Profile->FindCandidate(7);
        rec::PreparedCandidate Prepared(Handle, AcceptedPrepare(7));
        rec::CommitContext Context;
        Context.Inbound = Transport;
        rec::CommitResult First;
        rec::CommitResult Second;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    First = co_await Prepared.Commit(Context);
                    Second = co_await Prepared.Commit(Context);
                });

        EXPECT_EQ(First.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Second.Status, rec::RecognitionStatus::Polluted);
        EXPECT_TRUE(Second.Polluted);
        EXPECT_EQ(CallsState->Commit, 1U);
    }

TEST(ConfiguredModeTest, PollutedCommitAttemptCannotBeRetried)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::PreparedCandidate Prepared(Profile->FindCandidate(7), AcceptedPrepare(7));
        rec::CommitContext Polluted;
        Polluted.Inbound = Transport;
        Polluted.Polluted = true;
        rec::CommitContext Clean;
        Clean.Inbound = Transport;
        rec::CommitResult First;
        rec::CommitResult Second;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    First = co_await Prepared.Commit(Polluted);
                    Second = co_await Prepared.Commit(Clean);
                });

        EXPECT_EQ(First.Status, rec::RecognitionStatus::Polluted);
        EXPECT_EQ(Second.Status, rec::RecognitionStatus::Polluted);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, FailedCommitClosesConsumedCallbackTransportAndReturnsNoSuccessor)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Commit = AcceptedCommit(7);
        Commit.Status = rec::RecognitionStatus::IoError;
        CallsState->ConsumeCommitReplay = true;
        auto Decoy = std::make_shared<ScriptedTransport>(Io.get_executor());
        CallsState->ReturnedTransport = Decoy;
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), Commit});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_TRUE(CallsState->CommitCompleted);
    }

TEST(ConfiguredModeTest, SuccessfulEmptyCommitTransportDoesNotReplayAgain)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;
        CallsState->ReturnEmptyOnCommit = true;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_not_supported));
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
    }

TEST(ConfiguredModeTest, CommitReadsPrefixAndReturnsOnlyUnconsumedSuccessor)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "configured-successor";
        Candidate.Protocol = Prism::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &Snapshot)
        {
            if (Snapshot.Size() < 3)
            {
                return rec::MatchState::NeedMore;
            }
            return rec::MatchState::Structural;
        };
        Candidate.Prepare = [CallsState](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
        {
            ++CallsState->Prepare;
            co_return AcceptedPrepare(Context.Candidate);
        };
        Candidate.Commit = [CallsState](rec::CommitContext Context)
        { return CommitReadsPrefix(CallsState, std::move(Context)); };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Compiled.value());
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 2> Tail{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Read = co_await Result.transport->ReadSome(Tail);
                    EXPECT_FALSE(Read.Failure.Failed());
                    EXPECT_EQ(Read.Bytes, Tail.size());
                });
        EXPECT_EQ(Tail, (std::array<std::byte, 2>{std::byte{0x02}, std::byte{0x03}}));
    }
