/**
 * @file MixedTrialLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "MixedTrialModeTestSupport.hpp"

TEST(MixedTrialModeTest, FailedCommitAfterPartialReplayClosesConsumedSuccessor)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01, 0x02}));
        auto State = MakeState(1, true);
        State->ReadOnCommit = true;
        State->CommitStatus = rec::RecognitionStatus::IoError;
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
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
    }

TEST(MixedTrialModeTest, CommitSuccessReturnsResidualBytesExactlyOnce)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01, 0x02}));
        auto State = MakeState(1, true);
        State->ReadOnCommit = true;
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 2> Tail{};
        Prism::IoResult ReadResult{};
        std::array<std::byte, 1> Extra{};
        Prism::IoResult ExtraResult{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    ReadResult = co_await Result.transport->ReadExact(Tail);
                    ExtraResult = co_await Result.transport->ReadSome(Extra);
                    EXPECT_EQ(ReadResult.Bytes, Tail.size());
                });
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(Tail, (std::array<std::byte, 2>{std::byte{0x01}, std::byte{0x02}}));
        EXPECT_EQ(ExtraResult.Bytes, 0U);
        EXPECT_FALSE(ExtraResult.Failure.Failed());
    }

TEST(MixedTrialModeTest, ReusesStableWaitSourceAcrossReadPrepareAndCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1);
        auto Middle = MakeState(2);
        auto Winner = MakeState(3, true);
        auto Profile = MakeMixedProfile({First, Middle, Winner});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        auto WaitCompleted = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls, WaitCompleted]
        {
            return WaitForEventWithAck(
                {std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls, WaitCompleted});
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [] {};
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(*WaitCalls, 5U);
        EXPECT_TRUE(First->PrepareCompleted);
        EXPECT_TRUE(Middle->PrepareCompleted);
        EXPECT_TRUE(Winner->PrepareCompleted);
        EXPECT_TRUE(Winner->CommitCompleted);
        EXPECT_EQ(*WaitCompleted, *WaitCalls);
        Io.restart();
        EXPECT_EQ(Io.run(), 0U);
    }

TEST(MixedTrialModeTest, InFlightReadCancellationClosesTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->SetPending();
        auto State = MakeState(1, true);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{State}, 8, 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
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
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(*WaitCalls, 1U);
        EXPECT_TRUE(Transport->ReadCompleted());
    }

TEST(MixedTrialModeTest, ProfileDeadlineWinsOverLongPrepareWait)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto State = MakeState(1, true);
        State->PendingPrepare = true;
        State->Gate = Gate;
        // Keep the deadline short while leaving the prepare coroutine one scheduler turn
        // to start under the full Windows CTest suite.
        State->ProfileTimeout = std::chrono::milliseconds(50);
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate, Transport]
        {
            Gate->try_send(boost::system::error_code{});
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_FALSE(Result.Cancelled);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_EQ(State->Prepare, 1U);
        EXPECT_TRUE(State->PrepareCompleted);
        EXPECT_EQ(State->Commit, 0U);
        EXPECT_EQ(*WaitCalls, 2U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
    }

TEST(MixedTrialModeTest, ControlledCommitCleansIndependentSuccessorAndInboundExactlyOnce)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto State = MakeState(1, true);
        State->PendingCommit = true;
        State->Gate = Gate;
        State->ProfileTimeout = std::chrono::milliseconds(250);
        State->ReturnedTransport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate, Transport]
        {
            Gate->try_send(boost::system::error_code{});
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_FALSE(Result.Cancelled);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::timed_out));
        EXPECT_EQ(State->Commit, 1U);
        EXPECT_TRUE(State->CommitCompleted);
        EXPECT_EQ(*WaitCalls, 3U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        const auto Decoy = std::dynamic_pointer_cast<ScriptedTransport>(State->ReturnedTransport);
        ASSERT_NE(Decoy, nullptr);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_EQ(Result.transport, nullptr);
    }

TEST(MixedTrialModeTest, DirectOperationCancellationSetsCancelledForReadPrepareAndCommit)
    {
        const auto Canceled = std::make_error_code(std::errc::operation_canceled);

        Net::io_context ReadIo;
        auto ReadTransport = std::make_shared<ScriptedTransport>(ReadIo.get_executor());
        ReadTransport->Push({}, Canceled);
        auto ReadState = MakeState(1, true);
        auto ReadProfile = MakeMixedProfile({ReadState});
        rec::ProbeBuffer ReadBuffer(ReadProfile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode ReadMode(ReadProfile);
        rec::RecognizeResult ReadResult;
        RunCoro(ReadIo, [&]() -> Net::awaitable<void>
                {
                    ReadResult = co_await ReadMode.Recognize(ReadTransport, ReadBuffer);
                });
        EXPECT_EQ(ReadResult.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(ReadResult.Cancelled);
        EXPECT_EQ(ReadState->Prepare, 0U);

        Net::io_context PrepareIo;
        auto PrepareTransport = std::make_shared<ScriptedTransport>(PrepareIo.get_executor());
        PrepareTransport->Push(Bytes({0xB2, 0x01}));
        auto PrepareState = MakeState(1, true);
        PrepareState->PrepareStatus = rec::RecognitionStatus::NoMatch;
        PrepareState->PrepareError = Canceled;
        auto PrepareProfile = MakeMixedProfile({PrepareState});
        rec::ProbeBuffer PrepareBuffer(PrepareProfile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode PrepareMode(PrepareProfile);
        rec::RecognizeResult PrepareResult;
        RunCoro(PrepareIo, [&]() -> Net::awaitable<void>
                {
                    PrepareResult = co_await PrepareMode.Recognize(PrepareTransport, PrepareBuffer);
                });
        EXPECT_EQ(PrepareResult.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(PrepareResult.Cancelled);
        EXPECT_EQ(PrepareState->Commit, 0U);

        PrepareIo.restart();
        PrepareTransport = std::make_shared<ScriptedTransport>(PrepareIo.get_executor());
        PrepareTransport->Push(Bytes({0xB2, 0x01}));
        PrepareState = MakeState(1, true);
        PrepareState->PrepareStatus = rec::RecognitionStatus::Accepted;
        PrepareState->PrepareError = Canceled;
        PrepareProfile = MakeMixedProfile({PrepareState});
        PrepareBuffer = rec::ProbeBuffer(
            PrepareProfile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        PrepareMode = rec::MixedTrialMode(PrepareProfile);
        PrepareResult = {};
        RunCoro(PrepareIo, [&]() -> Net::awaitable<void>
                {
                    PrepareResult = co_await PrepareMode.Recognize(PrepareTransport, PrepareBuffer);
                });
        EXPECT_EQ(PrepareResult.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(PrepareResult.Cancelled);
        EXPECT_EQ(PrepareState->Commit, 0U);

        Net::io_context CommitIo;
        auto CommitTransport = std::make_shared<ScriptedTransport>(CommitIo.get_executor());
        CommitTransport->Push(Bytes({0xB2, 0x01}));
        auto CommitState = MakeState(1, true);
        CommitState->CommitStatus = rec::RecognitionStatus::NoMatch;
        CommitState->CommitError = Canceled;
        auto CommitProfile = MakeMixedProfile({CommitState});
        rec::ProbeBuffer CommitBuffer(CommitProfile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode CommitMode(CommitProfile);
        rec::RecognizeResult CommitResult;
        RunCoro(CommitIo, [&]() -> Net::awaitable<void>
                {
                    CommitResult = co_await CommitMode.Recognize(CommitTransport, CommitBuffer);
                });
        EXPECT_EQ(CommitResult.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(CommitResult.Cancelled);
        EXPECT_EQ(CommitState->Commit, 1U);
        EXPECT_EQ(CommitResult.transport, nullptr);

        CommitIo.restart();
        CommitTransport = std::make_shared<ScriptedTransport>(CommitIo.get_executor());
        CommitTransport->Push(Bytes({0xB2, 0x01}));
        CommitState = MakeState(1, true);
        CommitState->CommitStatus = rec::RecognitionStatus::Accepted;
        CommitState->CommitError = Canceled;
        CommitProfile = MakeMixedProfile({CommitState});
        CommitBuffer = rec::ProbeBuffer(
            CommitProfile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        CommitMode = rec::MixedTrialMode(CommitProfile);
        CommitResult = {};
        RunCoro(CommitIo, [&]() -> Net::awaitable<void>
                {
                    CommitResult = co_await CommitMode.Recognize(CommitTransport, CommitBuffer);
                });
        EXPECT_EQ(CommitResult.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(CommitResult.Cancelled);
        EXPECT_EQ(CommitState->Commit, 1U);
        EXPECT_EQ(CommitResult.transport, nullptr);
    }

TEST(MixedTrialModeTest, ReturnsEofAndCancellationAsExplicitTerminalResults)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2}));
        Transport->Push({});
        auto State = MakeState(1, true);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{State}, 8, 4});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Eof;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Eof = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_EQ(Eof.Status, rec::RecognitionStatus::EndOfStream);
        EXPECT_EQ(State->Prepare, 0U);

        Io.restart();
        auto CanceledTransport = std::make_shared<ScriptedTransport>(Io.get_executor());
        CanceledTransport->Push(Bytes({0xB2, 0x01}));
        rec::ProbeBuffer CanceledBuffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::RecognitionControl Control;
        Control.Cancelled = [] { return true; };
        rec::RecognizeResult Canceled;
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Canceled = co_await Mode.Recognize(CanceledTransport, CanceledBuffer, Control);
                });
        EXPECT_EQ(Canceled.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Canceled.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_TRUE(CanceledTransport->ReadRequests().empty());
    }

TEST(MixedTrialModeTest, PipelineProfilePathUsesMixedCoordinator)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2);
        auto Profile = MakeMixedProfile({Winner, Loser});
        auto BytePool = MakeMixedTrialProbeBytePool();
        rec::Pipeline Pipeline(Profile, BytePool);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, BytePool);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::MixedTrial);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Loser->Commit, 0U);
    }

TEST(MixedTrialModeTest, PipelineProfilePathUsesDeterministicCoordinator)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Winner = MakeState(1, true);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner}, 8, 2, {}, 32,
            rec::InvalidCandidate, rec::RecognitionMode::Deterministic});
        auto BytePool = MakeMixedTrialProbeBytePool();
        rec::Pipeline Pipeline(Profile, BytePool);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, BytePool);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::Deterministic);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Result.CryptoTrials, 1U);
    }

TEST(MixedTrialModeTest, StructuralWinnerDoesNotWaitForOpaqueFallback)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Winner = MakeState(4, true);
        auto OpaqueFallback = MakeState(5, true);
        OpaqueFallback->Fallback = true;
        OpaqueFallback->InspectMinimum = 60;
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner, OpaqueFallback}, 8, 2, {}, 64});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(OpaqueFallback->Prepare, 0U);
    }

TEST(MixedTrialModeTest, StructuralAuthFailureFallsThroughToOpaqueCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        Transport->Push(std::vector<std::byte>(58, std::byte{0xA5}));
        auto Structural = MakeState(6);
        auto OpaqueFallback = MakeState(7, true);
        OpaqueFallback->Fallback = true;
        OpaqueFallback->InspectMinimum = 60;
        OpaqueFallback->CandidateMinimum = 60;
        OpaqueFallback->PrepareMinimum = 60;
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Structural, OpaqueFallback}, 8, 2, {}, 64});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, OpaqueFallback->Id);
        EXPECT_EQ(Structural->Prepare, 1U);
        EXPECT_EQ(OpaqueFallback->Prepare, 1U);
        ASSERT_EQ(Transport->ReadRequests().size(), 2U);
        EXPECT_EQ(Transport->ReadRequests()[0], 2U);
        EXPECT_EQ(Transport->ReadRequests()[1], 58U);
    }

TEST(MixedTrialModeTest, StructuralAuthFailurePreservesOpaqueEofTerminalStatus)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        Transport->Push({});
        auto Structural = MakeState(6);
        auto OpaqueFallback = MakeState(7, true);
        OpaqueFallback->Fallback = true;
        OpaqueFallback->InspectMinimum = 60;
        OpaqueFallback->CandidateMinimum = 60;
        OpaqueFallback->PrepareMinimum = 60;
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Structural, OpaqueFallback}, 8, 2, {}, 64});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::EndOfStream);
        EXPECT_EQ(Structural->Prepare, 1U);
        EXPECT_EQ(OpaqueFallback->Prepare, 0U);
    }

TEST(MixedTrialModeTest, RestrictsTrialsToCandidateSelectedBySniRoute)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("winner.example");
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2, true);
        Winner->Fallback = true;
        Loser->Fallback = true;
        Winner->Protocol = Prism::Contract::ProtocolType::Tls;
        Loser->Protocol = Prism::Contract::ProtocolType::Tls;
        Winner->Kind = rec::CandidateKind::TlsCarrier;
        Loser->Kind = rec::CandidateKind::TlsCarrier;
        std::vector<rec::RouteBinding> Routes;
        Routes.emplace_back("winner.example", Winner->Id);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner, Loser}, 8, 2, std::move(Routes), 128});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Inspect, 1U);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Loser->Inspect, 1U);
        EXPECT_EQ(Loser->Prepare, 0U);
        EXPECT_EQ(Loser->Commit, 0U);
    }

TEST(MixedTrialModeTest, KeepsTlsFallbackWhenSniRouteDoesNotMatch)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("unknown.example");
        auto Winner = MakeState(1, true);
        auto Routed = MakeState(2, true);
        Winner->Fallback = true;
        Routed->Fallback = true;
        Routed->Structural = false;
        Winner->Protocol = Prism::Contract::ProtocolType::Tls;
        Routed->Protocol = Prism::Contract::ProtocolType::Tls;
        Winner->Kind = rec::CandidateKind::TlsCarrier;
        Routed->Kind = rec::CandidateKind::TlsCarrier;
        std::vector<rec::RouteBinding> Routes;
        Routes.emplace_back("known.example", Routed->Id);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner, Routed}, 8, 2, std::move(Routes), 128});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Routed->Prepare, 0U);
        EXPECT_EQ(Routed->Commit, 0U);
    }

TEST(MixedTrialModeTest, DoesNotApplyTlsRouteToCleartextPrefix)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x47, 0x45}));

        auto Http = MakeState(1, true);
        Http->Protocol = Prism::Contract::ProtocolType::Http;
        Http->FirstByte = 0x47;
        Http->Structural = true;

        auto Tls = MakeState(2, true);
        Tls->Protocol = Prism::Contract::ProtocolType::Tls;
        Tls->Kind = rec::CandidateKind::TlsCarrier;
        Tls->Fallback = true;
        Tls->Structural = true;

        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Http, Tls}, 8, 2,
            {rec::RouteBinding{"edge.example", Tls->Id}}});
        auto Storage = std::make_shared<const std::vector<std::byte>>(Bytes({0x47, 0x45}));
        const auto Route = rec::detail::ResolveSniRoute(*Profile, rec::ProbeSnapshot{Storage});
        EXPECT_FALSE(Route.Applicable);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, Http->Id);
        EXPECT_EQ(Http->Commit, 1U);
        EXPECT_EQ(Tls->Prepare, 0U);
    }

TEST(MixedTrialModeTest, UsesExplicitDefaultCandidateForMissingSni)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("unknown.example");
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2, true);
        Winner->Fallback = true;
        Loser->Fallback = true;
        Winner->Protocol = Prism::Contract::ProtocolType::Tls;
        Loser->Protocol = Prism::Contract::ProtocolType::Tls;
        Winner->Kind = rec::CandidateKind::TlsCarrier;
        Loser->Kind = rec::CandidateKind::TlsCarrier;
        std::vector<rec::RouteBinding> Routes;
        Routes.emplace_back("known.example", Loser->Id);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner, Loser}, 8, 2, std::move(Routes), 128,
            Winner->Id});
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Loser->Prepare, 0U);
        EXPECT_EQ(Loser->Commit, 0U);
    }

TEST(MixedTrialModeTest, UsesTlsScannerBoundaryInsteadOfByteAtATimeReads)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Prism::Testing::RecognitionWire::MakeTlsClientHello("edge.example"));

        auto Binding = Prism::Composition::Recognition::TlsCandidateFactory::Make(
            Prism::Composition::Recognition::TlsCandidateOptions{31, "native", "native", {"edge.example"}, {}},
            [](Prism::Recognition::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxProbeBytes = 4096;
        Spec.Candidates.push_back(std::move(Binding.Spec));
        Spec.Routes.emplace_back("edge.example", 31);
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        rec::ProbeBuffer Buffer((*Compiled)->Budget().MaxProbeBytes, MakeMixedTrialProbeBytePool());
        rec::RecognizeResult Result;
        rec::MixedTrialMode Mode(*Compiled);
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                    if (Result.transport)
                    {
                        Result.transport->Close();
                    }
                });

        ASSERT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, 31U);
        ASSERT_GT(Transport->ReadRequests().size(), 1U);
        const auto HasLargerFollowup = std::any_of(
            Transport->ReadRequests().begin() + 1, Transport->ReadRequests().end(),
            [](const auto RequestSize) { return RequestSize > 1U; });
        EXPECT_TRUE(HasLargerFollowup);
    }

