/**
 * @file MixedTrialAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "MixedTrialModeTestSupport.hpp"

TEST(MixedTrialModeTest, ChoosesAuthenticatedWinnerInPriorityOrder)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1);
        auto Winner = MakeState(2, true);
        auto Last = MakeState(3);
        auto Profile = MakeMixedProfile({First, Winner, Last});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(First->Prepare, 1U);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Last->Prepare, 1U);
        EXPECT_EQ(First->Commit, 0U);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Last->Commit, 0U);
        EXPECT_EQ(Transport->Writes(), 0U);
        EXPECT_EQ(Transport->Closes(), 0U);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 2> Replay{};
        std::error_code Error;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Count = co_await Result.transport->async_read_some(Replay, Error);
                    EXPECT_EQ(Count, Replay.size());
                });
        EXPECT_FALSE(Error);
        EXPECT_EQ(Replay, (std::array<std::byte, 2>{std::byte{0xB2}, std::byte{0x01}}));
    }

TEST(MixedTrialModeTest, AcceptsFirstPriorityWinner)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2);
        auto Profile = MakeMixedProfile({Winner, Loser});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Loser->Commit, 0U);
    }

TEST(MixedTrialModeTest, AcceptsLastPriorityWinner)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Loser = MakeState(1);
        auto Winner = MakeState(2, true);
        auto Profile = MakeMixedProfile({Loser, Winner});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, Winner->Id);
        EXPECT_EQ(Loser->Prepare, 1U);
        EXPECT_EQ(Winner->Prepare, 1U);
        EXPECT_EQ(Loser->Commit, 0U);
        EXPECT_EQ(Winner->Commit, 1U);
    }

TEST(MixedTrialModeTest, ReturnsNoMatchAfterAllCandidatesReject)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1);
        auto Second = MakeState(2);
        auto Profile = MakeMixedProfile({First, Second});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::NoMatch);
        EXPECT_EQ(First->Prepare, 1U);
        EXPECT_EQ(Second->Prepare, 1U);
        EXPECT_EQ(First->Commit, 0U);
        EXPECT_EQ(Second->Commit, 0U);
    }

TEST(MixedTrialModeTest, RejectsMultipleAuthenticatedCandidatesAsAmbiguous)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1, true);
        auto Second = MakeState(2, true);
        First->Priority = 10;
        Second->Priority = 10;
        auto Profile = MakeMixedProfile({First, Second});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Ambiguous);
        EXPECT_EQ(First->Prepare, 1U);
        EXPECT_EQ(Second->Prepare, 1U);
        EXPECT_EQ(First->Commit, 0U);
        EXPECT_EQ(Second->Commit, 0U);
        EXPECT_EQ(Transport->Writes(), 0U);
        EXPECT_EQ(Transport->Closes(), 0U);
    }

TEST(MixedTrialModeTest, SelectsUniqueHighestPriorityPreparedCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto LowerPriority = MakeState(1, true);
        auto HigherPriority = MakeState(2, true);
        LowerPriority->Priority = 10;
        HigherPriority->Priority = 20;
        HigherPriority->Protocol = Preview::Contract::ProtocolType::Socks5;
        auto Profile = MakeMixedProfile({LowerPriority, HigherPriority});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, HigherPriority->Id);
        EXPECT_EQ(Result.detected, Preview::Contract::ProtocolType::Socks5);
        EXPECT_EQ(LowerPriority->Prepare, 1U);
        EXPECT_EQ(HigherPriority->Prepare, 1U);
        EXPECT_EQ(LowerPriority->Commit, 0U);
        EXPECT_EQ(HigherPriority->Commit, 1U);
    }

TEST(MixedTrialModeTest, DeterministicRouteRejectsAmbiguityAtProfileCompile)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1, true);
        auto Second = MakeState(2, true);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{First, Second}, 8, 2, {}, 32,
            rec::InvalidCandidate, rec::RecognitionMode::Deterministic, false});
        EXPECT_EQ(Profile, nullptr);
        EXPECT_EQ(First->Prepare, 0U);
        EXPECT_EQ(Second->Prepare, 0U);
    }

TEST(MixedTrialModeTest, DeterministicRouteAuthenticatesOnlyTheIndexedCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x01}));
        auto Winner = MakeState(1, true);
        Winner->FirstByte = 0xA1;
        auto Other = MakeState(2, true);
        Other->FirstByte = 0xA2;
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Winner, Other}, 8, 2, {}, 32,
            rec::InvalidCandidate, rec::RecognitionMode::Deterministic});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        EXPECT_EQ(Other->Prepare, 0U);
        EXPECT_EQ(Other->Commit, 0U);
    }

TEST(MixedTrialModeTest, RequestsOnlyTheSmallestInitialBoundary)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01, 0x02, 0x03, 0x04}));
        auto Short = MakeState(1, true);
        auto Long = MakeState(2);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{Short, Long}, 8, 2});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        ASSERT_FALSE(Transport->ReadRequests().empty());
        EXPECT_EQ(Transport->ReadRequests().front(), 2U);
        EXPECT_TRUE(Result.success);
    }

TEST(MixedTrialModeTest, StopsAtCryptoTrialBudgetBeforeTryingAnotherCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1);
        auto Second = MakeState(2, true);
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{First, Second}, 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_EQ(Result.Status, rec::RecognitionStatus::BudgetExceeded);
        EXPECT_EQ(Result.CryptoTrials, 1U);
        EXPECT_EQ(First->Prepare, 1U);
        EXPECT_EQ(Second->Prepare, 0U);
        EXPECT_EQ(First->Commit, 0U);
    }

TEST(MixedTrialModeTest, PollutedCandidateTerminatesWithoutCommitOrLoserTrial)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Polluted = MakeState(1);
        Polluted->Polluted = true;
        Polluted->PrepareStatus = rec::RecognitionStatus::NoMatch;
        auto Loser = MakeState(2);
        auto Profile = MakeMixedProfile({Polluted, Loser});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Polluted);
        EXPECT_TRUE(Result.Polluted);
        EXPECT_EQ(Polluted->Prepare, 1U);
        EXPECT_EQ(Loser->Prepare, 0U);
        EXPECT_EQ(Polluted->Commit, 0U);
        EXPECT_EQ(Transport->Writes(), 0U);
        EXPECT_EQ(Transport->Closes(), 0U);
    }

TEST(MixedTrialModeTest, CommitFailureDoesNotRetryAnotherAuthenticatedCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2);
        Winner->CommitStatus = rec::RecognitionStatus::IoError;
        Winner->CommitError = std::make_error_code(std::errc::connection_reset);
        auto Profile = MakeMixedProfile({Winner, Loser});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Winner->Commit, 1U);
        EXPECT_EQ(Loser->Commit, 0U);
    }

TEST(MixedTrialModeTest, NeedMoreReadsTheNextSmallestBoundary)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2}));
        Transport->Push(Bytes({0x01}));
        auto State = MakeState(1, true);
        State->InspectMinimum = 2;
        auto Profile = MakeMixedProfile(MixedProfileOptions{
            std::vector<std::shared_ptr<CandidateState>>{State}, 8, 1});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_EQ(Transport->ReadRequests().size(), 2U);
        EXPECT_EQ(Transport->ReadRequests()[0], 1U);
        EXPECT_EQ(Transport->ReadRequests()[1], 1U);
        EXPECT_EQ(State->Inspect, 2U);
        EXPECT_EQ(State->Prepare, 1U);
    }

TEST(MixedTrialModeTest, WrongFirstByteRejectsIndexedCandidates)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xC2, 0x01}));
        auto State = MakeState(1, true);
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::NoMatch);
        EXPECT_EQ(State->Inspect, 0U);
        EXPECT_EQ(State->Prepare, 0U);
    }

TEST(MixedTrialModeTest, FallbackCandidateCanMatchAnUnindexedFirstByte)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xC2, 0x01}));
        auto State = MakeState(1, true);
        State->Fallback = true;
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, State->Id);
        EXPECT_EQ(State->Inspect, 1U);
        EXPECT_EQ(State->Prepare, 1U);
    }

TEST(MixedTrialModeTest, FailedCommitClosesCallbackTransportAndReturnsNoSuccessor)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto State = MakeState(1, true);
        State->CommitStatus = rec::RecognitionStatus::IoError;
        State->ReturnedTransport = std::make_shared<ScriptedTransport>(Io.get_executor());
        State->CloseReturnedTransportBeforeReturn = true;
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.transport, nullptr);
        const auto Decoy = std::dynamic_pointer_cast<ScriptedTransport>(State->ReturnedTransport);
        ASSERT_NE(Decoy, nullptr);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
    }

TEST(MixedTrialModeTest, PollutedCommitReturnsSafeReplay)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto State = MakeState(1, true);
        State->CommitStatus = rec::RecognitionStatus::Polluted;
        State->ReturnedTransport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Polluted);
        EXPECT_TRUE(Result.Polluted);
        EXPECT_EQ(Result.transport, nullptr);
        const auto Decoy = std::dynamic_pointer_cast<ScriptedTransport>(State->ReturnedTransport);
        ASSERT_NE(Decoy, nullptr);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
    }

TEST(MixedTrialModeTest, SuccessfulEmptyCommitDoesNotReplayConsumedInput)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto State = MakeState(1, true);
        State->ReturnEmptyOnCommit = true;
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_not_supported));
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_EQ(Result.preread.size(), 2U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
    }

