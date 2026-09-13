/**
 * @file MixedTrialModeTest.cpp
 * @brief MixedTrial 识别协调器测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Runtime/Recognition/MixedTrialMode.hpp>
#include <preview/Runtime/Recognition/Profile.hpp>
#include <preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <preview/Runtime/Recognition/Protocol.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include "RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace rec = Preview::Recognition;

    struct ReadStep
    {
        std::vector<std::byte> Data;
        std::error_code Error{};
    };

    class ScriptedTransport final : public Preview::Transmission
    {
    public:
        explicit ScriptedTransport(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}

        auto SetPending() -> void
        {
            Pending_ = true;
        }

        auto Push(std::vector<std::byte> Data, std::error_code Error = {}) -> void
        {
            Steps_.push_back(ReadStep{std::move(Data), Error});
        }

        auto ReadRequests() const -> const std::vector<std::size_t> &
        {
            return ReadRequests_;
        }

        auto Writes() const noexcept -> std::size_t
        {
            return Writes_;
        }

        auto Closes() const noexcept -> std::size_t
        {
            return Closes_;
        }

        auto Cancels() const noexcept -> std::size_t
        {
            return Cancels_;
        }

        auto ReadCompleted() const noexcept -> bool
        {
            return ReadCompleted_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ReadRequests_.push_back(Buffer.size());
            Error.clear();
            if (Pending_)
            {
                co_await ReadWake_.async_receive(Net::use_awaitable);
                ReadCompleted_ = true;
                if (Canceled_)
                {
                    Error = std::make_error_code(std::errc::operation_canceled);
                    co_return 0;
                }
            }
            if (Steps_.empty())
            {
                co_return 0;
            }
            auto &Step = Steps_.front();
            const auto Count = (std::min)(Buffer.size(), Step.Data.size());
            std::copy_n(Step.Data.begin(), static_cast<std::ptrdiff_t>(Count), Buffer.begin());
            Step.Data.erase(Step.Data.begin(), Step.Data.begin() + static_cast<std::ptrdiff_t>(Count));
            Error = Step.Error;
            if (Step.Data.empty())
            {
                Steps_.pop_front();
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ++Writes_;
            Error.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            ++Closes_;
            ReadWake_.try_send(boost::system::error_code{});
        }

        auto Cancel() -> void override
        {
            ++Cancels_;
            Canceled_ = true;
            ReadWake_.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Closes_ == 0;
        }

    private:
        Net::any_io_executor Executor_;
        boost::asio::experimental::channel<void(boost::system::error_code)> ReadWake_{Executor_, 1};
        std::deque<ReadStep> Steps_;
        std::vector<std::size_t> ReadRequests_;
        std::size_t Writes_{0};
        std::size_t Closes_{0};
        std::size_t Cancels_{0};
        bool Pending_{false};
        bool Canceled_{false};
        bool ReadCompleted_{false};
    };

    struct CandidateState
    {
        rec::CandidateId Id{rec::InvalidCandidate};
        std::size_t Inspect{0};
        std::size_t Prepare{0};
        std::size_t Commit{0};
        bool Structural{true};
        bool Authenticated{false};
        bool Polluted{false};
        bool Fallback{false};
        bool ReadOnCommit{false};
        bool ReturnEmptyOnCommit{false};
        bool CloseReturnedTransportBeforeReturn{false};
        Preview::SharedTransmission ReturnedTransport{};
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> Gate{};
        bool PendingPrepare{false};
        bool PendingCommit{false};
        std::size_t InspectMinimum{0};
        bool PrepareCompleted{false};
        bool CommitCompleted{false};
        std::chrono::milliseconds ProfileTimeout{250};
        rec::RecognitionStatus PrepareStatus{rec::RecognitionStatus::NoMatch};
        std::error_code PrepareError{};
        rec::RecognitionStatus CommitStatus{rec::RecognitionStatus::Accepted};
        std::error_code CommitError{};
        rec::ProtocolType Protocol{rec::ProtocolType::Vless};
        rec::CandidateKind Kind{rec::CandidateKind::Opaque};
        std::optional<std::uint8_t> FirstByte{};
    };

    auto Bytes(std::initializer_list<std::uint8_t> Values) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Values.size());
        for (const auto Value : Values)
        {
            Result.push_back(static_cast<std::byte>(Value));
        }
        return Result;
    }

    auto WaitForEvent(std::chrono::milliseconds Delay, rec::RecognitionControlEvent Event,
                      const std::shared_ptr<std::size_t> &Calls)
        -> Net::awaitable<rec::RecognitionControlEvent>
    {
        ++*Calls;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Delay);
        co_await Timer.async_wait(Net::use_awaitable);
        co_return Event;
    }

    struct WaitSourceRequest
    {
        std::chrono::milliseconds Delay;
        rec::RecognitionControlEvent Event;
        std::shared_ptr<std::size_t> Calls;
        std::shared_ptr<std::size_t> Completed;
    };

    auto WaitForEventWithAck(WaitSourceRequest Request) -> Net::awaitable<rec::RecognitionControlEvent>
    {
        ++*Request.Calls;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Request.Delay);
        try
        {
            co_await Timer.async_wait(Net::use_awaitable);
        }
        catch (...)
        {
            ++*Request.Completed;
            throw;
        }
        ++*Request.Completed;
        co_return Request.Event;
    }

    auto MakeMixedProfile(std::vector<std::shared_ptr<CandidateState>> States,
                          std::uint16_t MaxCryptoTrials = 8,
                          std::size_t MinimumBytes = 2,
                          std::vector<rec::RouteBinding> Routes = {},
                          std::size_t MaxProbeBytes = 32,
                          rec::CandidateId DefaultCandidate = rec::InvalidCandidate,
                          rec::RecognitionMode Mode = rec::RecognitionMode::MixedTrial,
                          bool ExpectCompile = true) -> rec::SharedProfile
    {
        rec::ProfileSpec Spec;
        Spec.Mode = Mode;
        Spec.Budget.MaxProbeBytes = MaxProbeBytes;
        Spec.Budget.MaxCandidates = 16;
        Spec.Budget.MaxCryptoTrials = MaxCryptoTrials;
        Spec.Budget.Timeout = std::chrono::milliseconds(250);
        if (!States.empty())
        {
            Spec.Budget.Timeout = States.front()->ProfileTimeout;
        }
        Spec.DefaultCandidate = DefaultCandidate;
        Spec.Routes = std::move(Routes);
        for (const auto &State : States)
        {
            rec::CandidateSpec Candidate;
            Candidate.Id = State->Id;
            Candidate.Name = "candidate-" + std::to_string(State->Id);
            Candidate.Protocol = State->Protocol;
            Candidate.Kind = State->Kind;
            if (State->Kind == rec::CandidateKind::TlsCarrier)
            {
                Candidate.Scheme = "native";
            }
            Candidate.RequiresAuthentication = true;
            Candidate.Priority = State->Id;
            if (!State->Fallback)
            {
                Candidate.FirstBytes = {State->FirstByte.value_or(0xB2)};
            }
            Candidate.Fallback = State->Fallback;
            Candidate.MinimumBytes = MinimumBytes;
            Candidate.Inspect = [State, MinimumBytes](const rec::ProbeSnapshot &Snapshot)
            {
                ++State->Inspect;
                if (State->Kind == rec::CandidateKind::TlsCarrier)
                {
                    const auto Data = Snapshot.Data();
                    if (Data.empty() || std::to_integer<std::uint8_t>(Data.front()) != 0x16)
                    {
                        return rec::MatchState::Rejected;
                    }
                }
                auto Required = State->InspectMinimum;
                if (Required == 0)
                {
                    Required = MinimumBytes;
                }
                if (Snapshot.Size() < Required)
                {
                    return rec::MatchState::NeedMore;
                }
                if (State->Structural)
                {
                    return rec::MatchState::Structural;
                }
                return rec::MatchState::Rejected;
            };
            Candidate.Prepare = [State](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
            {
                ++State->Prepare;
                if (State->PendingPrepare && State->Gate)
                {
                    co_await State->Gate->async_receive(Net::use_awaitable);
                }
                rec::PrepareResult Result;
                Result.Candidate = Context.Candidate;
                Result.Status = State->PrepareStatus;
                Result.Error = State->PrepareError;
                Result.Polluted = State->Polluted;
                State->PrepareCompleted = true;
                co_return Result;
            };
            Candidate.Commit = [State](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
            {
                ++State->Commit;
                rec::CommitResult Result;
                Result.Candidate = Context.Candidate;
                Result.Status = State->CommitStatus;
                Result.Error = State->CommitError;
                if (State->PendingCommit && State->Gate)
                {
                    co_await State->Gate->async_receive(Net::use_awaitable);
                }
                State->CommitCompleted = true;
                if (State->ReadOnCommit && Context.Inbound)
                {
                    std::array<std::byte, 1> Prefix{};
                    std::error_code Error;
                    (void)co_await Context.Inbound->async_read_some(Prefix, Error);
                }
                if (State->ReturnEmptyOnCommit)
                {
                    Result.Transport.reset();
                }
                else if (State->ReturnedTransport)
                {
                    Result.Transport = State->ReturnedTransport;
                }
                else
                {
                    Result.Transport = std::move(Context.Inbound);
                }
                if (State->CloseReturnedTransportBeforeReturn && Result.Transport)
                {
                    Result.Transport->Cancel();
                    Result.Transport->Close();
                }
                co_return Result;
            };
            Spec.Candidates.push_back(std::move(Candidate));
        }
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        if (ExpectCompile)
        {
            EXPECT_TRUE(Compiled.has_value());
        }
        if (!Compiled)
        {
            return rec::SharedProfile{};
        }
        return Compiled.value();
    }

    template <typename Factory>
    auto RunCoro(Net::io_context &Io, Factory FactoryFn) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, FactoryFn(), [&](std::exception_ptr Error)
                      {
                          Failure = Error;
                          Io.stop();
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto MakeState(rec::CandidateId Id, bool Authenticated = false) -> std::shared_ptr<CandidateState>
    {
        auto State = std::make_shared<CandidateState>();
        State->Id = Id;
        State->Authenticated = Authenticated;
        State->PrepareStatus = rec::RecognitionStatus::NoMatch;
        if (Authenticated)
        {
            State->PrepareStatus = rec::RecognitionStatus::Accepted;
        }
        return State;
    }

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

    TEST(MixedTrialModeTest, DeterministicRouteRejectsAmbiguityAtProfileCompile)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01}));
        auto First = MakeState(1, true);
        auto Second = MakeState(2, true);
        auto Profile = MakeMixedProfile({First, Second}, 8, 2, {}, 32,
                                        rec::InvalidCandidate, rec::RecognitionMode::DeterministicRoute, false);
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
        auto Profile = MakeMixedProfile({Winner, Other}, 8, 2, {}, 32,
                                        rec::InvalidCandidate, rec::RecognitionMode::DeterministicRoute);
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
        auto Profile = MakeMixedProfile({Short, Long}, 8, 2);
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
        auto Profile = MakeMixedProfile({First, Second}, 1);
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
        auto Profile = MakeMixedProfile({State}, 8, 1);
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

    TEST(MixedTrialModeTest, FailedCommitAfterPartialReplayClosesConsumedSuccessor)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xB2, 0x01, 0x02}));
        auto State = MakeState(1, true);
        State->ReadOnCommit = true;
        State->CommitStatus = rec::RecognitionStatus::IoError;
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::MixedTrialMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 2> Tail{};
        std::error_code Error;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Count = co_await Result.transport->AsyncRead(Tail, Error);
                    EXPECT_EQ(Count, Tail.size());
                });
        EXPECT_FALSE(Error);
        EXPECT_EQ(Tail, (std::array<std::byte, 2>{std::byte{0x01}, std::byte{0x02}}));
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        auto Profile = MakeMixedProfile({State}, 8, 1);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        State->ProfileTimeout = std::chrono::milliseconds(1);
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        State->ProfileTimeout = std::chrono::milliseconds(1);
        State->ReturnedTransport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto Profile = MakeMixedProfile({State});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer ReadBuffer(ReadProfile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer PrepareBuffer(PrepareProfile->Budget().MaxProbeBytes);
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
        PrepareBuffer = rec::ProbeBuffer(PrepareProfile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer CommitBuffer(CommitProfile->Budget().MaxProbeBytes);
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
        CommitBuffer = rec::ProbeBuffer(CommitProfile->Budget().MaxProbeBytes);
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
        auto Profile = MakeMixedProfile({State}, 8, 4);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer CanceledBuffer(Profile->Budget().MaxProbeBytes);
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
        rec::Pipeline Pipeline(Profile);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        auto Profile = MakeMixedProfile({Winner}, 8, 2, {}, 32,
                                        rec::InvalidCandidate, rec::RecognitionMode::DeterministicRoute);
        rec::Pipeline Pipeline(Profile);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Mode, rec::RecognitionMode::DeterministicRoute);
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
        auto Profile = MakeMixedProfile({Winner, OpaqueFallback}, 8, 2, {}, 64);
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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

    TEST(MixedTrialModeTest, RestrictsTrialsToCandidateSelectedBySniRoute)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Preview::Testing::RecognitionWire::MakeTlsClientHello("winner.example");
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2, true);
        Winner->Fallback = true;
        Loser->Fallback = true;
        Winner->Protocol = rec::ProtocolType::Tls;
        Loser->Protocol = rec::ProtocolType::Tls;
        Winner->Kind = rec::CandidateKind::TlsCarrier;
        Loser->Kind = rec::CandidateKind::TlsCarrier;
        std::vector<rec::RouteBinding> Routes;
        Routes.emplace_back("winner.example", Winner->Id);
        auto Profile = MakeMixedProfile({Winner, Loser}, 8, 2, std::move(Routes), 128);
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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

    TEST(MixedTrialModeTest, DoesNotApplyTlsRouteToCleartextPrefix)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x47, 0x45}));

        auto Http = MakeState(1, true);
        Http->Protocol = rec::ProtocolType::Http;
        Http->FirstByte = 0x47;
        Http->Structural = true;

        auto Tls = MakeState(2, true);
        Tls->Protocol = rec::ProtocolType::Tls;
        Tls->Kind = rec::CandidateKind::TlsCarrier;
        Tls->Fallback = true;
        Tls->Structural = true;

        auto Profile = MakeMixedProfile({Http, Tls}, 8, 2,
                                        {rec::RouteBinding{"edge.example", Tls->Id}});
        auto Storage = std::make_shared<const std::vector<std::byte>>(Bytes({0x47, 0x45}));
        const auto Route = rec::detail::ResolveSniRoute(*Profile, rec::ProbeSnapshot{Storage});
        EXPECT_FALSE(Route.Applicable);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        const auto Wire = Preview::Testing::RecognitionWire::MakeTlsClientHello("unknown.example");
        auto Winner = MakeState(1, true);
        auto Loser = MakeState(2, true);
        Winner->Fallback = true;
        Loser->Fallback = true;
        Winner->Protocol = rec::ProtocolType::Tls;
        Loser->Protocol = rec::ProtocolType::Tls;
        Winner->Kind = rec::CandidateKind::TlsCarrier;
        Loser->Kind = rec::CandidateKind::TlsCarrier;
        std::vector<rec::RouteBinding> Routes;
        Routes.emplace_back("known.example", Loser->Id);
        auto Profile = MakeMixedProfile({Winner, Loser}, 8, 2, std::move(Routes), 128, Winner->Id);
        ASSERT_NE(Profile, nullptr);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        Transport->Push(Preview::Testing::RecognitionWire::MakeTlsClientHello("edge.example"));

        auto Binding = Preview::Composition::Recognition::TlsCandidateFactory::Make(
            Preview::Composition::Recognition::TlsCandidateOptions{31, "native", "native", {"edge.example"}, {}},
            [](Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::SharedTransmission>
            {
                co_return Inbound;
            });
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::MixedTrial;
        Spec.Budget.MaxProbeBytes = 4096;
        Spec.Candidates.push_back(std::move(Binding.Spec));
        Spec.Routes.emplace_back("edge.example", 31);
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        rec::ProbeBuffer Buffer((*Compiled)->Budget().MaxProbeBytes);
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

} // namespace
