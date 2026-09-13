/**
 * @file ConfiguredModeTest.cpp
 * @brief Configured 识别协调器测试
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
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Runtime/Recognition/ConfiguredMode.hpp>
#include <preview/Runtime/Recognition/MixedTrialMode.hpp>
#include <preview/Runtime/Recognition/Profile.hpp>
#include <preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <preview/Runtime/Recognition/Protocol.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
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

    struct Calls
    {
        std::size_t Inspect{0};
        std::size_t Prepare{0};
        std::size_t Commit{0};
        bool ReturnEmptyOnCommit{false};
        bool ConsumeCommitReplay{false};
        bool CloseReturnedTransportBeforeReturn{false};
        Preview::SharedTransmission ReturnedTransport{};
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> CommitGate{};
        bool PendingCommit{false};
        bool PrepareCompleted{false};
        bool CommitCompleted{false};
        std::shared_ptr<bool> CancelAfterPrepare{};
        std::shared_ptr<bool> CancelAfterCommit{};
        bool CommitSawPreparedState{false};
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

    struct ConfiguredProfileRequest
    {
        std::shared_ptr<Calls> State;
        rec::PrepareResult Prepare;
        rec::CommitResult Commit;
        std::size_t MinimumBytes{3};
        std::chrono::milliseconds Timeout{250};
        std::vector<rec::RouteBinding> Routes;
        std::size_t MaxProbeBytes{32};
        rec::ProtocolType Protocol{rec::ProtocolType::Vless};
        rec::CandidateKind Kind{rec::CandidateKind::Opaque};
        rec::RecognitionMode Mode{rec::RecognitionMode::Configured};
    };

    auto MakeConfiguredProfile(ConfiguredProfileRequest Request) -> rec::SharedProfile
    {
        const auto State = std::move(Request.State);
        auto PrepareResult = std::move(Request.Prepare);
        auto CommitResult = std::move(Request.Commit);
        const auto MinimumBytes = Request.MinimumBytes;
        rec::ProfileSpec Spec;
        Spec.Mode = Request.Mode;
        Spec.ConfiguredCandidate = rec::InvalidCandidate;
        if (Request.Mode == rec::RecognitionMode::Configured)
        {
            Spec.ConfiguredCandidate = rec::CandidateId{7};
        }
        Spec.Budget.MaxProbeBytes = Request.MaxProbeBytes;
        Spec.Budget.Timeout = Request.Timeout;
        Spec.Routes = std::move(Request.Routes);

        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "configured";
        Candidate.Protocol = Request.Protocol;
        Candidate.Kind = Request.Kind;
        if (Request.Kind == rec::CandidateKind::TlsCarrier)
        {
            Candidate.Scheme = "native";
        }
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = MinimumBytes;
        Candidate.Inspect = [State, MinimumBytes](const rec::ProbeSnapshot &Snapshot)
        {
            ++State->Inspect;
            if (Snapshot.Size() < MinimumBytes)
            {
                return rec::MatchState::NeedMore;
            }
            return rec::MatchState::Structural;
        };
        Candidate.Prepare = [State, PrepareResult](rec::PrepareContext) mutable -> Net::awaitable<rec::PrepareResult>
        {
            ++State->Prepare;
            if (State->CancelAfterPrepare)
            {
                *State->CancelAfterPrepare = true;
            }
            State->PrepareCompleted = true;
            co_return PrepareResult;
        };
        Candidate.Commit = [State, CommitResult](rec::CommitContext Context) mutable
            -> Net::awaitable<rec::CommitResult>
        {
            ++State->Commit;
            State->CommitSawPreparedState = State->CommitSawPreparedState ||
                                            static_cast<bool>(Context.PreparedState);
            if (State->CancelAfterCommit)
            {
                *State->CancelAfterCommit = true;
            }
            if (State->PendingCommit && State->CommitGate)
            {
                co_await State->CommitGate->async_receive(Net::use_awaitable);
            }
            if (State->ConsumeCommitReplay && Context.Inbound)
            {
                std::array<std::byte, 1> Prefix{};
                std::error_code Error;
                (void)co_await Context.Inbound->async_read_some(Prefix, Error);
                auto Consumed = CommitResult;
                if (State->ReturnedTransport)
                {
                    Consumed.Transport = State->ReturnedTransport;
                }
                else
                {
                    Consumed.Transport = std::move(Context.Inbound);
                }
                if (State->CloseReturnedTransportBeforeReturn && Consumed.Transport)
                {
                    Consumed.Transport->Cancel();
                    Consumed.Transport->Close();
                }
                State->CommitCompleted = true;
                co_return Consumed;
            }
            auto Result = CommitResult;
            if (State->ReturnEmptyOnCommit)
            {
                Result.Transport.reset();
                State->CommitCompleted = true;
                co_return Result;
            }
            if (!Result.Transport)
            {
                if (State->ReturnedTransport)
                {
                    Result.Transport = State->ReturnedTransport;
                }
                else
                {
                    Result.Transport = std::move(Context.Inbound);
                }
            }
            if (State->CloseReturnedTransportBeforeReturn && Result.Transport)
            {
                Result.Transport->Cancel();
                Result.Transport->Close();
            }
            State->CommitCompleted = true;
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));

        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        EXPECT_TRUE(Compiled.has_value());
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

    auto AcceptedPrepare(rec::CandidateId Candidate) -> rec::PrepareResult
    {
        rec::PrepareResult Result;
        Result.Candidate = Candidate;
        Result.Status = rec::RecognitionStatus::Accepted;
        Result.PreparedState = std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(Candidate));
        return Result;
    }

    auto AcceptedCommit(rec::CandidateId Candidate) -> rec::CommitResult
    {
        rec::CommitResult Result;
        Result.Candidate = Candidate;
        Result.Status = rec::RecognitionStatus::Accepted;
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

    TEST(ConfiguredModeTest, InspectsPreparesAndCommitsOnlyConfiguredCandidate)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03, 0x04}));
        auto CallsState = std::make_shared<Calls>();
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Vless);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 1U);
        ASSERT_EQ(Transport->ReadRequests().size(), 1U);
        EXPECT_EQ(Transport->ReadRequests().front(), 3U);
        ASSERT_NE(Result.transport, nullptr);
        std::array<std::byte, 3> Replay{};
        std::error_code Error;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Count = co_await Result.transport->async_read_some(Replay, Error);
                    EXPECT_EQ(Count, Replay.size());
                });
        EXPECT_FALSE(Error);
        EXPECT_EQ(Replay, (std::array<std::byte, 3>{std::byte{0xA1}, std::byte{0x02}, std::byte{0x03}}));
        std::array<std::byte, 1> Tail{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Count = co_await Result.transport->async_read_some(Tail, Error);
                    EXPECT_EQ(Count, Tail.size());
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(2);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::Pipeline Pipeline(Profile);
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
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
        Candidate.Protocol = rec::ProtocolType::Vless;
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
        Candidate.Commit = [CallsState](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++CallsState->Commit;
            std::array<std::byte, 1> Prefix{};
            std::error_code Error;
            (void)co_await Context.Inbound->async_read_some(Prefix, Error);
            rec::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = rec::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32);
        rec::ConfiguredMode Mode(Compiled.value());
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
                    const auto Count = co_await Result.transport->async_read_some(Tail, Error);
                    EXPECT_EQ(Count, Tail.size());
                });
        EXPECT_FALSE(Error);
        EXPECT_EQ(Tail, (std::array<std::byte, 2>{std::byte{0x02}, std::byte{0x03}}));
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

    TEST(ConfiguredModeTest, ControlledCommitCleansIndependentSuccessorAndInboundExactlyOnce)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        CallsState->PendingCommit = true;
        CallsState->CommitGate = Gate;
        auto Decoy = std::make_shared<ScriptedTransport>(Io.get_executor());
        CallsState->ReturnedTransport = Decoy;
        auto Profile = MakeConfiguredProfile(
            {CallsState, AcceptedPrepare(7), AcceptedCommit(7), 3, std::chrono::milliseconds(1)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
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
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_TRUE(CallsState->CommitCompleted);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
    }

    TEST(ConfiguredModeTest, PrepareCancellationIsNormalized)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "pending-prepare";
        Candidate.Protocol = rec::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [Gate, CallsState](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
        {
            ++CallsState->Prepare;
            co_await Gate->async_receive(Net::use_awaitable);
            CallsState->PrepareCompleted = true;
            auto Result = AcceptedPrepare(Context.Candidate);
            Result.Status = rec::RecognitionStatus::IoError;
            Result.Error = std::make_error_code(std::errc::operation_canceled);
            co_return Result;
        };
        Candidate.Commit = [CallsState](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++CallsState->Commit;
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32);
        rec::ConfiguredMode Mode(Compiled.value());
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate]
        {
            Gate->try_send(boost::system::error_code{});
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_TRUE(CallsState->PrepareCompleted);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

    TEST(ConfiguredModeTest, CommitCancellationIsNormalizedAndReturnsNoSuccessor)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Decoy = std::make_shared<ScriptedTransport>(Io.get_executor());
        CallsState->ReturnedTransport = Decoy;
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "pending-commit";
        Candidate.Protocol = rec::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [CallsState](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
        {
            ++CallsState->Prepare;
            co_return AcceptedPrepare(Context.Candidate);
        };
        Candidate.Commit = [Gate, CallsState](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++CallsState->Commit;
            co_await Gate->async_receive(Net::use_awaitable);
            CallsState->CommitCompleted = true;
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Status = rec::RecognitionStatus::IoError;
            Result.Error = std::make_error_code(std::errc::operation_canceled);
            if (CallsState->ReturnedTransport)
            {
                Result.Transport = CallsState->ReturnedTransport;
            }
            else
            {
                Result.Transport = std::move(Context.Inbound);
            }
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32);
        rec::ConfiguredMode Mode(Compiled.value());
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
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
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_EQ(CallsState->Commit, 1U);
        EXPECT_TRUE(CallsState->CommitCompleted);
        EXPECT_EQ(*WaitCalls, 3U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(ConfiguredModeTest, OperationWinningNearCancellationIsOverriddenBeforeCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Cancelled = std::make_shared<bool>(false);
        CallsState->CancelAfterPrepare = Cancelled;
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Cancelled = [Cancelled] { return *Cancelled; };
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
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
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 0U);
        EXPECT_EQ(*WaitCalls, 2U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);

        Io.restart();
        Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        CallsState = std::make_shared<Calls>();
        Cancelled = std::make_shared<bool>(false);
        CallsState->CancelAfterCommit = Cancelled;
        Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        Buffer = rec::ProbeBuffer(Profile->Budget().MaxProbeBytes);
        Mode = rec::ConfiguredMode(Profile);
        Control = rec::RecognitionControl{};
        Control.Cancelled = [Cancelled] { return *Cancelled; };
        WaitCalls = std::make_shared<std::size_t>(0);
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        Result = {};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(CallsState->Commit, 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_EQ(*WaitCalls, 3U);
    }

    TEST(ConfiguredModeTest, CandidateHandleOwnsProfileAcrossAsyncPrepareAndCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto CallsState = std::make_shared<Calls>();
        rec::CandidateHandle Handle;
        {
            auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
            Handle = Profile->FindCandidate(7);
        }

        rec::PrepareContext PrepareContext;
        PrepareContext.Candidate = 7;
        PrepareContext.Budget.MaxProbeBytes = 32;
        rec::PrepareResult PreparedResult;
        rec::CommitResult CommitResult;
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    PreparedResult = co_await Handle.Prepare(std::move(PrepareContext));
                    rec::PreparedCandidate Prepared(Handle, std::move(PreparedResult));
                    rec::CommitContext CommitContext;
                    CommitContext.Inbound = Transport;
                    CommitResult = co_await Prepared.Commit(std::move(CommitContext));
                });

        EXPECT_EQ(CommitResult.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(CommitResult.Candidate, 7U);
        EXPECT_NE(CommitResult.Transport, nullptr);
        EXPECT_TRUE(CallsState->CommitSawPreparedState);
        EXPECT_TRUE(Handle.IsValid());
    }

    TEST(ConfiguredModeTest, UsesMatchingSniRouteBeforePrepare)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Preview::Testing::RecognitionWire::MakeTlsClientHello("configured.example");
        auto State = std::make_shared<Calls>();
        ConfiguredProfileRequest Request{State, AcceptedPrepare(7), AcceptedCommit(7)};
        Request.MinimumBytes = 5;
        Request.Routes.emplace_back("configured.example", 7);
        Request.Timeout = std::chrono::milliseconds(250);
        Request.MaxProbeBytes = 128;
        Request.Protocol = rec::ProtocolType::Tls;
        Request.Kind = rec::CandidateKind::TlsCarrier;
        auto Profile = MakeConfiguredProfile(std::move(Request));
        ASSERT_NE(Profile, nullptr);
        ASSERT_TRUE(Profile->Budget().MaxProbeBytes >= Wire.size());
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(State->Inspect, 1U);
        EXPECT_EQ(State->Prepare, 1U);
        EXPECT_EQ(State->Commit, 1U);
    }

    TEST(ConfiguredModeTest, RejectsUnmatchedSniWithoutPrepare)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Preview::Testing::RecognitionWire::MakeTlsClientHello("other.example");
        auto State = std::make_shared<Calls>();
        ConfiguredProfileRequest Request{State, AcceptedPrepare(7), AcceptedCommit(7)};
        Request.MinimumBytes = 5;
        Request.Routes.emplace_back("configured.example", 7);
        Request.Timeout = std::chrono::milliseconds(250);
        Request.MaxProbeBytes = 128;
        Request.Protocol = rec::ProtocolType::Tls;
        Request.Kind = rec::CandidateKind::TlsCarrier;
        auto Profile = MakeConfiguredProfile(std::move(Request));
        ASSERT_NE(Profile, nullptr);
        ASSERT_TRUE(Profile->Budget().MaxProbeBytes >= Wire.size());
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::NoMatch);
        EXPECT_EQ(State->Inspect, 1U);
        EXPECT_EQ(State->Prepare, 0U);
        EXPECT_EQ(State->Commit, 0U);
    }

} // namespace
