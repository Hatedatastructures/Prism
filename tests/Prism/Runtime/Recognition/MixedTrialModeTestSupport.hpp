/**
 * @file MixedTrialModeTestSupport.hpp
 * @brief MixedTrialModeTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

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

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/MixedTrialMode.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Protocol.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace rec = Prism::Recognition;

    /** @brief 创建混合试探测试使用的有界预读池。 */
    auto MakeMixedTrialProbeBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    struct ReadStep
    {
        std::vector<std::byte> Data;
        std::error_code Error{};
    };

    class ScriptedTransport final : public Prism::Transmission
    {
    public:
        explicit ScriptedTransport(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

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

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ReadRequests_.push_back(Buffer.size());
            if (Pending_)
            {
                auto Self = std::static_pointer_cast<ScriptedTransport>(shared_from_this());
                ReadWake_.async_receive(
                    [Self, Buffer, Handler = std::move(Handler)](boost::system::error_code Error) mutable
                    { Self->ResumeRead(Buffer, std::move(Handler), std::move(Error)); });
                return;
            }
            CompleteRead(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++Writes_;
            Prism::Transmission::PostResult(Executor_, std::move(Handler),
                                                  Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++Closes_;
            (void)ReadWake_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++Cancels_;
            Canceled_ = true;
            (void)ReadWake_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Closes_ == 0;
        }

    private:
        auto ResumeRead(std::span<std::byte> Buffer, Completion Handler,
                        boost::system::error_code Error) -> void
        {
            if (Error)
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(static_cast<std::error_code>(Error))});
                return;
            }
            ReadCompleted_ = true;
            if (Canceled_)
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))});
                return;
            }
            CompleteRead(Buffer, std::move(Handler));
        }

        auto CompleteRead(std::span<std::byte> Buffer, Completion Handler) -> void
        {
            if (Steps_.empty())
            {
                Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{0, {}});
                return;
            }
            auto &Step = Steps_.front();
            const auto Count = (std::min)(Buffer.size(), Step.Data.size());
            std::copy_n(Step.Data.begin(), static_cast<std::ptrdiff_t>(Count), Buffer.begin());
            Step.Data.erase(Step.Data.begin(), Step.Data.begin() + static_cast<std::ptrdiff_t>(Count));
            auto Failure = Prism::Fault::FromNative(Step.Error);
            if (Step.Data.empty())
            {
                Steps_.pop_front();
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Count, std::move(Failure)});
        }

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
        Prism::SharedTransmission ReturnedTransport{};
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> Gate{};
        bool PendingPrepare{false};
        bool PendingCommit{false};
        std::size_t InspectMinimum{0};
        std::size_t CandidateMinimum{0};
        bool PrepareCompleted{false};
        bool CommitCompleted{false};
        std::chrono::milliseconds ProfileTimeout{250};
        rec::RecognitionStatus PrepareStatus{rec::RecognitionStatus::NoMatch};
        std::error_code PrepareError{};
        std::size_t PrepareMinimum{0};
        rec::RecognitionStatus CommitStatus{rec::RecognitionStatus::Accepted};
        std::error_code CommitError{};
        Prism::Contract::ProtocolType Protocol{Prism::Contract::ProtocolType::Vless};
        rec::CandidateKind Kind{rec::CandidateKind::Opaque};
        std::optional<std::uint16_t> Priority{};
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

    struct MixedProfileOptions final
    {
        std::vector<std::shared_ptr<CandidateState>> States;
        std::uint16_t MaxCryptoTrials{8};
        std::size_t MinimumBytes{2};
        std::vector<rec::RouteBinding> Routes;
        std::size_t MaxProbeBytes{32};
        rec::CandidateId DefaultCandidate{rec::InvalidCandidate};
        rec::RecognitionMode Mode{rec::RecognitionMode::MixedTrial};
        bool ExpectCompile{true};
    };

    auto InspectCandidate(const std::shared_ptr<CandidateState> &State,
                          const std::size_t MinimumBytes,
                          const rec::ProbeSnapshot &Snapshot) -> rec::MatchState
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
        return State->Structural ? rec::MatchState::Structural : rec::MatchState::Rejected;
    }

    auto PrepareCandidate(const std::shared_ptr<CandidateState> &State,
                          rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
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
        if (State->PrepareMinimum != 0 && Context.Snapshot.Size() < State->PrepareMinimum)
        {
            Result.Status = rec::RecognitionStatus::NoMatch;
            Result.NeedMore = true;
        }
        State->PrepareCompleted = true;
        co_return Result;
    }

    auto CommitCandidate(const std::shared_ptr<CandidateState> &State,
                         rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
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
            (void)co_await Context.Inbound->ReadSome(Prefix);
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
    }

    auto MakeCandidate(const std::shared_ptr<CandidateState> &State,
                       const std::size_t MinimumBytes) -> rec::CandidateSpec
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
        Candidate.Priority = State->Priority.value_or(State->Id);
        if (!State->Fallback)
        {
            Candidate.FirstBytes = {State->FirstByte.value_or(0xB2)};
        }
        Candidate.Fallback = State->Fallback;
        Candidate.MinimumBytes = State->CandidateMinimum == 0 ? MinimumBytes : State->CandidateMinimum;
        Candidate.Inspect = [State, MinimumBytes](const rec::ProbeSnapshot &Snapshot)
        { return InspectCandidate(State, MinimumBytes, Snapshot); };
        Candidate.Prepare = [State](rec::PrepareContext Context)
        { return PrepareCandidate(State, std::move(Context)); };
        Candidate.Commit = [State](rec::CommitContext Context)
        { return CommitCandidate(State, std::move(Context)); };
        return Candidate;
    }

    auto MakeMixedProfile(MixedProfileOptions Options) -> rec::SharedProfile
    {
        rec::ProfileSpec Spec;
        Spec.Mode = Options.Mode;
        Spec.Budget.MaxProbeBytes = Options.MaxProbeBytes;
        Spec.Budget.MaxCandidates = 16;
        Spec.Budget.MaxCryptoTrials = Options.MaxCryptoTrials;
        Spec.Budget.Timeout = std::chrono::milliseconds(250);
        if (!Options.States.empty())
        {
            Spec.Budget.Timeout = Options.States.front()->ProfileTimeout;
        }
        Spec.DefaultCandidate = Options.DefaultCandidate;
        Spec.Routes = std::move(Options.Routes);
        for (const auto &State : Options.States)
        {
            Spec.Candidates.push_back(MakeCandidate(State, Options.MinimumBytes));
        }
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        if (Options.ExpectCompile)
        {
            EXPECT_TRUE(Compiled.has_value());
        }
        if (!Compiled)
        {
            return rec::SharedProfile{};
        }
        return Compiled.value();
    }

    auto MakeMixedProfile(
        std::initializer_list<std::shared_ptr<CandidateState>> States) -> rec::SharedProfile
    {
        return MakeMixedProfile(MixedProfileOptions{std::vector<std::shared_ptr<CandidateState>>(States)});
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





































} // namespace




