/**
 * @file ConfiguredModeTestSupport.hpp
 * @brief ConfiguredModeTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

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

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/ConfiguredMode.hpp>
#include <Prism/Runtime/Recognition/MixedTrialMode.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Protocol.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace rec = Prism::Recognition;

    /** @brief 创建配置模式探测测试使用的有界预读池。 */
    auto MakeConfiguredProbeBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
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

        auto FailOnCancel() -> void
        {
            FailCancel_ = true;
        }

        auto FailOnClose() -> void
        {
            FailClose_ = true;
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
            if (FailClose_)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++Cancels_;
            Canceled_ = true;
            (void)ReadWake_.try_send(boost::system::error_code{});
            if (FailCancel_)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
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
        bool FailCancel_{false};
        bool FailClose_{false};
    };

    struct Calls
    {
        std::size_t Inspect{0};
        std::size_t Prepare{0};
        std::size_t Commit{0};
        bool ReturnEmptyOnCommit{false};
        bool ConsumeCommitReplay{false};
        bool CloseReturnedTransportBeforeReturn{false};
        Prism::SharedTransmission ReturnedTransport{};
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> CommitGate{};
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> CommitEntered{};
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
        Prism::Contract::ProtocolType Protocol{Prism::Contract::ProtocolType::Vless};
        rec::CandidateKind Kind{rec::CandidateKind::Opaque};
        rec::RecognitionMode Mode{rec::RecognitionMode::Configured};
    };

    /** @brief 持有配置化提交脚本和结果；每次调用接管本次 replay 与 prepared state。 */
    struct ConfiguredCommitOperation final
    {
        std::shared_ptr<Calls> State;
        rec::CommitResult CommitResult;

        auto operator()(rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
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
                if (State->CommitEntered)
                {
                    (void)State->CommitEntered->try_send(boost::system::error_code{});
                }
                co_await State->CommitGate->async_receive(Net::use_awaitable);
            }
            if (State->ConsumeCommitReplay && Context.Inbound)
            {
                std::array<std::byte, 1> Prefix{};
                (void)co_await Context.Inbound->ReadSome(Prefix);
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
        }
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
        Candidate.Commit = ConfiguredCommitOperation{State, CommitResult};
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


































} // namespace




