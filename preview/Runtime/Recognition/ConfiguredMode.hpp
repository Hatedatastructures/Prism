/**
 * @file ConfiguredMode.hpp
 * @brief Configured recognition coordinator and shared recognition results.
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Recognition/Profile.hpp>
#include <preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <preview/Runtime/Recognition/Tls.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @enum RecognitionControlEvent
     * @brief Caller-owned asynchronous recognition stop event.
     */
    enum class RecognitionControlEvent : std::uint8_t
    {
        Cancelled,
        TimedOut,
    };

    struct RecognizeResult;

    /**
     * @struct RecognitionControl
     * @brief Caller-owned cancellation and total-deadline checks.
     * @details The coordinator computes one effective total deadline and uses
     *          a fresh internal timer for each in-flight operation without
     *          resetting that deadline per candidate. A caller that owns a
     *          timer can expose its state via Cancelled and Deadline. Wait must
     *          be a repeatable factory; WaitCancellationSafe declares that the
     *          factory cooperates with CancelTransport so every losing race can
     *          complete.
     */
    struct RecognitionControl
    {
        using Clock = std::chrono::steady_clock;
        using WaitFn = std::function<Net::awaitable<RecognitionControlEvent>()>;
        using CancelFn = std::function<void()>;

        Clock::time_point Deadline{Clock::time_point::max()};
        std::function<bool()> Cancelled{};
        WaitFn Wait{};
        CancelFn CancelTransport{};
        // Wait 必须可重复创建，并能在取消钩子触发后收口。
        bool WaitCancellationSafe{false};

        [[nodiscard]] auto IsCancelled() const -> bool
        {
            return Cancelled && Cancelled();
        }

        [[nodiscard]] auto IsExpired(Clock::time_point Now = Clock::now()) const noexcept -> bool
        {
            return Deadline != Clock::time_point::max() && Now >= Deadline;
        }
    };

    struct ControlRaceRequest
    {
        RecognitionControl Control;
        RecognitionControl::Clock::time_point Deadline{RecognitionControl::Clock::time_point::max()};
    };

    namespace detail
    {

        template <typename T>
        struct ControlRaceResult
        {
            T Value{};
            RecognitionControlEvent Event{RecognitionControlEvent::Cancelled};
            bool Controlled{false};
        };

        [[nodiscard]] inline auto IsCancellationError(const std::error_code &Error) noexcept -> bool
        {
            return Error == std::make_error_code(std::errc::operation_canceled) ||
                   Preview::Fault::ToCode(Error) == Preview::Fault::Code::Canceled;
        }

        template <typename Result>
        inline auto NormalizeCandidateStatus(Result &Candidate) -> void
        {
            if (IsCancellationError(Candidate.Error))
            {
                Candidate.Status = RecognitionStatus::IoError;
            }
        }

        [[nodiscard]] inline auto WaitUntil(RecognitionControl::Clock::time_point Deadline)
            -> Net::awaitable<RecognitionControlEvent>
        {
            const auto Executor = co_await Net::this_coro::executor;
            Net::steady_timer Timer(Executor);
            Timer.expires_at(Deadline);
            co_await Timer.async_wait(Net::use_awaitable);
            co_return RecognitionControlEvent::TimedOut;
        }

        [[nodiscard]] inline auto WaitForControl(Net::awaitable<RecognitionControlEvent> Wait,
                                                 RecognitionControl::CancelFn Cancel)
            -> Net::awaitable<RecognitionControlEvent>
        {
            const auto Event = co_await std::move(Wait);
            if (Cancel)
            {
                Cancel();
            }
            co_return Event;
        }

        [[nodiscard]] inline auto WaitForControlSource(RecognitionControl::WaitFn Caller,
                                                       RecognitionControl::Clock::time_point Deadline)
            -> Net::awaitable<RecognitionControlEvent>
        {
            if (Caller && Deadline != RecognitionControl::Clock::time_point::max())
            {
                auto CallerWait = Caller();
                auto DeadlineWait = WaitUntil(Deadline);
                using Net::experimental::awaitable_operators::operator||;
                auto Race = co_await (std::move(CallerWait) || std::move(DeadlineWait));
                if (Race.index() == 0)
                {
                    co_return std::get<0>(Race);
                }
                co_return std::get<1>(Race);
            }
            if (Caller)
            {
                co_return co_await Caller();
            }
            co_return co_await WaitUntil(Deadline);
        }

        template <typename T>
        [[nodiscard]] auto AwaitWithControl(Net::awaitable<T> Operation,
                                            ControlRaceRequest Request)
            -> Net::awaitable<ControlRaceResult<T>>
        {
            ControlRaceResult<T> Result;
            if (!Request.Control.Wait &&
                Request.Deadline == RecognitionControl::Clock::time_point::max())
            {
                Result.Value = co_await std::move(Operation);
                co_return Result;
            }

            auto OperationResult = std::make_shared<T>();
            auto WrappedOperation = [Operation = std::move(Operation), OperationResult]() mutable
                -> Net::awaitable<void>
            {
                *OperationResult = co_await std::move(Operation);
            };
            auto Source = WaitForControlSource(Request.Control.Wait, Request.Deadline);
            auto Wait = WaitForControl(std::move(Source), Request.Control.CancelTransport);
            using Net::experimental::awaitable_operators::operator||;
            auto Race = co_await (WrappedOperation() || std::move(Wait));
            if (Race.index() == 0)
            {
                Result.Value = std::move(*OperationResult);
                co_return Result;
            }
            Result.Event = std::get<1>(Race);
            Result.Controlled = true;
            Result.Value = std::move(*OperationResult);
            co_return Result;
        }

        inline auto InvokeCancel(const RecognitionControl &Control) -> void
        {
            if (Control.CancelTransport)
            {
                Control.CancelTransport();
            }
        }

        inline auto CleanupTransport(SharedTransmission Transport) -> void
        {
            if (Transport && Transport->IsOpen())
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        [[nodiscard]] inline auto ContainsTransport(const SharedTransmission &Outer,
                                                     const SharedTransmission &Target) noexcept -> bool
        {
            if (!Outer || !Target)
            {
                return false;
            }
            auto *Current = Outer.get();
            while (Current)
            {
                if (Current == Target.get())
                {
                    return true;
                }
                Current = Current->NextLayer();
            }
            return false;
        }

        struct CleanupTransportsRequest
        {
            SharedTransmission Returned;
            SharedTransmission Inbound;
        };

        inline auto CleanupTransports(CleanupTransportsRequest Request) -> void
        {
            const bool Aliased = Request.Returned && Request.Inbound &&
                                 (Request.Returned.get() == Request.Inbound.get() ||
                                  ContainsTransport(Request.Returned, Request.Inbound) ||
                                  ContainsTransport(Request.Inbound, Request.Returned));
            CleanupTransport(std::move(Request.Returned));
            if (!Aliased)
            {
                CleanupTransport(std::move(Request.Inbound));
            }
        }

        inline auto ArmControl(RecognitionControl &Control, const SharedTransmission &Inbound,
                               RecognitionControl::Clock::time_point Deadline) -> bool
        {
            Control.Deadline = Deadline;
            if (Control.Wait && (!Control.WaitCancellationSafe || !Control.CancelTransport))
            {
                return false;
            }
            if (Control.Cancelled && !Control.Wait && !Control.IsCancelled())
            {
                return false;
            }
            if (Deadline != RecognitionControl::Clock::time_point::max() && !Control.CancelTransport)
            {
                Control.CancelTransport = [Inbound]
                {
                    Inbound->Cancel();
                    Inbound->Close();
                };
            }
            return true;
        }

    } // namespace detail

    /**
     * @struct RecognizeResult
     * @brief Recognition result shared by legacy and profile-based pipelines.
     * @note Legacy fields intentionally remain first and retain their defaults.
     */
    struct RecognizeResult
    {
        ProtocolType detected{ProtocolType::Unknown};
        SharedTransmission transport;
        std::vector<std::byte> preread;
        std::string scheme;
        bool success{false};

        RecognitionMode Mode{RecognitionMode::Configured};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        CandidateId Candidate{InvalidCandidate};
        std::string CandidateName;
        std::error_code Error{};
        bool Polluted{false};
        bool Cancelled{false};
        std::size_t ProbeBytes{0};
        std::uint16_t CryptoTrials{0};
    };

    struct ResultStatusRequest
    {
        RecognizeResult *Result{nullptr};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        std::error_code Error{};
        bool Polluted{false};
    };

    namespace detail
    {

        inline auto SetResultStatus(ResultStatusRequest Request) -> void
        {
            auto &Result = *Request.Result;
            const auto Status = Request.Status;
            const auto &Error = Request.Error;
            const auto Polluted = Request.Polluted;
            Result.Status = Status;
            Result.Error = Error;
            Result.Polluted = Result.Polluted || Polluted || Status == RecognitionStatus::Polluted;
            if (IsCancellationError(Error))
            {
                Result.Status = RecognitionStatus::IoError;
                Result.Cancelled = true;
            }
            Result.success = Result.Status == RecognitionStatus::Accepted && !Result.Polluted;
        }

        inline auto SetControlStatus(RecognizeResult &Result, RecognitionControlEvent Event) -> void
        {
            if (Event == RecognitionControlEvent::Cancelled)
            {
                SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                                                    std::make_error_code(std::errc::operation_canceled)});
                Result.Cancelled = true;
                return;
            }
            SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::TimedOut,
                                                std::make_error_code(std::errc::timed_out)});
        }

        /**
         * @struct RouteDecision
         * @brief 同一预读快照上的 SNI 路由解析结果
         */
        struct RouteDecision
        {
            std::optional<CandidateId> Candidate;
            std::size_t Required{0};
            bool Applicable{false};
            bool NeedMore{false};
        };

        [[nodiscard]] inline auto IsTlsRouteCandidate(const CandidateHandle &Handle) noexcept -> bool
        {
            return Handle.Protocol() == ProtocolType::Tls || Handle.Kind() == CandidateKind::TlsCarrier;
        }

        [[nodiscard]] inline auto HasTlsRouteCandidate(const Profile &Profile,
                                                       const std::vector<CandidateId> &Candidates) noexcept
            -> bool
        {
            return std::any_of(Candidates.begin(), Candidates.end(), [&Profile](const auto Id)
                               { return IsTlsRouteCandidate(Profile.FindCandidate(Id)); });
        }

        /**
         * @brief 从同一 ProbeSnapshot 解析 SNI 并查找 Profile route
         * @param Profile 不可变识别 Profile
         * @param Snapshot 当前连接预读快照
         * @return route 候选及下一次读取边界
         * @details 仅在调用方已确认活动候选包含 TLS carrier 时调用。未命中 route
         *          保持空 Candidate，由 coordinator 映射为 NoMatch。
         */
        [[nodiscard]] inline auto ResolveSniRoute(const Profile &Profile, const ProbeSnapshot &Snapshot)
            -> RouteDecision
        {
            RouteDecision Result;
            if (!Profile.HasRoutes())
            {
                return Result;
            }
            Result.Applicable = true;
            const auto Data = Snapshot.Data();
            if (Data.empty())
            {
                Result.NeedMore = true;
                Result.Required = 1;
                return Result;
            }
            if (std::to_integer<std::uint8_t>(Data.front()) != 0x16)
            {
                Result.Applicable = false;
                return Result;
            }

            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
            const auto Scan = ::Preview::Recognition::detail::ScanClientHello(Bytes);
            if (Scan.Status == Error::NeedMore)
            {
                Result.NeedMore = true;
                Result.Required = (std::max)(Snapshot.Size() + 1, Scan.Required);
                return Result;
            }
            if (Scan.Status != Error::None)
            {
                return Result;
            }

            const auto [ParseError, Features] = ParseClientHelloProgress(Bytes);
            if (ParseError == Error::None)
            {
                Result.Candidate = Profile.LookupRoute(Features.ServerName);
            }
            return Result;
        }

        /**
         * @brief 获取当前 TLS ClientHello 扫描器给出的下一读取边界
         * @param Snapshot 当前连接预读快照
         * @return 需要补齐的绝对字节数；非 TLS 或已结束时返回 0
         * @details 只扫描已捕获字节，不执行 I/O。这样 TLS 多记录握手
         *          可以一次补齐到下一条结构边界，避免按字节增长。
         */
        [[nodiscard]] inline auto TlsProbeRequired(const ProbeSnapshot &Snapshot) -> std::size_t
        {
            const auto Data = Snapshot.Data();
            if (Data.empty() || std::to_integer<std::uint8_t>(Data.front()) != 0x16)
            {
                return 0;
            }
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
            const auto Scan = ScanClientHello(Bytes);
            if (Scan.Status == Error::NeedMore)
            {
                return Scan.Required;
            }
            return 0;
        }

    } // namespace detail

    /**
     * @class PreparedCandidate
     * @brief Moveable prepared candidate with a one-shot commit barrier.
     */
    class PreparedCandidate
    {
    public:
        PreparedCandidate() = default;

        PreparedCandidate(CandidateHandle Handle, PrepareResult Result)
            : Handle_(std::move(Handle)), Result_(std::move(Result))
        {
        }

        PreparedCandidate(const PreparedCandidate &) = delete;
        auto operator=(const PreparedCandidate &) -> PreparedCandidate & = delete;
        PreparedCandidate(PreparedCandidate &&) noexcept = default;
        auto operator=(PreparedCandidate &&) noexcept -> PreparedCandidate & = default;

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Handle_.IsValid() && Result_.Status == RecognitionStatus::Accepted && !Result_.Polluted &&
                   !detail::IsCancellationError(Result_.Error);
        }

        [[nodiscard]] auto Id() const noexcept -> CandidateId
        {
            return Handle_.Id();
        }

        [[nodiscard]] auto Handle() const -> CandidateHandle
        {
            return Handle_;
        }

        [[nodiscard]] auto Result() const noexcept -> const PrepareResult &
        {
            return Result_;
        }

        /**
         * @brief Commit exactly once.
         * @param Context Commit input, including the replay transport.
         * @return Commit result.
         */
        [[nodiscard]] auto Commit(CommitContext Context) -> Net::awaitable<CommitResult>
        {
            const bool AlreadyAttempted = Committed_;
            Committed_ = true;
            if (AlreadyAttempted || !IsValid() || Context.Polluted)
            {
                CommitResult Result;
                Result.Candidate = Handle_.Id();
                Result.Status = RecognitionStatus::Polluted;
                Result.Error = std::make_error_code(std::errc::operation_not_permitted);
                Result.Polluted = true;
                co_return Result;
            }

            Context.Candidate = Handle_.Id();
            Context.PreparedState = Result_.PreparedState;
            Context.Polluted = Context.Polluted || Result_.Polluted;
            co_return co_await Handle_.Commit(std::move(Context));
        }

        /**
         * @brief Convenience commit overload for a replay transport.
         * @param Inbound Replay transport.
         * @return Commit result.
         */
        [[nodiscard]] auto Commit(SharedTransmission Inbound) -> Net::awaitable<CommitResult>
        {
            CommitContext Context;
            Context.Inbound = std::move(Inbound);
            co_return co_await Commit(std::move(Context));
        }

    private:
        CandidateHandle Handle_;
        PrepareResult Result_;
        bool Committed_{false};
    };

    /**
     * @class ConfiguredMode
     * @brief Coordinator for a profile with one configured candidate.
     */
    class ConfiguredMode
    {
    private:
        struct TerminalRequest
        {
            RecognizeResult *Result{nullptr};
            const RecognitionControl *Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            ProbeBuffer *Buffer{nullptr};
            const SharedTransmission *Inbound{nullptr};
            bool InvokeCancel{true};
        };

        struct PrepareRequest
        {
            CandidateHandle Handle;
            ProbeSnapshot Snapshot;
            const RecognitionControl *Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            RecognizeResult *Result{nullptr};
        };

        struct CommitRequest
        {
            RecognizeResult Result;
            PreparedCandidate Prepared;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
        };

    public:
        explicit ConfiguredMode(SharedProfile Profile) : Profile_(std::move(Profile)) {}

        /**
         * @brief Recognize using the caller-owned probe buffer.
         * @param Inbound Inbound transport.
         * @param Buffer Connection-level pre-read owner.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer &Buffer,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            Result.Mode = RecognitionMode::Configured;
            if (Profile_)
            {
                Result.Mode = Profile_->Mode();
            }
            if (!Profile_ || !Inbound || Profile_->Mode() != RecognitionMode::Configured ||
                Profile_->CandidateCount() != 1)
            {
                co_return Result;
            }

            co_await Net::dispatch(Inbound->Executor(), Net::use_awaitable);

            const auto Handle = Profile_->FindCandidate(Profile_->ConfiguredCandidate());
            InitializeResult(Result, Handle);
            const auto Deadline = EffectiveDeadline(Control);
            if (!detail::ArmControl(Control, Inbound, Deadline))
            {
                SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                                              std::make_error_code(std::errc::operation_not_supported)});
                co_return Result;
            }

            std::size_t Required = Handle.MinimumBytes();
            while (true)
            {
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                const auto FillRace = co_await detail::AwaitWithControl(
                    Buffer.Ensure(*Inbound, Required), ControlRaceRequest{Control, Deadline});
                if (FillRace.Controlled)
                {
                    detail::SetControlStatus(Result, FillRace.Event);
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                auto Fill = std::move(FillRace.Value);
                Result.ProbeBytes = Buffer.Size();
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                detail::NormalizeCandidateStatus(Fill);
                if (Fill.Status != RecognitionStatus::Accepted)
                {
                    SetStatus(ResultStatusRequest{&Result, Fill.Status, Fill.Error,
                                                  Fill.Status == RecognitionStatus::Polluted});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }

                const auto Snapshot = Buffer.Snapshot();
                const auto State = Handle.Inspect(Snapshot);
                if (State == MatchState::NeedMore)
                {
                    if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                    Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                          (std::max)(Buffer.Size() + 1, detail::TlsProbeRequired(Snapshot)));
                    continue;
                }
                if (State == MatchState::Rejected)
                {
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }

                if (detail::IsTlsRouteCandidate(Handle))
                {
                    const auto Route = detail::ResolveSniRoute(*Profile_, Snapshot);
                    if (Route.NeedMore)
                    {
                        if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                        {
                            SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                            co_return CompleteBufferResult(Result, Buffer, Inbound);
                        }
                        Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                              (std::max)(Buffer.Size() + 1, Route.Required));
                        continue;
                    }
                    if (Route.Applicable &&
                        (!Route.Candidate || *Route.Candidate != Handle.Id()))
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                }

                auto PreparedRace = co_await Prepare(PrepareRequest{Handle, Snapshot, &Control, Deadline, &Result});
                if (PreparedRace.Controlled)
                {
                    detail::SetControlStatus(Result, PreparedRace.Event);
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                auto PreparedResult = std::move(PreparedRace.Value);
                detail::NormalizeCandidateStatus(PreparedResult);
                PreparedResult.Candidate = Handle.Id();
                if (PreparedResult.NeedMore && !PreparedResult.Polluted)
                {
                    if (Result.CryptoTrials > 0)
                    {
                        --Result.CryptoTrials;
                    }
                    if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                    Required = (std::min)(Profile_->Budget().MaxProbeBytes, Buffer.Size() + 1);
                    continue;
                }
                if (PreparedResult.Status != RecognitionStatus::Accepted || PreparedResult.Polluted)
                {
                    if (PreparedResult.Polluted)
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::Polluted,
                                                      PreparedResult.Error, true});
                    }
                    else
                    {
                        SetStatus(ResultStatusRequest{&Result, PreparedResult.Status, PreparedResult.Error,
                                                      PreparedResult.Status == RecognitionStatus::Polluted});
                    }
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }

                PreparedCandidate Prepared(Handle, std::move(PreparedResult));
                co_return co_await CommitPrepared(CommitRequest{std::move(Result), std::move(Prepared), Handle,
                                                                std::move(Inbound), &Buffer, std::move(Control),
                                                                Deadline});
            }
        }

        /**
         * @brief Alternate argument order for callers that own the buffer first.
         * @param Buffer Connection-level pre-read owner.
         * @param Inbound Inbound transport.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(ProbeBuffer &Buffer, SharedTransmission Inbound,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            co_return co_await Recognize(std::move(Inbound), Buffer, std::move(Control));
        }

    private:
        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl &Control) const
            -> RecognitionControl::Clock::time_point
        {
            const auto Limit = RecognitionControl::Clock::time_point::max();
            if (Profile_->Budget().Timeout.count() <= 0)
            {
                return Control.Deadline;
            }
            const auto BudgetDeadline = RecognitionControl::Clock::now() + Profile_->Budget().Timeout;
            if (Control.Deadline == Limit)
            {
                return BudgetDeadline;
            }
            return (std::min)(Control.Deadline, BudgetDeadline);
        }

        static auto InitializeResult(RecognizeResult &Result, const CandidateHandle &Handle) -> void
        {
            Result.Candidate = Handle.Id();
            Result.CandidateName = Handle.Name();
            Result.detected = Handle.Protocol();
            Result.scheme = Handle.Scheme();
            if (Result.scheme.empty())
            {
                Result.scheme = Result.CandidateName;
            }
        }

        static auto SetStatus(ResultStatusRequest Request) -> void
        {
            detail::SetResultStatus(std::move(Request));
        }

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer &Buffer,
                                         const SharedTransmission &Inbound) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport = Buffer.Replay(Inbound);
            return Result;
        }

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer &Buffer)
            -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport.reset();
            return Result;
        }

        static auto SetControlTerminal(TerminalRequest Request) -> bool
        {
            auto &Result = *Request.Result;
            const auto &Control = *Request.Control;
            if (Control.IsCancelled())
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::Cancelled);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            if (Request.Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Request.Deadline)
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::TimedOut);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            return false;
        }

        static auto RemainingBudget(const RecognitionBudget &Budget,
                                    RecognitionControl::Clock::time_point Deadline)
            -> RecognitionBudget
        {
            auto Result = Budget;
            if (Deadline != RecognitionControl::Clock::time_point::max())
            {
                const auto Now = RecognitionControl::Clock::now();
                if (Now >= Deadline)
                {
                    Result.Timeout = std::chrono::milliseconds{0};
                }
                else
                {
                    Result.Timeout = std::chrono::duration_cast<std::chrono::milliseconds>(Deadline - Now);
                }
            }
            return Result;
        }

        auto CommitPrepared(CommitRequest Request) -> Net::awaitable<RecognizeResult>
        {
            auto Result = std::move(Request.Result);
            auto Prepared = std::move(Request.Prepared);
            const auto Handle = Request.Handle;
            auto Inbound = std::move(Request.Inbound);
            auto Control = std::move(Request.Control);
            auto *Buffer = Request.Buffer;
            const auto Deadline = Request.Deadline;
            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound}))
            {
                co_return Result;
            }

            Result.preread.assign(Buffer->Data().begin(), Buffer->Data().end());
            CommitContext Context;
            Context.Candidate = Handle.Id();
            Context.Inbound = Buffer->Replay(Inbound);
            auto CommittedRace = co_await detail::AwaitWithControl(
                Prepared.Commit(std::move(Context)), ControlRaceRequest{Control, Deadline});
            auto Committed = std::move(CommittedRace.Value);
            if (CommittedRace.Controlled)
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                detail::SetControlStatus(Result, CommittedRace.Event);
                co_return CompleteNoTransportResult(std::move(Result), *Buffer);
            }

            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound, false}))
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                co_return Result;
            }

            detail::NormalizeCandidateStatus(Committed);
            NormalizeCommit(Result, Committed, Handle);
            if (Committed.Status == RecognitionStatus::Accepted && !Committed.Polluted)
            {
                if (!Committed.Transport)
                {
                    detail::CleanupTransports({{}, Inbound});
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                                                  std::make_error_code(std::errc::operation_not_supported)});
                }
                else
                {
                    Result.transport = std::move(Committed.Transport);
                }
            }
            else
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
            }
            co_return Result;
        }

        auto Prepare(PrepareRequest Request) -> Net::awaitable<detail::ControlRaceResult<PrepareResult>>
        {
            detail::ControlRaceResult<PrepareResult> Outcome;
            const auto &Handle = Request.Handle;
            const auto &Snapshot = Request.Snapshot;
            const auto &Control = *Request.Control;
            const auto Deadline = Request.Deadline;
            auto &Result = *Request.Result;
            if (!Handle.HasPrepare())
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::Accepted;
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            if (Control.IsCancelled())
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::IoError;
                Prepared.Error = std::make_error_code(std::errc::operation_canceled);
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            if (Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Deadline)
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::TimedOut;
                Prepared.Error = std::make_error_code(std::errc::timed_out);
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            if (Result.CryptoTrials >= Profile_->Budget().MaxCryptoTrials)
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::BudgetExceeded;
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            ++Result.CryptoTrials;
            PrepareContext Context;
            Context.Candidate = Handle.Id();
            Context.Snapshot = Snapshot;
            Context.Budget = RemainingBudget(Profile_->Budget(), Deadline);
            co_return co_await detail::AwaitWithControl(
                Handle.Prepare(std::move(Context)), ControlRaceRequest{Control, Deadline});
        }

        static auto NormalizeCommit(RecognizeResult &Result, CommitResult &Committed,
                                    const CandidateHandle &Handle) -> void
        {
            detail::NormalizeCandidateStatus(Committed);
            Committed.Candidate = Handle.Id();
            Result.Candidate = Handle.Id();
            if (Committed.Polluted || Committed.Status == RecognitionStatus::Polluted)
            {
                Committed.Status = RecognitionStatus::Polluted;
                Result.Polluted = true;
            }
            detail::SetResultStatus(ResultStatusRequest{&Result, Committed.Status, Committed.Error,
                                                        Committed.Polluted});
            Result.transport = Committed.Transport;
        }

        SharedProfile Profile_;
    };

} // namespace Preview::Recognition
