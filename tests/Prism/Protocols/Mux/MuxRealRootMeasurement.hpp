#pragma once

/**
 * @file MuxRealRootMeasurement.hpp
 * @brief 真实 Mux Root 的测量、H2、矩阵和诊断共享逻辑。
 * @details 依赖 Fixture 头中的 Root 状态与真实生命周期辅助，不承载 TEST 宏。
 */

#include "MuxRealRootProcessMetrics.hpp"
#include "MuxRealRootWorkload.hpp"
#include "MuxRealRootMatrixControl.hpp"

namespace Prism::Testing::MuxRealRoot
{

    /** @brief 固定块逐字节校验真实 root 回包，再记录往返延迟；仅当前协程借用 Stream。 */
    inline auto MeasureRealStream(const Prism::SharedTransmission &Stream) -> Net::awaitable<Prism::BenchReport>
    {
        std::vector<std::byte> Payload(RealBlockBytes, std::byte{0x5a});
        std::vector<std::byte> Response(RealBlockBytes);
        std::vector<double> Latencies;
        Latencies.reserve(RealTotalBytes / RealBlockBytes);
        const auto Started = std::chrono::steady_clock::now();
        std::size_t Sent = 0;
        while (Sent < RealTotalBytes)
        {
            const auto BlockStarted = std::chrono::steady_clock::now();
            std::error_code Error;
            co_await Stream->AsyncWrite(Payload, Error);
            if (Error) break;
            co_await Stream->AsyncRead(Response, Error);
            if (Error || Response != Payload) break;
            Sent += RealBlockBytes;
            Latencies.push_back(std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - BlockStarted).count());
        }
        co_return FinishRealReport(Sent, Started, Latencies);
    }

    template <typename Client>
    inline auto RunRealMuxClient(const std::shared_ptr<RealRootState> &State, const Prism::Mux::Mode Mode)
        -> Net::awaitable<void>
    {
        auto ClientValue = co_await RootFixture::Connect<Client>(State->Peer, Mode);
        if (ClientValue)
        {
            MarkRealDiagnosticStage(State, RealDiagnosticStage::Connect);
        }
        auto Stream = co_await ClientValue->OpenStream();
        if (!Stream)
        {
            State->FailureMessage = "real root mux child setup failed";
            co_return;
        }
        MarkRealDiagnosticStage(State, RealDiagnosticStage::Open);
        if (!co_await WriteRealLiteralRequest(State, Stream))
        {
            State->FailureMessage = "real root mux child setup failed";
            co_return;
        }
        MarkRealDiagnosticStage(State, RealDiagnosticStage::Literal);
        EXPECT_EQ(State->Harness->UseState->Outstanding(), 1U);
        if (State->Window)
        {
            if (!co_await AwaitRealMeasureStart(State))
            {
                co_return;
            }
            if (State->FailurePoint == RealMatrixFailurePoint::Transfer)
            {
                InjectRealFailure(State, "real root transfer failure injection", true);
                co_return;
            }
            State->Report = co_await MeasureRealStream(Stream);
            const auto Complete = State->Report.Bytes == RealTotalBytes &&
                State->Report.Samples == RealTotalBytes / RealBlockBytes;
            if (Complete)
            {
                MarkRealDiagnosticStage(State, RealDiagnosticStage::TransferComplete);
                MarkRealMeasureComplete(State);
            }
            else
            {
                State->FailureMessage = "real mux throughput exchange failed";
                MarkRealMeasureFailure(State);
            }
            if (State->FailurePoint == RealMatrixFailurePoint::End)
            {
                InjectRealFailure(State, "real root end-gate failure injection", true);
                (void)co_await AwaitRealMeasureEnd(State);
            }
            else
            {
                (void)co_await AwaitRealMeasureEnd(State);
            }
        }
        else
        {
            PrismMuxPerfAllocation::Scope AllocationScope;
            State->Report = co_await MeasureRealStream(Stream);
            RecordRealReportAllocations(State);
        }
        Stream->Shutdown();
        std::array<std::byte, 1> Tail{};
        std::error_code Error;
        const auto Count = co_await Stream->async_read_some(Tail, Error);
        State->ClientPeerClosed = Count == 0U && Error == Prism::Fault::make_error_code(Code::Eof);
        if (State->FailurePoint == RealMatrixFailurePoint::Close)
        {
            InjectRealFailure(State, "real root close failure injection", false);
        }
        Stream->Close();
        co_await ClientValue->Session()->Close();
        State->Peer->Client->Close();
    }
    inline auto FlushRealH2(
        const std::shared_ptr<RealRootState> &State,
        const std::shared_ptr<Prism::Http2::Session> &Session) -> Net::awaitable<bool>
    {
        std::vector<std::byte> Wire;
        if (!Session->Collect(Wire))
        {
            co_return true;
        }
        std::error_code Error;
        co_await State->Peer->Client->AsyncWrite(Wire, Error);
        co_return !Error;
    }

    inline auto PumpRealH2(const std::shared_ptr<RealH2Context> &Context, const std::size_t Required)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        while (Context->Received.size() < Required)
        {
            std::error_code Error;
            const auto Count = co_await Context->State->Peer->Client->async_read_some(Buffer, Error);
            if (Error || Count == 0U)
            {
                co_return false;
            }
            std::error_code FeedError;
            if (!Context->Session->Feed(std::span(Buffer).first(Count), FeedError) || FeedError)
            {
                co_return false;
            }
            std::vector<std::byte> Wire;
            if (Context->Session->Collect(Wire))
            {
                std::error_code WriteError;
                co_await Context->State->Peer->Client->AsyncWrite(Wire, WriteError);
                if (WriteError)
                {
                    co_return false;
                }
            }
        }
        co_return true;
    }

    /** @brief END_STREAM 后等待服务器实际关闭该流；错误和额外 DATA 均不能算正常 EOF。 */
    inline auto WaitRealH2Eof(const std::shared_ptr<RealH2Context> &Context) -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        while (!Context->StreamClosed)
        {
            std::error_code Error;
            const auto Count = co_await Context->State->Peer->Client->async_read_some(Buffer, Error);
            if (Error || Count == 0U) co_return false;
            if (!Context->Session->Feed(std::span(Buffer).first(Count), Error) || Error)
                co_return false;
            if (!co_await FlushRealH2(Context->State, Context->Session)) co_return false;
        }
        co_return Context->StreamClosureKind == Prism::Http2::StreamReceiveClosureKind::EndStream &&
            Context->StreamError == Prism::Http2::ErrorNoError && Context->Received.empty();
    }
    inline auto FinishRealReport(
        const std::size_t Sent,
        const std::chrono::steady_clock::time_point Started,
        const std::vector<double> &Latencies) -> Prism::BenchReport
    {
        Prism::BenchReport Report;
        Report.Bytes = Sent;
        Report.Samples = Latencies.size();
        if (Latencies.empty())
        {
            return Report;
        }
        const auto Ended = std::chrono::steady_clock::now();
        const auto Seconds = std::chrono::duration<double>(Ended - Started).count();
        Report.Mbps = static_cast<double>(Sent) / (1024.0 * 1024.0) / (Seconds > 0.0 ? Seconds : 1e-9);
        auto Ordered = Latencies;
        std::sort(Ordered.begin(), Ordered.end());
        const auto Quantile = [&Ordered](const double Percentile) -> double
        {
            const auto Index = static_cast<std::size_t>(Percentile * static_cast<double>(Ordered.size() - 1U));
            return Ordered[Index];
        };
        Report.LatencyAvg = std::accumulate(Ordered.begin(), Ordered.end(), 0.0) /
            static_cast<double>(Ordered.size());
        Report.LatencyP50 = Quantile(0.50);
        Report.LatencyP95 = Quantile(0.95);
        Report.LatencyP99 = Quantile(0.99);
        Report.LatencyMin = Ordered.front();
        Report.LatencyMax = Ordered.back();
        return Report;
    }
    /** @brief 一个 64 KiB 测量块按 HTTP/2 默认窗口分帧并泵入实际 WINDOW_UPDATE，不修改测量输入。 */
    inline auto ExchangeRealH2Block(const std::shared_ptr<RealH2Context> &Context,
                             std::span<const std::byte> Payload) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Payload.size())
        {
            const auto Count = (std::min)(Payload.size() - Offset, std::size_t{16U * 1024U});
            if (Context->Session->SubmitData(
                    Context->StreamId, Payload.subspan(Offset, Count), false) !=
                Prism::Http2::SubmitDataStatus::Accepted)
                co_return false;
            if (!co_await FlushRealH2(Context->State, Context->Session)) co_return false;
            if (!co_await PumpRealH2(Context, Offset + Count)) co_return false;
            Offset += Count;
        }
        co_return true;
    }

    inline auto FinishRealH2Client(const std::shared_ptr<RealRootState> &State,
                            const std::shared_ptr<RealH2Context> &Context) -> Net::awaitable<void>
    {
        if (Context->Session->SubmitData(
                Context->StreamId, std::span<const std::byte>{}, true) !=
            Prism::Http2::SubmitDataStatus::Accepted)
        {
            State->FailureMessage = "real H2 end stream submission failed";
            co_return;
        }
        if (!co_await FlushRealH2(State, Context->Session))
        {
            State->FailureMessage = "real H2 end stream flush failed";
            co_return;
        }
        State->ClientPeerClosed = co_await WaitRealH2Eof(Context);
        Context->Session->OnData = {};
        Context->Session->OnStreamClose = {};
        State->Peer->Client->Close();
    }

    inline auto PrepareRealH2Client(const std::shared_ptr<RealRootState> &State)
        -> Net::awaitable<std::shared_ptr<RealH2Context>>
    {
        if (!co_await AuthenticateRealRoot(State))
        {
            co_return nullptr;
        }
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{2}};
        std::error_code Error;
        co_await State->Peer->Client->AsyncWrite(Envelope, Error);
        if (Error)
        {
            State->FailureMessage = "real H2 envelope write failed";
            co_return nullptr;
        }
        auto Context = std::make_shared<RealH2Context>();
        Context->State = State;
        Context->Session = std::make_shared<Prism::Http2::Session>(State->Peer->Client->Executor(), false);
        const auto OpenedStream = Context->Session->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}}, false);
        if (!OpenedStream)
        {
            State->FailureMessage = "real H2 stream open failed";
            co_return nullptr;
        }
        Context->StreamId = *OpenedStream;
        Context->Session->OnData = [&Received = Context->Received, StreamId = Context->StreamId](
            const std::int32_t Id, std::span<const std::byte> Value)
        {
            if (Id == StreamId)
            {
                Received.insert(Received.end(), Value.begin(), Value.end());
            }
        };
        Context->Session->OnStreamClose = [Weak = std::weak_ptr<RealH2Context>(Context)](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (const auto Owner = Weak.lock(); Owner && Closure.StreamId == Owner->StreamId)
            {
                Owner->StreamClosed = true;
                Owner->StreamClosureKind = Closure.Kind;
                Owner->StreamError = Closure.ErrorCode;
            }
        };
        Context->Session->SendSettings();
        if (!co_await FlushRealH2(State, Context->Session))
        {
            State->FailureMessage = "real H2 settings flush failed";
            co_return nullptr;
        }
        auto Request = RealTargetRequest(State->Harness->Acceptor.local_endpoint().port());
        const auto Literal = std::as_bytes(std::span(RealLiteral));
        Request.insert(Request.end(), Literal.begin(), Literal.end());
        if (Context->Session->SubmitData(Context->StreamId, Request, false) !=
                Prism::Http2::SubmitDataStatus::Accepted ||
            !co_await FlushRealH2(State, Context->Session) ||
            !co_await PumpRealH2(Context, Literal.size() + 1U))
        {
            State->FailureMessage = "real H2 literal exchange failed";
            co_return nullptr;
        }
        State->LiteralValid = Context->Received.front() == std::byte{0} &&
            std::equal(Context->Received.begin() + 1, Context->Received.end(), Literal.begin(), Literal.end());
        State->FirstConnections = State->Harness->Record->Runtime()->ActiveConnections();
        State->FirstStreams = State->Harness->Record->Runtime()->ActiveStreams();
        if (!State->LiteralValid)
        {
            State->FailureMessage = "real H2 literal response was invalid";
            co_return nullptr;
        }
        co_return Context;
    }

    inline auto RunRealH2Transfer(
        const std::shared_ptr<RealRootState> &State,
        const std::shared_ptr<RealH2Context> &Context) -> Net::awaitable<void>
    {
        Prism::BenchOptions Options;
        Options.Total = RealTotalBytes;
        Options.Block = RealBlockBytes;
        std::vector<std::byte> Payload(Options.Block, std::byte{0x5a});
        std::vector<double> Latencies;
        Latencies.reserve(Options.Total / Options.Block);
        Context->Received.clear();
        if (State->Window)
        {
            if (!co_await AwaitRealMeasureStart(State))
            {
                co_return;
            }
            if (State->FailurePoint == RealMatrixFailurePoint::Transfer)
            {
                InjectRealFailure(State, "real H2 transfer failure injection", true);
                co_return;
            }
        }
        const auto Started = std::chrono::steady_clock::now();
        std::optional<PrismMuxPerfAllocation::Scope> AllocationScope;
        if (!State->Window)
        {
            AllocationScope.emplace();
        }
        std::size_t Sent = 0;
        while (Sent < Options.Total)
        {
            const auto Chunk = std::min(Options.Block, Options.Total - Sent);
            const auto StartedBlock = std::chrono::steady_clock::now();
            if (!co_await ExchangeRealH2Block(Context,
                    std::span<const std::byte>(Payload.data(), Chunk)))
            {
                State->FailureMessage = "real H2 throughput exchange failed";
                co_return;
            }
            if (Context->Received.size() != Chunk ||
                !std::equal(Context->Received.begin(), Context->Received.end(), Payload.begin(), Payload.end()))
            {
                State->FailureMessage = "real H2 throughput response mismatch";
                co_return;
            }
            Context->Received.clear();
            Latencies.push_back(std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - StartedBlock).count());
            Sent += Chunk;
        }
        AllocationScope.reset();
        if (State->Window)
        {
            MarkRealMeasureComplete(State);
            if (State->FailurePoint == RealMatrixFailurePoint::End)
            {
                InjectRealFailure(State, "real H2 end-gate failure injection", true);
                (void)co_await AwaitRealMeasureEnd(State);
            }
            else
            {
                (void)co_await AwaitRealMeasureEnd(State);
            }
        }
        else
        {
            RecordRealReportAllocations(State);
        }
        State->Report = FinishRealReport(Sent, Started, Latencies);
        if (State->FailurePoint == RealMatrixFailurePoint::Close)
        {
            InjectRealFailure(State, "real H2 close failure injection", false);
        }
        co_await FinishRealH2Client(State, Context);
    }

    inline auto RunRealH2Client(const std::shared_ptr<RealRootState> &State) -> Net::awaitable<void>
    {
        const auto Context = co_await PrepareRealH2Client(State);
        if (Context)
        {
            co_await RunRealH2Transfer(State, Context);
        }
    }

    [[nodiscard]] inline auto ExpectedRealHash() -> std::uint64_t
    {
        std::uint64_t Hash = 14695981039346656037ULL;
        UpdateRealHash(Hash, std::as_bytes(std::span(RealLiteral)));
        std::array<std::byte, RealBlockBytes> Block{};
        Block.fill(std::byte{0x5a});
        for (std::size_t Offset = 0; Offset < RealTotalBytes; Offset += RealBlockBytes)
        {
            UpdateRealHash(Hash, Block);
        }
        return Hash;
    }

    inline auto RunRealScenario(const std::shared_ptr<RealRootState> &State) -> Net::awaitable<void>
    {
        Net::co_spawn(State->Harness->Executor, RunRealRoot(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Harness->Stop(); } });
        Net::co_spawn(State->Harness->Executor, RunRealBackend(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Harness->Stop(); } });
        if (State->Mode == RealRootMode::H2Mux)
        {
            co_await RunRealH2Client(State);
        }
        else if (State->Mode == RealRootMode::Smux)
        {
            if (co_await AuthenticateRealRoot(State))
            {
                MarkRealDiagnosticStage(State, RealDiagnosticStage::Authenticate);
                co_await RunRealMuxClient<Smux::Client<>>(State, Prism::Mux::Mode::Smux);
            }
        }
        else if (co_await AuthenticateRealRoot(State))
        {
            MarkRealDiagnosticStage(State, RealDiagnosticStage::Authenticate);
            co_await RunRealMuxClient<Yamux::Client<>>(State, Prism::Mux::Mode::Yamux);
        }
        if (State->Window &&
            State->MeasureTerminal.load(std::memory_order_acquire) == RealMeasureTerminal::Pending)
        {
            MarkRealMeasureFailure(State);
        }
        (void)State->DrainStarted.try_send(boost::system::error_code{});
        State->Harness->Binding->Close();
        const auto DrainResult=co_await State->Harness->Binding->Drain();
        State->Drained=State->Harness->Binding->IsRetired();
        (void)DrainResult;
        if(State->Drained)MarkRealDiagnosticStage(State,RealDiagnosticStage::Drained);
        co_await State->RootDone.async_receive(Net::use_awaitable);
        co_await State->BackendDone.async_receive(Net::use_awaitable);
        State->QuotaZero = State->Harness->Record->Runtime()->ActiveConnections() == 0U &&
            State->Harness->Record->Runtime()->ActiveStreams() == 0U;
        State->WeakExpired = State->Peer->WeakRoot.expired();
        if (State->QuotaZero)
        {
            MarkRealDiagnosticStage(State, RealDiagnosticStage::QuotaZero);
        }
        if (State->WeakExpired)
        {
            MarkRealDiagnosticStage(State, RealDiagnosticStage::WeakExpired);
        }
        State->Harness->Stop();
    }

    inline auto ObserveRealFailureBeforeDrain(
        const std::shared_ptr<RealRootState> &State,
        bool &Observed) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator||;
        auto Timer = Net::steady_timer(co_await Net::this_coro::executor);
        Timer.expires_after(std::chrono::seconds(4));
        boost::system::error_code ReceiveError;
        const auto Outcome = co_await (
            State->DrainStarted.async_receive(
                Net::redirect_error(Net::use_awaitable, ReceiveError)) ||
            Timer.async_wait(Net::use_awaitable));
        if (Outcome.index() != 0U || ReceiveError)
        {
            Observed = false;
            co_return;
        }
        const auto Window = State->Window;
        Observed = Window &&
            Window->ReadyOrFailed.load(std::memory_order_acquire) >= Window->Lanes;
    }

    inline auto CollectRealScenarioResult(const std::shared_ptr<RealRootState> &State)
        -> RealScenarioResult
    {
        RealScenarioResult Result;
        Result.Mode = State->Mode;
        Result.Failure = static_cast<bool>(State->Failure);
        Result.FailureMessage = State->FailureMessage;
        Result.Authenticated = State->Authenticated;
        Result.LiteralValid = State->LiteralValid;
        Result.BackendPeerClosed = State->BackendPeerClosed;
        Result.ClientPeerClosed = State->ClientPeerClosed;
        Result.RootFinished = State->RootFinished;
        Result.Drained = State->Drained;
        Result.QuotaZero = State->QuotaZero;
        Result.WeakExpired = State->WeakExpired;
        Result.Ready = State->MeasureReady.load(std::memory_order_acquire);
        Result.ScenarioCompleted = State->ScenarioCompleted.load(std::memory_order_acquire);
        Result.Exited = State->Exited.load(std::memory_order_acquire);
        Result.Diagnostic = State->Diagnostic;
        Result.DiagnosticRound = State->DiagnosticRound;
        Result.DiagnosticLane = State->DiagnosticLane;
        Result.DiagnosticStages = State->DiagnosticStages.load(std::memory_order_acquire);
        Result.ReadyOrFailed = State->Window
            ? State->Window->ReadyOrFailed.load(std::memory_order_acquire)
            : 0U;
        Result.MeasureCompleted = State->Window
            ? State->Window->MeasureCompleted.load(std::memory_order_acquire)
            : 0U;
        Result.MeasureFailed = State->Window
            ? State->Window->MeasureFailed.load(std::memory_order_acquire)
            : 0U;
        Result.BackendBytes = State->BackendBytes;
        Result.Dials = State->Dials;
        Result.FirstConnections = State->FirstConnections;
        Result.FirstStreams = State->FirstStreams;
        Result.OrdinaryCalls = State->OrdinaryCalls;
        Result.OrdinaryBytes = State->OrdinaryBytes;
        Result.AlignedCalls = State->AlignedCalls;
        Result.AlignedBytes = State->AlignedBytes;
        Result.BackendHash = State->BackendHash;
        Result.ExpectedHash = State->ExpectedHash;
        Result.Report = State->Report;
        return Result;
    }

    inline auto RealScenario(
        const RealRootMode Mode,
        const std::string_view Name,
        const bool InvalidPassword = false) -> RealScenarioResult
    {
        Net::io_context IoContext;
        auto State = MakeRealRootState(Mode, IoContext.get_executor());
        State->InvalidPassword = InvalidPassword;
        State->ExpectedHash = ExpectedRealHash();
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, RunRealScenario(State),
            [&Failure, State](std::exception_ptr Error)
            {
                Failure = Error;
                State->ScenarioCompleted.store(true, std::memory_order_release);
            });
        IoContext.run();
        State->Exited.store(true, std::memory_order_release);
        if (Failure)
        {
            State->Failure = Failure;
        }
        // 状态中的 socket、executor 与 channel 全部先于 IoContext 析构；只在此作用域审验。
        return CollectRealScenarioResult(State);
    }

    inline auto PrintRealReport(const std::string_view Name, const RealScenarioResult &Result) -> void
    {
        std::printf(
            "%.*s real-root bytes=%zu hash=%llu literal=%d halfclose=%d drain=%d quota0=%d weak=%d "
            "client_eof=%d dials=%zu throughput=%.1f p50=%.3f p95=%.3f p99=%.3f samples=%zu "
            "ordinary_new=%zu/%zu aligned_new=%zu/%zu\n",
            static_cast<int>(Name.size()), Name.data(), Result.Report.Bytes,
            static_cast<unsigned long long>(Result.BackendHash), Result.LiteralValid ? 1 : 0,
            Result.BackendPeerClosed ? 1 : 0, Result.Drained ? 1 : 0, Result.QuotaZero ? 1 : 0,
            Result.WeakExpired ? 1 : 0, Result.ClientPeerClosed ? 1 : 0, Result.Dials,
            Result.Report.Mbps, Result.Report.LatencyP50, Result.Report.LatencyP95,
            Result.Report.LatencyP99, Result.Report.Samples, Result.OrdinaryCalls,
            Result.OrdinaryBytes, Result.AlignedCalls, Result.AlignedBytes);
    }

    inline auto PrintRealDiagnosticSummary(const std::string_view Name,
                                           const RealScenarioResult &Result) -> void
    {
        if (!Result.Diagnostic)
        {
            return;
        }
        const auto Mode = RealRootModeName(Result.Mode);
        std::printf(
            "real-root-matrix diagnostic-only=1 mode=%.*s round=%zu lane=%zu stage-mask=0x%08x exception=%d failure=%s\n",
            static_cast<int>(Mode.size()), Mode.data(), Result.DiagnosticRound,
            Result.DiagnosticLane, Result.DiagnosticStages, Result.Failure ? 1 : 0,
            Result.FailureMessage.empty() ? "" : Result.FailureMessage.c_str());
        std::printf("real-root-matrix diagnostic-only=1 identity=%.*s\n",
                    static_cast<int>(Name.size()), Name.data());
        std::fflush(stdout);
    }

    inline auto RealRootModeName(const RealRootMode Mode) -> std::string_view
    {
        switch (Mode)
        {
        case RealRootMode::Smux:
            return "smux";
        case RealRootMode::Yamux:
            return "yamux";
        case RealRootMode::H2Mux:
            return "h2mux";
        }
        return "unknown";
    }

    struct RealMatrixCompletion final
    {
        std::shared_ptr<RealRootState> State;
        std::exception_ptr *Failure;

        inline auto operator()(std::exception_ptr Error) const -> void
        {
            *Failure = Error;
            if (Error)
            {
                State->Failure = Error;
                State->Harness->Stop();
            }
            if (State->MeasureTerminal.load(std::memory_order_acquire) ==
                RealMeasureTerminal::Pending)
            {
                MarkRealMeasureFailure(State);
            }
            State->ScenarioCompleted.store(true, std::memory_order_release);
        }
    };

    inline auto RunRealMatrixLane(const std::shared_ptr<RealRootState> &State,
                           const std::shared_ptr<Net::io_context> &IoContext) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(*IoContext, RunRealScenario(State),
            RealMatrixCompletion{State, &Failure});
        IoContext->run();
        if (Failure)
        {
            State->Failure = Failure;
        }
        if (!State->ScenarioCompleted.load(std::memory_order_acquire))
        {
            State->FailureMessage = "matrix lane io_context returned before scenario completion";
            State->Failure = std::make_exception_ptr(std::runtime_error(State->FailureMessage));
        }
        State->Exited.store(true, std::memory_order_release);
        State->Window->ExitedLanes.fetch_add(1U, std::memory_order_acq_rel);
        NotifyRealMeasureWindow(State->Window);
    }

    inline auto RunRealMatrix(const RealMatrixRequest Request) -> RealMatrixResult
    {
        const auto Budget = Request.Budget ? Request.Budget : MakeRealMatrixBudget();
        auto Window = std::make_shared<RealMeasureWindow>(Request.Lanes);
        std::vector<RealMatrixLane> MatrixLanes;
        MatrixLanes.reserve(Request.Lanes);
        for (std::size_t Lane = 0; Lane < Request.Lanes; ++Lane)
        {
            auto Context = std::make_shared<Net::io_context>();
            auto State = MakeRealRootState(Request.Mode, Context->get_executor());
            State->ExpectedHash = ExpectedRealHash();
            State->Window = Window;
            State->Diagnostic = Request.Diagnostic;
            State->DiagnosticRound = Request.Round;
            State->DiagnosticLane = Lane + 1U;
            State->FailurePoint = Request.FailurePoint;
            MatrixLanes.push_back(RealMatrixLane{std::move(Context), std::move(State), {}, false});
        }
        RealMatrixResult Result;
        std::thread Sampler;
        PrepareRealMatrixSampler(RealMatrixSamplerRequest{
            &Request, Window, &MatrixLanes, &Result, &Sampler, Budget});
        std::chrono::steady_clock::time_point Started;
        std::chrono::steady_clock::time_point Finished;
        if (!Result.ThreadCreationFailed)
        {
            StartRealMatrixLanes(MatrixLanes, Request, Result);
        }
        if (!Result.ThreadCreationFailed)
        {
            Result.Prepared = true;
            const auto Ready = WaitRealMatrixReady(Window, Budget->WorkDeadline);
            if (!Ready)
            {
                Result.DeadlineExceeded = true;
                PrintRealMatrixLaneTimeout(MatrixLanes, "ready");
                CancelRealMatrixLanes(MatrixLanes, "real matrix ready deadline exceeded");
            }
            else if (Window->SamplerFailed.load(std::memory_order_acquire))
            {
                Result.SamplerFailed = true;
                CancelRealMatrixLanes(MatrixLanes, "real matrix sampler failed");
            }
            else if (Window->Ready.load(std::memory_order_acquire) != MatrixLanes.size() &&
                     !RealMatrixWindowComplete(Window))
            {
                CancelRealMatrixLanes(MatrixLanes, "real matrix ready gate failed");
            }
            else
            {
                std::optional<PrismMuxPerfAllocation::Scope> AllocationScope;
                Started = std::chrono::steady_clock::now();
                if (!Request.Diagnostic)
                {
                    Window->Before = CurrentRealProcessMetrics();
                    AllocationScope.emplace();
                    Window->BeginNanoseconds.store(Started.time_since_epoch().count(), std::memory_order_release);
                    Window->Active.store(true, std::memory_order_release);
                }
                for (const auto &Lane : MatrixLanes)
                {
                    PostRealGate(Lane.State, RealGate::Start);
                }
                if (!WaitRealMatrixOutcome(Window, Budget->WorkDeadline))
                {
                    Result.DeadlineExceeded = true;
                    PrintRealMatrixLaneTimeout(MatrixLanes, "transfer");
                    CancelRealMatrixLanes(MatrixLanes, "real matrix transfer deadline exceeded");
                }
                else if (Window->SamplerFailed.load(std::memory_order_acquire))
                {
                    Result.SamplerFailed = true;
                    CancelRealMatrixLanes(MatrixLanes, "real matrix sampler failed");
                }
                if (!Request.Diagnostic)
                {
                    Finished = std::chrono::steady_clock::now();
                    Window->EndNanoseconds.store(Finished.time_since_epoch().count(), std::memory_order_release);
                    Window->Active.store(false, std::memory_order_release);
                    PrismMuxPerfAllocation::Active.store(false, std::memory_order_release);
                    Window->After = CurrentRealProcessMetrics();
                }
                for (const auto &Lane : MatrixLanes)
                {
                    PostRealGate(Lane.State, RealGate::End);
                }
            }
        }
        const auto Bytes = FinalizeRealMatrix(RealMatrixFinalizeRequest{
            &MatrixLanes, &Request, &Result, Window, &Sampler, Budget});
        if (!Request.Diagnostic && !Result.DeadlineExceeded && !Result.ThreadCreationFailed &&
            Window->Ready.load(std::memory_order_acquire) == MatrixLanes.size())
        {
            PrintRealMatrixReport(RealMatrixSummary{
                Request.Mode, Request.Lanes, Request.Round, Window, Bytes,
                Finished > Started ? std::chrono::duration<double>(Finished - Started).count() : 0.0});
        }
        return Result;
    }

    [[nodiscard]] inline auto IsRealMatrixDiagnosticEnabled() noexcept -> bool
    {
        const auto *Value = std::getenv("PRISM_MUX_MATRIX_DIAG");
        return Value != nullptr && std::string_view(Value) == "1";
    }
} // namespace Prism::Testing::MuxRealRoot
