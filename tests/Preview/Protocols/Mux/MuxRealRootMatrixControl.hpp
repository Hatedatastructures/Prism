#pragma once

/**
 * @file MuxRealRootMatrixControl.hpp
 * @brief 真实 Mux Root 矩阵的 deadline、lane owner 和有界收口控制。
 * @details Matrix 与 Lifecycle 两个测试编译单元共同消费；所有 lane 都由此处持有，
 *          取消仍投递到 lane executor，未启动的 lane 不伪造 Exited。
 */

#include "MuxRealRootFixture.hpp"

namespace Preview::Testing::MuxRealRoot
{

    struct RealMatrixBudget final
    {
        using Clock = std::chrono::steady_clock;

        Clock::time_point WorkDeadline;
        Clock::time_point CloseDeadline;
    };

    [[nodiscard]] inline auto MakeRealMatrixBudget() -> std::shared_ptr<RealMatrixBudget>
    {
        const auto WorkDeadline = RealMatrixBudget::Clock::now() + std::chrono::seconds(50);
        return std::make_shared<RealMatrixBudget>(
            RealMatrixBudget{WorkDeadline, WorkDeadline + std::chrono::seconds(5)});
    }

    struct RealMatrixLane final
    {
        std::shared_ptr<Net::io_context> Context;
        std::shared_ptr<RealRootState> State;
        std::thread Thread;
        bool Started{false};
    };

    struct RealMatrixRequest final
    {
        RealRootMode Mode{RealRootMode::Smux};
        std::size_t Lanes{1};
        std::size_t Round{1};
        bool Diagnostic{false};
        RealMatrixFailurePoint FailurePoint{RealMatrixFailurePoint::None};
        std::size_t FailureLane{1};
        std::shared_ptr<RealMatrixBudget> Budget;
    };

    struct RealScenarioResult final
    {
        RealRootMode Mode{RealRootMode::Smux};
        bool Failure{false};
        std::string FailureMessage;
        bool Authenticated{false};
        bool LiteralValid{false};
        bool BackendPeerClosed{false};
        bool ClientPeerClosed{false};
        bool RootFinished{false};
        bool Drained{false};
        bool QuotaZero{false};
        bool WeakExpired{false};
        bool Ready{false};
        bool ScenarioCompleted{false};
        bool Exited{false};
        bool Diagnostic{false};
        std::size_t DiagnosticRound{0};
        std::size_t DiagnosticLane{0};
        std::uint32_t DiagnosticStages{0};
        std::size_t ReadyOrFailed{0};
        std::size_t MeasureCompleted{0};
        std::size_t MeasureFailed{0};
        std::size_t BackendBytes{0};
        std::size_t Dials{0};
        std::size_t FirstConnections{0};
        std::size_t FirstStreams{0};
        std::size_t OrdinaryCalls{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedCalls{0};
        std::size_t AlignedBytes{0};
        std::uint64_t BackendHash{0};
        std::uint64_t ExpectedHash{0};
        Preview::BenchReport Report{};
    };

    struct RealMatrixResult final
    {
        bool Prepared{false};
        bool DeadlineExceeded{false};
        bool ThreadCreationFailed{false};
        bool SamplerFailed{false};
        bool CloseTimedOut{false};
        std::size_t StartedLanes{0};
        std::size_t ExitedLanes{0};
        std::vector<RealScenarioResult> Lanes;
    };

    inline auto RunRealMatrixLane(const std::shared_ptr<RealRootState> &State,
                                  const std::shared_ptr<Net::io_context> &IoContext) -> void;
    inline auto CollectRealScenarioResult(const std::shared_ptr<RealRootState> &State)
        -> RealScenarioResult;
    inline auto PrintRealDiagnosticSummary(const std::string_view Name,
                                           const RealScenarioResult &Result) -> void;

    struct RealMatrixSummary final
    {
        RealRootMode Mode;
        std::size_t Lanes{0};
        std::size_t Round{0};
        std::shared_ptr<RealMeasureWindow> Window;
        std::size_t Bytes{0};
        double Seconds{0};
    };

    inline auto PrintRealMatrixReport(const RealMatrixSummary &Summary) -> void
    {
        const auto Throughput = Summary.Seconds > 0.0
            ? static_cast<double>(Summary.Bytes) / (1024.0 * 1024.0) / Summary.Seconds : 0.0;
        std::printf("real-root-matrix mode=%.*s lanes=%zu round=%zu bytes=%zu wall_seconds=%.6f wall_throughput=%.1f ordinary_new=%zu/%zu aligned_new=%zu/%zu\n",
                    static_cast<int>(RealRootModeName(Summary.Mode).size()),
                    RealRootModeName(Summary.Mode).data(), Summary.Lanes, Summary.Round,
                    Summary.Bytes, Summary.Seconds, Throughput,
                    PreviewMuxPerfAllocation::OrdinaryCalls.load(std::memory_order_relaxed),
                    PreviewMuxPerfAllocation::OrdinaryBytes.load(std::memory_order_relaxed),
                    PreviewMuxPerfAllocation::AlignedCalls.load(std::memory_order_relaxed),
                    PreviewMuxPerfAllocation::AlignedBytes.load(std::memory_order_relaxed));
        if (Summary.Window->Before && Summary.Window->After)
        {
            std::printf("real-root-matrix cpu_user_delta_100ns=%lld cpu_kernel_delta_100ns=%lld commit_delta_bytes=%lld rss_before_bytes=%llu rss_after_bytes=%llu peak_working_set_bytes=%llu peak_commit_bytes=%llu samples=%llu sample_interval_ms=1\n",
                        static_cast<long long>(Summary.Window->After->UserTime100ns) -
                            static_cast<long long>(Summary.Window->Before->UserTime100ns),
                        static_cast<long long>(Summary.Window->After->KernelTime100ns) -
                            static_cast<long long>(Summary.Window->Before->KernelTime100ns),
                        static_cast<long long>(Summary.Window->After->CommitBytes) -
                            static_cast<long long>(Summary.Window->Before->CommitBytes),
                        static_cast<unsigned long long>(Summary.Window->Before->WorkingSetBytes),
                        static_cast<unsigned long long>(Summary.Window->After->WorkingSetBytes),
                        static_cast<unsigned long long>(Summary.Window->PeakWorkingSet.load()),
                        static_cast<unsigned long long>(Summary.Window->PeakCommit.load()),
                        static_cast<unsigned long long>(Summary.Window->Samples.load()));
        }
        else
        {
            std::puts("real-root-matrix process_metrics=unavailable");
        }
        std::puts("real-root-matrix process_metric_boundary=1ms sampler is warmed before Start, samples are filtered to the shared window, and sampler CPU/RSS effects remain included in the window deltas");
        std::puts("real-root-matrix allocation_boundary=ordinary and aligned process-wide new/new[] requested bytes during the shared transfer window; setup, cleanup, allocator retention and native DLL allocations are excluded");
    }

    [[nodiscard]] inline auto RealMatrixWindowReady(
        const std::shared_ptr<RealMeasureWindow> &Window) -> bool
    {
        return Window->SamplerFailed.load(std::memory_order_acquire) ||
               Window->ReadyOrFailed.load(std::memory_order_acquire) >= Window->Lanes;
    }

    [[nodiscard]] inline auto RealMatrixWindowComplete(
        const std::shared_ptr<RealMeasureWindow> &Window) -> bool
    {
        return Window->SamplerFailed.load(std::memory_order_acquire) ||
               Window->MeasureCompleted.load(std::memory_order_acquire) +
                   Window->MeasureFailed.load(std::memory_order_acquire) >=
               Window->Lanes;
    }

    inline auto WaitRealMatrixReady(const std::shared_ptr<RealMeasureWindow> &Window,
                                    const RealMatrixBudget::Clock::time_point Deadline) -> bool
    {
        std::unique_lock Lock(Window->GateMutex);
        return Window->GateChanged.wait_until(Lock, Deadline,
                                              [&Window] { return RealMatrixWindowReady(Window); });
    }

    inline auto WaitRealMatrixOutcome(const std::shared_ptr<RealMeasureWindow> &Window,
                                      const RealMatrixBudget::Clock::time_point Deadline) -> bool
    {
        std::unique_lock Lock(Window->GateMutex);
        return Window->GateChanged.wait_until(
            Lock, Deadline, [&Window] { return RealMatrixWindowComplete(Window); });
    }

    inline auto WaitRealSamplerReady(const std::shared_ptr<RealMeasureWindow> &Window,
                                     const RealMatrixBudget::Clock::time_point Deadline) -> bool
    {
        std::unique_lock Lock(Window->GateMutex);
        return Window->GateChanged.wait_until(
            Lock, Deadline,
            [&Window] { return Window->SamplerReady.load(std::memory_order_acquire); });
    }

    inline auto WaitRealSamplerExit(const std::shared_ptr<RealMeasureWindow> &Window,
                                    const RealMatrixBudget::Clock::time_point Deadline) -> bool
    {
        std::unique_lock Lock(Window->GateMutex);
        return Window->GateChanged.wait_until(
            Lock, Deadline,
            [&Window] { return Window->SamplerExited.load(std::memory_order_acquire); });
    }

    inline auto CancelRealMatrixLane(RealMatrixLane &Lane, const std::string_view Message) -> void
    {
        if (!Lane.Started || !Lane.State || Lane.State->Exited.load(std::memory_order_acquire))
        {
            return;
        }
        auto OwnedMessage = std::string(Message);
        Net::post(Lane.Context->get_executor(), [State = Lane.State,
                                                  Message = std::move(OwnedMessage)]
        {
            CancelRealState(State, Message);
        });
    }

    inline auto CancelRealMatrixLanes(std::vector<RealMatrixLane> &Lanes,
                                      const std::string_view Message) -> void
    {
        for (auto &Lane : Lanes)
        {
            CancelRealMatrixLane(Lane, Message);
        }
    }

    inline auto StartRealMatrixLanes(std::vector<RealMatrixLane> &Lanes,
                                     const RealMatrixRequest &Request,
                                     RealMatrixResult &Result) -> void
    {
        for (std::size_t Lane = 0; Lane < Lanes.size(); ++Lane)
        {
            try
            {
                if (Request.FailurePoint == RealMatrixFailurePoint::ThreadCreation &&
                    Lane == Request.FailureLane)
                {
                    throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                            "injected matrix lane thread creation failure");
                }
                auto &LaneOwner = Lanes[Lane];
                LaneOwner.Thread = std::thread(RunRealMatrixLane, LaneOwner.State, LaneOwner.Context);
                LaneOwner.Started = true;
                ++Result.StartedLanes;
            }
            catch (...)
            {
                Result.ThreadCreationFailed = true;
                const auto Failure = std::current_exception();
                for (std::size_t Index = Lane; Index < Lanes.size(); ++Index)
                {
                    Lanes[Index].State->Failure = Failure;
                    Lanes[Index].State->FailureMessage =
                        "matrix lane thread creation failed before start";
                    MarkRealMeasureFailure(Lanes[Index].State);
                }
                CancelRealMatrixLanes(Lanes, "matrix lane thread creation cancellation");
                return;
            }
        }
    }

    struct RealMatrixSamplerRequest final
    {
        const RealMatrixRequest *Request;
        std::shared_ptr<RealMeasureWindow> Window;
        std::vector<RealMatrixLane> *Lanes;
        RealMatrixResult *Result;
        std::thread *Sampler;
        std::shared_ptr<RealMatrixBudget> Budget;
    };

    /**
     * @brief 创建并预热矩阵 sampler，处理 sampler 线程失败和 ready deadline。
     * @param Request sampler、lane failure 状态及工作预算。
     */
    inline auto PrepareRealMatrixSampler(RealMatrixSamplerRequest Request) -> void
    {
        if (Request.Request->Diagnostic)
        {
            return;
        }
        try
        {
            *Request.Sampler = std::thread(RunRealMetricSampler, Request.Window);
            if (!WaitRealSamplerReady(Request.Window, Request.Budget->WorkDeadline))
            {
                std::printf("real-root-matrix timeout=1 phase=sampler-ready action=abort\n");
                std::fflush(stdout);
                std::abort();
            }
            if (Request.Window->SamplerFailed.load(std::memory_order_acquire))
            {
                std::printf("real-root-matrix failure=1 phase=sampler-ready action=abort\n");
                std::fflush(stdout);
                std::abort();
            }
        }
        catch (...)
        {
            Request.Result->ThreadCreationFailed = true;
            const auto Failure = std::current_exception();
            for (const auto &Lane : *Request.Lanes)
            {
                Lane.State->Failure = Failure;
                Lane.State->FailureMessage = "matrix sampler thread creation failed";
                MarkRealMeasureFailure(Lane.State);
            }
        }
    }

    inline auto PrintRealMatrixLaneTimeout(const std::vector<RealMatrixLane> &Lanes,
                                           const std::string_view Phase) -> void
    {
        for (std::size_t Index = 0; Index < Lanes.size(); ++Index)
        {
            const auto &Lane = Lanes[Index];
            if (!Lane.State || Lane.State->Exited.load(std::memory_order_acquire))
            {
                continue;
            }
            std::printf(
                "real-root-matrix timeout=1 phase=%.*s lane=%zu started=%d ready=%d terminal=%u stages=0x%08x\n",
                static_cast<int>(Phase.size()), Phase.data(), Index + 1U, Lane.Started ? 1 : 0,
                Lane.State->MeasureReady.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned int>(Lane.State->MeasureTerminal.load(std::memory_order_acquire)),
                Lane.State->DiagnosticStages.load(std::memory_order_acquire));
        }
        std::fflush(stdout);
    }

    inline auto JoinRealMatrixLanes(
        std::vector<RealMatrixLane> &Lanes,
        const RealMatrixBudget::Clock::time_point Deadline) -> bool
    {
        std::size_t Started = 0;
        std::shared_ptr<RealMeasureWindow> Window;
        for (const auto &Lane : Lanes)
        {
            if (Lane.Started)
            {
                ++Started;
                Window = Lane.State->Window;
            }
        }
        if (Started != 0U)
        {
            std::unique_lock Lock(Window->GateMutex);
            const auto Exited = Window->GateChanged.wait_until(
                Lock, Deadline, [&Window, Started]
                {
                    return Window->ExitedLanes.load(std::memory_order_acquire) >= Started;
                });
            if (!Exited)
            {
                PrintRealMatrixLaneTimeout(Lanes, "close");
                std::printf("real-root-matrix timeout=1 phase=close action=abort\n");
                std::fflush(stdout);
                std::abort();
            }
        }
        for (auto &Lane : Lanes)
        {
            if (Lane.Thread.joinable())
            {
                Lane.Thread.join();
            }
        }
        return true;
    }

    inline auto CollectRealMatrixLanes(const std::vector<RealMatrixLane> &Lanes,
                                       const RealMatrixRequest &Request,
                                       RealMatrixResult &Result) -> std::size_t
    {
        std::size_t Bytes = 0;
        for (std::size_t Lane = 0; Lane < Lanes.size(); ++Lane)
        {
            if (Lanes[Lane].Started && Lanes[Lane].State->Exited.load(std::memory_order_acquire))
            {
                MarkRealDiagnosticStage(Lanes[Lane].State, RealDiagnosticStage::ThreadJoined);
            }
            const auto Name = std::string(RealRootModeName(Request.Mode)) + "-matrix-r" +
                              std::to_string(Request.Round) + "-lane" + std::to_string(Lane + 1U);
            const auto LaneResult = CollectRealScenarioResult(Lanes[Lane].State);
            PrintRealDiagnosticSummary(Name, LaneResult);
            Bytes += LaneResult.Report.Bytes;
            Result.ExitedLanes += LaneResult.Exited ? 1U : 0U;
            Result.Lanes.push_back(LaneResult);
        }
        return Bytes;
    }

    struct RealMatrixFinalizeRequest final
    {
        std::vector<RealMatrixLane> *Lanes;
        const RealMatrixRequest *Request;
        RealMatrixResult *Result;
        std::shared_ptr<RealMeasureWindow> Window;
        std::thread *Sampler;
        std::shared_ptr<RealMatrixBudget> Budget;
    };

    /**
     * @brief 收口矩阵 sampler、已启动 lane 线程和结果 collector。
     * @details 只等待真实 Exited lane；未启动 lane 不伪造退出，关闭预算与原矩阵一致。
     * @param Request 矩阵 lane、窗口、sampler 和预算 owner。
     * @return 所有 lane 收集到的有效字节数。
     */
    inline auto FinalizeRealMatrix(RealMatrixFinalizeRequest Request) -> std::size_t
    {
        if (Request.Window->SamplerFailed.load(std::memory_order_acquire))
        {
            Request.Result->SamplerFailed = true;
        }
        if (Request.Sampler->joinable())
        {
            Request.Window->StopSampler.store(true, std::memory_order_release);
            if (!WaitRealSamplerExit(Request.Window, Request.Budget->CloseDeadline))
            {
                std::printf("real-root-matrix timeout=1 phase=sampler-close action=abort\n");
                std::fflush(stdout);
                std::abort();
            }
            Request.Sampler->join();
        }
        Request.Result->CloseTimedOut = !JoinRealMatrixLanes(
            *Request.Lanes, Request.Budget->CloseDeadline);
        return CollectRealMatrixLanes(*Request.Lanes, *Request.Request, *Request.Result);
    }

} // namespace Preview::Testing::MuxRealRoot
