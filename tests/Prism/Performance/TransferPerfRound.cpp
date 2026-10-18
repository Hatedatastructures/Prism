/**
 * @file TransferPerfRound.cpp
 * @brief TransferPerf 模块所有者。
 */

#include "TransferPerf.hpp"

namespace TransferPerf
{
    class GlobalAllocationWindow final
    {
    public:
        GlobalAllocationWindow()
        {
            TransferPerfAllocation::Start();
        }

        ~GlobalAllocationWindow()
        {
            End();
        }

        auto End() noexcept -> void
        {
            if (!Active_)
            {
                return;
            }
            TransferPerfAllocation::Stop();
            Snapshot_ = TransferPerfAllocation::ReadSnapshot();
            Active_ = false;
        }

        [[nodiscard]] auto Stats() const noexcept -> TransferPerfAllocation::Snapshot
        {
            return Snapshot_;
        }

    private:
        bool Active_{true};
        TransferPerfAllocation::Snapshot Snapshot_{};
    };

    auto NowNs() -> std::int64_t;
    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void;
    auto FillPayload(std::span<std::byte> Buffer, std::size_t Offset) -> void;
    [[nodiscard]] auto IsCleanEof(const std::error_code &ErrorCode) -> bool;
    [[nodiscard]] auto EndpointRead(const EndpointReadRequest &Request)
        -> Net::awaitable<std::pair<std::error_code, std::size_t>>;
    [[nodiscard]] auto EndpointWrite(IoEndpoint &Endpoint, IoMode Mode,
                                     std::span<const std::byte> Buffer)
        -> Net::awaitable<std::pair<std::error_code, std::size_t>>;
    [[nodiscard]] auto RunProcessSampler(
        ProcessSamplerRequest Request) -> Net::awaitable<void>;
    [[nodiscard]] auto MakeEndpoint(IoMode Mode, std::shared_ptr<Prism::Transport::Reliable> Reliable)
        -> IoEndpoint;
    auto SignalLaneReady(const LaneReadyRequest &Request) -> void;
    [[nodiscard]] auto ModeName(IoMode Mode) -> const char *;
    auto AddAllocationStats(
        IoCompareResult &Result,
        const AllocationStats &Allocation) -> void
    {
        Result.OrdinaryAllocations += Allocation.OrdinaryAllocations;
        Result.AlignedAllocations += Allocation.AlignedAllocations;
        Result.OrdinaryBytes += Allocation.OrdinaryBytes;
        Result.AlignedBytes += Allocation.AlignedBytes;
    }

    auto AddAllocationStats(
        IoCompareResult &Result,
        const IoCompareResult &Source) -> void
    {
        Result.OrdinaryAllocations += Source.OrdinaryAllocations;
        Result.AlignedAllocations += Source.AlignedAllocations;
        Result.OrdinaryBytes += Source.OrdinaryBytes;
        Result.AlignedBytes += Source.AlignedBytes;
    }

    struct CompareServerState;

    struct CompareServerRequest final
    {
        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        IoMode Mode{IoMode::Direct};
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::shared_ptr<GateChannel> Start;
    };

    struct CompareLaneBodyRequest final
    {
        IoMode Mode{IoMode::Direct};
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::size_t LaneIndex{0};
        std::shared_ptr<LaneSignalChannel> Ready;
        std::shared_ptr<std::atomic_bool> ReadySignaled;
        std::shared_ptr<GateChannel> StartGate;
        std::shared_ptr<CompareServerState> ServerState;
    };

    struct CompareLaneRequest final
    {
        IoMode Mode{IoMode::Direct};
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::size_t LaneIndex{0};
        std::shared_ptr<LaneSignalChannel> Ready;
        std::shared_ptr<std::atomic_bool> ReadySignaled;
        std::shared_ptr<GateChannel> StartGate;
        std::shared_ptr<IoCompareResultChannel> Done;
        std::shared_ptr<GateChannel> End;
    };

    struct CompareLaneTaskRequest final
    {
        CompareLaneRequest Lane;
        std::shared_ptr<LaneSignalChannel> Exited;
        bool InjectStartupFailure{false};
    };

    struct CompareServerState final
    {
        explicit CompareServerState(Net::any_io_executor Executor)
            : Acceptor(std::make_shared<Net::ip::tcp::acceptor>(
                  Executor, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0))),
              Done(std::make_shared<IoCompareResultChannel>(Executor, 1))
        {
        }

        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        std::shared_ptr<IoCompareResultChannel> Done;
        IoCompareResult Result;
        bool Started{false};
        bool Joined{false};
    };

    [[nodiscard]] auto WaitCompareServer(
        const std::shared_ptr<CompareServerState> &State) -> Net::awaitable<IoCompareResult>
    {
        if (State->Joined)
        {
            co_return State->Result;
        }
        State->Joined = true;
        if (!State->Started)
        {
            ++State->Result.Errors;
            co_return State->Result;
        }
        boost::system::error_code CompletionError;
        State->Result = co_await State->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        if (CompletionError)
        {
            ++State->Result.Errors;
        }
        co_return State->Result;
    }

    [[nodiscard]] auto RunCompareServer(CompareServerRequest Request)
        -> Net::awaitable<IoCompareResult>
    {
        IoCompareResult Result;
        Net::ip::tcp::socket Socket(Request.Acceptor->get_executor());
        boost::system::error_code AcceptError;
        co_await Request.Acceptor->async_accept(
            Socket, Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError)
        {
            ++Result.Errors;
            co_return Result;
        }
        auto Endpoint = MakeEndpoint(
            Request.Mode, std::make_shared<Prism::Transport::Reliable>(std::move(Socket)));
        Result.ExpectedInputHash = Request.ExpectedInputHash;
        boost::system::error_code StartError;
        co_await Request.Start->async_receive(
            Net::redirect_error(Net::use_awaitable, StartError));
        if (StartError)
        {
            Endpoint.Reliable->Close();
            ++Result.Errors;
            co_return Result;
        }
        AllocationStats Allocation;
        CountingResource Resource(Allocation);
        const auto BlockCount =
            (Request.BlockSize + sizeof(AlignedPayload) - 1U) / sizeof(AlignedPayload);
        std::pmr::vector<AlignedPayload> BufferStorage(BlockCount, &Resource);
        auto Buffer = std::as_writable_bytes(std::span<AlignedPayload>(BufferStorage));
        while (Result.Received < Request.TotalBytes)
        {
            const auto Limit = std::min(
                Request.BlockSize, Request.TotalBytes - Result.Received);
            const auto [ErrorCode, Count] = co_await EndpointRead(
                EndpointReadRequest{Endpoint, Request.Mode, Buffer.first(Limit), nullptr});
            if (ErrorCode || Count == 0 || Count > Limit)
            {
                AddAllocationStats(Result, Allocation);
                ++Result.Errors;
                co_return Result;
            }
            if (Count < Limit)
            {
                ++Result.Partial;
            }
            Result.Received += Count;
            HashBytes(Result.ServerInputHash,
                      std::span<const std::byte>(Buffer).first(Count));
            std::size_t Echoed = 0;
            while (Echoed < Count)
            {
                const auto [WriteError, Written] = co_await EndpointWrite(
                    Endpoint, Request.Mode,
                    std::span<const std::byte>(Buffer).subspan(Echoed, Count - Echoed));
                if (WriteError || Written == 0 || Written > Count - Echoed)
                {
                    AddAllocationStats(Result, Allocation);
                    ++Result.Errors;
                    co_return Result;
                }
                if (Written < Count - Echoed)
                {
                    ++Result.Partial;
                }
                Echoed += Written;
                Result.Sent += Written;
            }
        }
        Endpoint.Reliable->Shutdown();
        std::array<std::byte, 2> PeerFin{};
        const auto [PeerError, PeerCount] = co_await EndpointRead(
            EndpointReadRequest{Endpoint, Request.Mode, PeerFin, nullptr});
        if (PeerCount != 0 || !IsCleanEof(PeerError))
        {
            AddAllocationStats(Result, Allocation);
            ++Result.Errors;
            Endpoint.Reliable->Close();
            co_return Result;
        }
        Endpoint.Reliable->Close();
        AddAllocationStats(Result, Allocation);
        Result.Completed = Result.ServerInputHash == Result.ExpectedInputHash;
        co_return Result;
    }

    [[nodiscard]] auto RunCompareLaneBody(
        CompareLaneBodyRequest Request) -> Net::awaitable<IoCompareResult>
    {
        auto ClientSocket = std::make_shared<Prism::Transport::Reliable>(
            Request.ServerState->Acceptor->get_executor());
        const auto Port = Request.ServerState->Acceptor->local_endpoint().port();
        const auto ConnectError = co_await ClientSocket->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
        if (ConnectError)
        {
            SignalLaneReady(LaneReadyRequest{
                Request.Ready, Request.ReadySignaled, Request.LaneIndex, false});
            IoCompareResult Result;
            ++Result.Errors;
            co_return Result;
        }
        auto Endpoint = MakeEndpoint(Request.Mode, std::move(ClientSocket));
        SignalLaneReady(LaneReadyRequest{
            Request.Ready, Request.ReadySignaled, Request.LaneIndex, true});
        boost::system::error_code StartError;
        co_await Request.StartGate->async_receive(
            Net::redirect_error(Net::use_awaitable, StartError));
        if (StartError)
        {
            Endpoint.Reliable->Close();
            IoCompareResult Result;
            ++Result.Errors;
            co_return Result;
        }
        AllocationStats Allocation;
        CountingResource Resource(Allocation);
        const auto BlockCount =
            (Request.BlockSize + sizeof(AlignedPayload) - 1U) / sizeof(AlignedPayload);
        std::pmr::vector<AlignedPayload> ChunkStorage(BlockCount, &Resource);
        auto Chunk = std::as_writable_bytes(std::span<AlignedPayload>(ChunkStorage));
        std::pmr::vector<std::byte> Received(Request.BlockSize, &Resource);
        IoCompareResult Result;
        Result.ExpectedInputHash = Request.ExpectedInputHash;
        while (Result.Sent < Request.TotalBytes)
        {
            const auto BlockBytes = std::min(
                Request.BlockSize, Request.TotalBytes - Result.Sent);
            FillPayload(Chunk.first(BlockBytes), Result.Sent);
            std::size_t BlockSent = 0;
            std::size_t BlockReceived = 0;
            bool BlockValid = true;
            const auto BlockStart = NowNs();
            while (BlockSent < BlockBytes)
            {
                const auto [ErrorCode, Count] = co_await EndpointWrite(
                    Endpoint, Request.Mode,
                    std::span<const std::byte>(Chunk).subspan(BlockSent, BlockBytes - BlockSent));
                if (ErrorCode || Count == 0 || Count > BlockBytes - BlockSent)
                {
                    BlockValid = false;
                    ++Result.Errors;
                    break;
                }
                if (Count < BlockBytes - BlockSent)
                {
                    ++Result.Partial;
                }
                BlockSent += Count;
            }
            while (BlockValid && BlockReceived < BlockBytes)
            {
                const auto [ReadError, ReadCount] = co_await EndpointRead(
                    EndpointReadRequest{
                        Endpoint, Request.Mode,
                        std::span<std::byte>(Received).subspan(
                            BlockReceived, BlockBytes - BlockReceived), nullptr});
                if (ReadError || ReadCount == 0 || ReadCount > BlockBytes - BlockReceived)
                {
                    BlockValid = false;
                    ++Result.Errors;
                    break;
                }
                if (ReadCount < BlockBytes - BlockReceived)
                {
                    ++Result.Partial;
                }
                for (std::size_t Index = 0; Index < ReadCount; ++Index)
                {
                    if (Received[BlockReceived + Index] != Chunk[BlockReceived + Index])
                    {
                        BlockValid = false;
                        ++Result.Errors;
                        break;
                    }
                }
                HashBytes(Result.ClientOutputHash,
                          std::span<const std::byte>(Received).subspan(
                              BlockReceived, ReadCount));
                BlockReceived += ReadCount;
            }
            Result.Sent += BlockSent;
            Result.Received += BlockReceived;
            if (!BlockValid || BlockSent != BlockBytes || BlockReceived != BlockBytes)
            {
                break;
            }
            Result.BlockSamples.push_back(NowNs() - BlockStart);
        }
        Endpoint.Reliable->Shutdown();
        std::array<std::byte, 2> PeerFin{};
        const auto [PeerError, PeerCount] = co_await EndpointRead(
            EndpointReadRequest{Endpoint, Request.Mode, PeerFin, nullptr});
        if (PeerCount != 0 || !IsCleanEof(PeerError))
        {
            ++Result.Errors;
        }
        Endpoint.Reliable->Close();
        AddAllocationStats(Result, Allocation);
        co_return Result;
    }

    auto HoldCompareResult(
        const std::shared_ptr<IoCompareResultChannel> &Done,
        const std::shared_ptr<GateChannel> &End,
        IoCompareResult Result) -> Net::awaitable<void>
    {
        (void)Done->try_send(boost::system::error_code{}, std::move(Result));
        (void)co_await End->async_receive(Net::use_awaitable);
        co_return;
    }

    [[nodiscard]] auto RunCompareLane(
        CompareLaneRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        IoCompareResult Result;
        std::exception_ptr Failure;
        const auto ServerState = std::make_shared<CompareServerState>(Executor);
        try
        {
            Net::co_spawn(
                ServerState->Acceptor->get_executor(),
                RunCompareServer(CompareServerRequest{
                    ServerState->Acceptor, Request.Mode, Request.TotalBytes,
                    Request.BlockSize, Request.ExpectedInputHash, Request.StartGate}),
                [ServerState](std::exception_ptr Exception, IoCompareResult ServerResult)
                {
                    if (Exception)
                    {
                        ++ServerResult.Errors;
                    }
                    (void)ServerState->Done->try_send(
                        boost::system::error_code{}, std::move(ServerResult));
                });
            ServerState->Started = true;
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        if (!Failure)
        {
            try
            {
                Result = co_await RunCompareLaneBody(
                    CompareLaneBodyRequest{
                        Request.Mode, Request.TotalBytes, Request.BlockSize,
                        Request.ExpectedInputHash, Request.LaneIndex,
                        Request.Ready, Request.ReadySignaled, Request.StartGate, ServerState});
            }
            catch (...)
            {
                Failure = std::current_exception();
            }
        }
        if (Failure)
        {
            SignalLaneReady(LaneReadyRequest{
                Request.Ready, Request.ReadySignaled, Request.LaneIndex, false});
            ++Result.Errors;
        }
        boost::system::error_code CloseError;
        // 客户端异常后先关闭入口，再等待真实 server completion，避免遗留 accept/read 协程。
        ServerState->Acceptor->close(CloseError);
        const auto ServerResult = co_await WaitCompareServer(ServerState);
        Result.LaneId = Request.LaneIndex;
        Result.ExpectedInputHash = Request.ExpectedInputHash;
        Result.ServerInputHash = ServerResult.ServerInputHash;
        Result.ServerCompleted = ServerResult.Completed;
        Result.Completed = !Failure && Result.Errors == 0 &&
                           Result.Sent == Request.TotalBytes &&
                           Result.Received == Request.TotalBytes && ServerResult.Completed &&
                           Result.ExpectedInputHash == ServerResult.ExpectedInputHash &&
                           Result.ServerInputHash == Result.ExpectedInputHash &&
                           Result.ClientOutputHash == Result.ExpectedInputHash;
        Result.Errors += ServerResult.Errors;
        Result.Partial += ServerResult.Partial;
        AddAllocationStats(Result, ServerResult);
        co_await HoldCompareResult(Request.Done, Request.End, std::move(Result));
        co_return;
    }

    [[nodiscard]] auto RunCompareLaneTask(
        CompareLaneTaskRequest Request) -> Net::awaitable<void>
    {
        bool Failed = false;
        try
        {
            if (Request.InjectStartupFailure)
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
            co_await RunCompareLane(Request.Lane);
        }
        catch (...)
        {
            Failed = true;
            SignalLaneReady(LaneReadyRequest{
                Request.Lane.Ready, Request.Lane.ReadySignaled,
                Request.Lane.LaneIndex, false});
        }
        if (Failed)
        {
            IoCompareResult Result;
            Result.LaneId = Request.Lane.LaneIndex;
            ++Result.Errors;
            co_await HoldCompareResult(Request.Lane.Done, Request.Lane.End,
                                        std::move(Result));
        }
        (void)Request.Exited->try_send(
            boost::system::error_code{}, Request.Lane.LaneIndex);
    }

    struct CompareRoundRuntime final
    {
        CompareRoundRequest Request;
        Net::any_io_executor Executor;
        std::shared_ptr<IoCompareResultChannel> Done;
        std::shared_ptr<LaneSignalChannel> Ready;
        std::shared_ptr<GateChannel> Start;
        std::shared_ptr<GateChannel> End;
        std::shared_ptr<LaneSignalChannel> Exited;
        std::array<bool, 4> LaneSpawned{};
        std::array<bool, 4> ReadyReceived{};
        std::array<bool, 4> ReadyPassed{};
        std::array<IoCompareResult, 4> LaneResults{};
        std::array<bool, 4> LaneReceived{};
        std::array<bool, 4> EndSent{};
        std::array<bool, 4> ExitedReceived{};
        bool StartupFailure{false};
        bool CoordinatorFailure{false};
    };

    auto SpawnCompareLanes(CompareRoundRuntime &State) -> void
    {
        for (std::size_t Index = 0; Index < State.Request.LaneCount; ++Index)
        {
            const auto ReadySignaled = std::make_shared<std::atomic_bool>(false);
            try
            {
                Net::co_spawn(
                    State.Executor,
                    RunCompareLaneTask(CompareLaneTaskRequest{
                        CompareLaneRequest{State.Request.Mode, State.Request.TotalBytes,
                                           State.Request.BlockSize,
                                           State.Request.ExpectedInputHash, Index, State.Ready,
                                           ReadySignaled, State.Start, State.Done, State.End},
                        State.Exited, State.Request.InjectStartupFailure}),
                    Net::detached);
                State.LaneSpawned[Index] = true;
            }
            catch (...)
            {
                SignalLaneReady(LaneReadyRequest{State.Ready, ReadySignaled, Index, false});
                IoCompareResult Result;
                Result.LaneId = Index;
                ++Result.Errors;
                (void)State.Done->try_send(boost::system::error_code{}, std::move(Result));
            }
        }
    }

    auto CollectCompareReady(CompareRoundRuntime &State) -> Net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < State.Request.LaneCount; ++Index)
        {
            boost::system::error_code ReadyError;
            const auto ReadyIndex = co_await State.Ready->async_receive(
                Net::redirect_error(Net::use_awaitable, ReadyError));
            if (ReadyError || ReadyIndex >= State.Request.LaneCount ||
                State.ReadyReceived[ReadyIndex])
            {
                State.StartupFailure = true;
                continue;
            }
            State.ReadyReceived[ReadyIndex] = true;
            State.ReadyPassed[ReadyIndex] = true;
        }
    }

    auto CollectCompareDone(CompareRoundRuntime &State) -> Net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < State.Request.LaneCount; ++Index)
        {
            boost::system::error_code DoneError;
            auto Result = co_await State.Done->async_receive(
                Net::redirect_error(Net::use_awaitable, DoneError));
            if (DoneError || Result.LaneId >= State.Request.LaneCount ||
                State.LaneReceived[Result.LaneId])
            {
                State.CoordinatorFailure = true;
                continue;
            }
            State.LaneResults[Result.LaneId] = std::move(Result);
            State.LaneReceived[State.LaneResults[Result.LaneId].LaneId] = true;
        }
    }

    auto ReleaseCompareLanes(CompareRoundRuntime &State) -> Net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < State.Request.LaneCount; ++Index)
        {
            if (State.LaneSpawned[Index])
            {
                State.EndSent[Index] = State.End->try_send(boost::system::error_code{});
                State.CoordinatorFailure = State.CoordinatorFailure || !State.EndSent[Index];
            }
        }
        for (std::size_t Index = 0; Index < State.Request.LaneCount; ++Index)
        {
            if (State.LaneSpawned[Index])
            {
                boost::system::error_code ExitedError;
                const auto ExitedIndex = co_await State.Exited->async_receive(
                    Net::redirect_error(Net::use_awaitable, ExitedError));
                if (ExitedError || ExitedIndex >= State.Request.LaneCount ||
                    State.ExitedReceived[ExitedIndex])
                {
                    State.CoordinatorFailure = true;
                    continue;
                }
                State.ExitedReceived[ExitedIndex] = true;
            }
        }
    }

    [[nodiscard]] auto RunIoCompareRound(
        CompareRoundRequest Request) -> Net::awaitable<IoCompareResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        CompareRoundRuntime State{
            Request, Executor,
            std::make_shared<IoCompareResultChannel>(Executor, Request.LaneCount),
            std::make_shared<LaneSignalChannel>(Executor, Request.LaneCount),
            std::make_shared<GateChannel>(Executor, Request.LaneCount * 2U),
            std::make_shared<GateChannel>(Executor, Request.LaneCount),
            std::make_shared<LaneSignalChannel>(Executor, Request.LaneCount)};
        SpawnCompareLanes(State);
        co_await CollectCompareReady(State);
#ifdef _WIN32
        const auto ProcessBefore = SampleProcess();
#endif
        const auto SamplerState = std::make_shared<ProcessSamplerState>();
        const auto SamplerStarted = std::make_shared<GateChannel>(Executor, 1);
        const auto SamplerStart = std::make_shared<GateChannel>(Executor, 1);
        const auto SamplerDone = std::make_shared<GateChannel>(Executor, 1);
        Net::co_spawn(
            Executor,
            RunProcessSampler(
                ProcessSamplerRequest{SamplerState, SamplerStarted, SamplerStart, SamplerDone}),
            Net::detached);
        co_await SamplerStarted->async_receive(Net::use_awaitable);
        GlobalAllocationWindow AllocationWindow;
        const auto BusinessStart = NowNs();
        (void)SamplerStart->try_send(boost::system::error_code{});
        for (std::size_t Index = 0; Index < Request.LaneCount * 2U; ++Index)
        {
            (void)State.Start->try_send(boost::system::error_code{});
        }
        co_await CollectCompareDone(State);
        const auto BusinessEnd = NowNs();
        AllocationWindow.End();
        SamplerState->Stop.store(true, std::memory_order_release);
#ifdef _WIN32
        const auto ProcessAfter = SampleProcess();
#endif
        co_await SamplerDone->async_receive(Net::use_awaitable);
        co_await ReleaseCompareLanes(State);
        for (std::size_t Index = 0; Index < Request.LaneCount; ++Index)
        {
            const auto &Result = State.LaneResults[Index];
            std::printf(
                "io-compare-round round=%zu order=%s mode=%s lanes=%zu lane=%zu ready=%s done=%s end=%s "
                "exited=%s completed=%s server-completed=%s sent=%zu received=%zu "
                "errors=%zu partial=%zu expected-hash=%016llx server-input-hash=%016llx "
                "client-output-hash=%016llx "
                "round-wall-ns=%lld block-samples=%zu\n",
                Request.Round, (Request.Round % 2U) == 0U ? "AB" : "BA",
                ModeName(Request.Mode), Request.LaneCount, Index,
                State.ReadyReceived[Index] && State.ReadyPassed[Index] ? "pass" : "fail",
                State.LaneReceived[Index] ? "pass" : "fail",
                State.EndSent[Index] ? "pass" : "fail",
                State.ExitedReceived[Index] ? "pass" : "fail", Result.Completed ? "yes" : "no",
                Result.ServerCompleted ? "yes" : "no", Result.Sent, Result.Received,
                Result.Errors, Result.Partial,
                static_cast<unsigned long long>(Result.ExpectedInputHash),
                static_cast<unsigned long long>(Result.ServerInputHash),
                static_cast<unsigned long long>(Result.ClientOutputHash),
                static_cast<long long>(BusinessEnd - BusinessStart), Result.BlockSamples.size());
        }
        IoCompareResult Combined;
        Combined.Completed = true;
        Combined.ExpectedInputHash = Request.ExpectedInputHash;
        if (State.StartupFailure || State.CoordinatorFailure)
        {
            Combined.Completed = false;
            ++Combined.Errors;
        }
        Combined.GlobalAllocations = AllocationWindow.Stats();
        bool HasHash = false;
        for (std::size_t Index = 0; Index < Request.LaneCount; ++Index)
        {
            auto &Result = State.LaneResults[Index];
            if (!State.LaneReceived[Index])
            {
                Combined.Completed = false;
                ++Combined.Errors;
                continue;
            }
            Combined.Completed = Combined.Completed && Result.Completed;
            Combined.Sent += Result.Sent;
            Combined.Received += Result.Received;
            Combined.Partial += Result.Partial;
            Combined.Errors += Result.Errors;
            Combined.OrdinaryAllocations += Result.OrdinaryAllocations;
            Combined.AlignedAllocations += Result.AlignedAllocations;
            Combined.OrdinaryBytes += Result.OrdinaryBytes;
            Combined.AlignedBytes += Result.AlignedBytes;
            Combined.BlockSamples.insert(Combined.BlockSamples.end(),
                                         Result.BlockSamples.begin(), Result.BlockSamples.end());
            if (!HasHash)
            {
                Combined.ExpectedInputHash = Result.ExpectedInputHash;
                Combined.ServerInputHash = Result.ServerInputHash;
                Combined.ClientOutputHash = Result.ClientOutputHash;
                HasHash = true;
            }
            else if (Combined.ExpectedInputHash != Result.ExpectedInputHash ||
                     Combined.ServerInputHash != Result.ServerInputHash ||
                     Combined.ClientOutputHash != Result.ClientOutputHash)
            {
                ++Combined.Errors;
            }
        }
#ifdef _WIN32
        Combined.CpuUser100ns = ProcessAfter.User100ns - ProcessBefore.User100ns;
        Combined.CpuKernel100ns = ProcessAfter.Kernel100ns - ProcessBefore.Kernel100ns;
        Combined.PeakWorkingSet = (std::max)(
            {ProcessBefore.WorkingSet, ProcessAfter.WorkingSet, SamplerState->PeakWorkingSet});
        Combined.PeakPrivateUsage = (std::max)(
            {ProcessBefore.PrivateUsage, ProcessAfter.PrivateUsage,
             SamplerState->PeakPrivateUsage});
        Combined.ProcessSampleCount = SamplerState->SampleCount;
        Combined.ProcessAvailable = ProcessBefore.Available && ProcessAfter.Available &&
                                    SamplerState->Valid && SamplerState->SampleCount > 0;
#endif
        Combined.WallNs = BusinessEnd - BusinessStart;
        co_return Combined;
    }


}

