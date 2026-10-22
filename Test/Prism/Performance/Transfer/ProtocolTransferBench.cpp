/**
 * @file ProtocolTransferBench.cpp
 * @brief 协议层传输基准的独立 CLI 入口。
 */

#include "ProtocolTransferBench.hpp"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace ProtocolTransferBench
{
}

int main(int argc, char **argv)
{
    using ProtocolTransferBench::BenchVmessChunk;
    using ProtocolTransferBench::ChunkRun;
    using ProtocolTransferBench::DefaultProtocolMatrixGroups;
    using ProtocolTransferBench::Gate;
    using ProtocolTransferBench::PrintProtocolSeries;
    using ProtocolTransferBench::ProtocolSeries;
    using ProtocolTransferBench::ProtocolSeriesPrintRequest;
    using ProtocolTransferBench::ProtocolRoundCount;
    using ProtocolTransferBench::Result;
    using ProtocolTransferBench::RunAllocationPreflight;
    using ProtocolTransferBench::RunFailurePreflightCase;
    using ProtocolTransferBench::RunPreflightDiagnosis;
    using ProtocolTransferBench::RunProtocolDiagnosis;
    using ProtocolTransferBench::RunSocksRound;
    using ProtocolTransferBench::RunVmessRound;
    using ProtocolTransferBench::PayloadHash;


    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockSize = 262144;
    const auto ExpectedInputHash = PayloadHash(TotalBytes);

    if (argc > 1 && std::strcmp(argv[1], "--diagnose-preflight") == 0)
    {
        return RunPreflightDiagnosis();
    }
    if (argc > 1 && std::strcmp(argv[1], "--diagnose") == 0)
    {
        return RunProtocolDiagnosis(TotalBytes, BlockSize);
    }
    if (argc > 1)
    {
        std::printf("usage: ProtocolTransferBench [--diagnose|--diagnose-preflight]\n");
        std::fflush(stdout);
        return 2;
    }

    bool AllValid = true;
    AllValid = RunAllocationPreflight() && AllValid;
    AllValid = RunFailurePreflightCase() && AllValid;
    std::size_t MatrixGroups = 0;
    for (const auto LaneCount : {std::size_t{1}, std::size_t{2}, std::size_t{4}})
    {
        ProtocolSeries SocksSeries;
        ProtocolSeries VmessSeries;
        for (std::size_t Round = 0; Round < SocksSeries.Rounds.size(); ++Round)
        {
            SocksSeries.Rounds[Round] = RunSocksRound(ProtocolRoundOptions{
                TotalBytes, BlockSize, LaneCount, ExpectedInputHash});
            VmessSeries.Rounds[Round] = RunVmessRound(ProtocolRoundOptions{
                TotalBytes, BlockSize, LaneCount, ExpectedInputHash});
            MatrixGroups += 2U;
        }
        AllValid = PrintProtocolSeries(
                       ProtocolSeriesPrintRequest{"socks5", TotalBytes, LaneCount, &SocksSeries}) &&
                   AllValid;
        AllValid = PrintProtocolSeries(
                       ProtocolSeriesPrintRequest{"vmess", TotalBytes, LaneCount, &VmessSeries}) &&
                   AllValid;
    }
    const auto MatrixValid = MatrixGroups == DefaultProtocolMatrixGroups;
    std::printf("protocol-matrix groups=%zu expected-groups=%zu expected-input-hash=%016llx valid=%s\n",
                MatrixGroups, DefaultProtocolMatrixGroups,
                static_cast<unsigned long long>(ExpectedInputHash),
                MatrixValid ? "yes" : "no");
    AllValid = MatrixValid && AllValid;

    Result ReuseResult, NaiveResult;
    std::array<ChunkRun, ProtocolRoundCount> ReuseRuns{};
    std::array<ChunkRun, ProtocolRoundCount> NaiveRuns{};
    for (std::size_t Round = 0; Round < ReuseRuns.size(); ++Round)
    {
        if ((Round % 2U) == 0U)
        {
            ReuseRuns[Round] = BenchVmessChunk(true);
            NaiveRuns[Round] = BenchVmessChunk(false);
        }
        else
        {
            NaiveRuns[Round] = BenchVmessChunk(false);
            ReuseRuns[Round] = BenchVmessChunk(true);
        }
        ReuseResult.Samples[Round] = ReuseRuns[Round].ElapsedNanoseconds;
        NaiveResult.Samples[Round] = NaiveRuns[Round].ElapsedNanoseconds;
    }
    std::printf("---- vmess 加密 256MB（纯加密，无传输）----\n");
    bool ChunkValid = true;
    std::uint64_t ReferenceHash = 0;
    std::size_t ReferenceBytes = 0;
    for (std::size_t Round = 0; Round < ReuseRuns.size(); ++Round)
    {
        if (Round == 0U)
        {
            ReferenceHash = ReuseRuns[Round].OutputHash;
            ReferenceBytes = ReuseRuns[Round].OutputBytes;
        }
        const auto RoundValid = ReuseRuns[Round].Valid && NaiveRuns[Round].Valid &&
            ReuseRuns[Round].OutputHash == ReferenceHash &&
            NaiveRuns[Round].OutputHash == ReferenceHash &&
            ReuseRuns[Round].OutputBytes == ReferenceBytes &&
            NaiveRuns[Round].OutputBytes == ReferenceBytes;
        ChunkValid = ChunkValid && RoundValid;
        std::printf(
            "vmess-chunk round=%zu order=%s reuse_hash=%016llx naive_hash=%016llx "
            "reuse_bytes=%zu naive_bytes=%zu valid=%s\n",
            Round + 1U, (Round % 2U) == 0U ? "AB" : "BA",
            static_cast<unsigned long long>(ReuseRuns[Round].OutputHash),
            static_cast<unsigned long long>(NaiveRuns[Round].OutputHash),
            ReuseRuns[Round].OutputBytes, NaiveRuns[Round].OutputBytes,
            RoundValid ? "yes" : "no");
    }
    AllValid = ChunkValid && AllValid;
    AllValid = Gate("vmess Chunk 复用缓冲 (资源指针)", 256ULL * 1024 * 1024, ReuseResult) && AllValid;
    AllValid = Gate("vmess Chunk 每帧分配 (无资源指针)", 256ULL * 1024 * 1024, NaiveResult) && AllValid;
    std::printf("ProtocolTransferBench: %s\n", AllValid ? "ALL PASS" : "FAILED");
    return AllValid ? 0 : 1;
}
