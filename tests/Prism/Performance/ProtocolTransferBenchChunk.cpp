/**
 * @file ProtocolTransferBenchChunk.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    struct ChunkOutputRequest final
    {
        ChunkRun &Run;
        std::span<const std::uint8_t> Output;
        std::size_t Written{0};
        std::size_t ExpectedBytes{0};
    };

    auto RecordChunkOutput(const ChunkOutputRequest &Request) -> void
    {
        if (Request.Written != Request.ExpectedBytes || Request.Output.size() < Request.Written)
        {
            Request.Run.Valid = false;
            return;
        }
        Request.Run.OutputBytes += Request.Written;
        HashBytes(Request.Run.OutputHash,
                  std::as_bytes(Request.Output.first(Request.Written)));
    }

    // ── vmess 加密：复用 vs 每帧分配（资源指针收益） ──
    auto BenchVmessChunk(const bool Reuse) -> ChunkRun
    {
        namespace VmessLocal = Prism::Vmess;
        const auto Key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        VmessLocal::ChunkEncryptor Encoder(Key, Nonce);
        constexpr std::size_t ChunkSize = 16384;
        constexpr int IterationCount = 16384; // 16KB x 16384 = 256MB
        constexpr std::size_t ExpectedChunkBytes =
            ChunkSize + VmessLocal::ChunkEncryptor::Overhead;
        std::vector<std::uint8_t> Plain(ChunkSize);
        for (std::size_t I = 0; I < Plain.size(); ++I)
        {
            Plain[I] = static_cast<std::uint8_t>(I);
        }

        ChunkRun Run;
        Run.Valid = true;
        const std::int64_t StartNs = NowNs();
        if (Reuse)
        {
            // 资源指针：Arena 缓冲复用（vmess Conn 实际路径）
            Prism::Memory::SessionResource<> MemoryResource;
            auto Output = MemoryResource.MakeBuffer<std::uint8_t>(ExpectedChunkBytes);
            for (int I = 0; I < IterationCount; ++I)
            {
                const auto Written = Encoder.Seal(Plain, Output);
                RecordChunkOutput(ChunkOutputRequest{
                    Run, std::span<const std::uint8_t>(Output), Written, ExpectedChunkBytes});
                if (!Run.Valid)
                {
                    break;
                }
            }
        }
        else
        {
            // 无资源指针：每块新建（系统堆分配）
            for (int I = 0; I < IterationCount; ++I)
            {
                std::vector<std::uint8_t> Output(ExpectedChunkBytes);
                const auto Written = Encoder.Seal(Plain, Output);
                RecordChunkOutput(ChunkOutputRequest{
                    Run, std::span<const std::uint8_t>(Output), Written, ExpectedChunkBytes});
                if (!Run.Valid)
                {
                    break;
                }
            }
        }
        Run.ElapsedNanoseconds = NowNs() - StartNs;
        Run.Valid = Run.Valid && Run.OutputBytes == ExpectedChunkBytes * IterationCount;
        return Run;
    }

    auto RunProtocolDiagnosis(
        const std::size_t Total,
        const std::size_t BlockSize) -> int
    {
        bool AllValid = true;
        const auto ExpectedInputHash = PayloadHash(Total);
        for (const auto *Protocol : {"socks5", "vmess"})
        {
            std::printf(
                "protocol-diagnose begin protocol=%s lane-count=1 total=%zu block=%zu "
                "mode=diagnostic-only\n",
                Protocol, Total, BlockSize);
            std::fflush(stdout);
            const auto Round = std::strcmp(Protocol, "socks5") == 0
                                   ? RunProtocolRound(
                                         ProtocolRoundOptions{
                                             Total, BlockSize, 1, ExpectedInputHash, Protocol, true},
                                         RunSocksLane)
                                   : RunProtocolRound(
                                         ProtocolRoundOptions{
                                             Total, BlockSize, 1, ExpectedInputHash, Protocol, true},
                                         RunVmessLane);
            const auto Valid = Round.Completed && Round.Errors == 0 &&
                               Round.Sent == Total && Round.Echoed == Total &&
                               Round.ExpectedInputHash == ExpectedInputHash &&
                               Round.ExpectedInputHash == Round.ServerInputHash &&
                               Round.ExpectedInputHash == Round.ClientOutputHash &&
                               Round.PartialIo > 0;
            std::printf(
                "protocol-diagnose result protocol=%s completed=%s sent=%zu echoed=%zu "
                "errors=%zu hash=%016llx valid=%s\n",
                Protocol, Round.Completed ? "yes" : "no", Round.Sent, Round.Echoed,
                Round.Errors, static_cast<unsigned long long>(Round.ClientOutputHash),
                Valid ? "yes" : "no");
            std::fflush(stdout);
            AllValid = AllValid && Valid;
        }
        return AllValid ? 0 : 1;
    }

    auto RunPreflightDiagnosis() -> int
    {
        std::printf("protocol-preflight-diagnose begin mode=diagnostic-only\n");
        std::fflush(stdout);
        const auto AllocationValid = RunAllocationPreflight(true);
        const auto FailureValid = RunFailurePreflightCase(true);
        const auto Valid = AllocationValid && FailureValid;
        std::printf(
            "protocol-preflight-diagnose result allocation=%s failure=%s valid=%s\n",
            AllocationValid ? "pass" : "fail", FailureValid ? "pass" : "fail",
            Valid ? "yes" : "no");
        std::fflush(stdout);
        return Valid ? 0 : 1;
    }

}
