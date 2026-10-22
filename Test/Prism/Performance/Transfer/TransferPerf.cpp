/**
 * @file TransferPerf.cpp
 * @brief TransferPerf 的独立 CLI 入口。
 */

#include "TransferPerf.hpp"

#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace TransferPerf
{
    [[nodiscard]] auto RunIoCompare() -> int;
    [[nodiscard]] auto BenchRawTcp(std::size_t TotalBytes, std::size_t BlockSize) -> std::int64_t;
    [[nodiscard]] auto Gate(const char *Name, std::size_t Bytes, const Result &Measurement) -> bool;
}

int main(int argc, char **argv)
{
    using TransferPerf::Result;

    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc > 1 && std::strcmp(argv[1], "--io-compare") == 0)
    {
        return TransferPerf::RunIoCompare();
    }
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    Result Block16K;
    Result Block256K;
    for (std::size_t SampleIndex = 0;
         SampleIndex < Block16K.Samples.size();
         ++SampleIndex)
    {
        Block16K.Samples[SampleIndex] =
            TransferPerf::BenchRawTcp(TotalBytes, 16384);
        Block256K.Samples[SampleIndex] =
            TransferPerf::BenchRawTcp(TotalBytes, 262144);
    }
    if (!TransferPerf::Gate("Tcp raw 16KB block", TotalBytes, Block16K))
    {
        return 1;
    }
    if (!TransferPerf::Gate("Tcp raw 256KB block", TotalBytes, Block256K))
    {
        return 1;
    }
    std::printf("TransferPerf: ALL PASS\n");
    return 0;
}
