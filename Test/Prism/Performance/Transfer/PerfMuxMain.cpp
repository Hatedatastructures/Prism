/**
 * @file PerfMuxMain.cpp
 * @brief Mux 多 lane 性能场景的进程入口。
 */

#include "PerfMux.hpp"

#include <cstdio>

int main()
{
    bool AllValid = true;
    for (const auto LaneCount : TransferPerfMux::LaneCounts)
    {
        for (std::size_t Round = 0; Round < TransferPerfMux::RoundCount; ++Round)
        {
            const auto ForwardOrder = Round % 2U == 0U;
            TransferPerfMux::RoundRequest Request;
            Request.Round = Round;
            Request.LaneCount = LaneCount;
            Request.ForwardOrder = ForwardOrder;
            Request.ServerFirst = ForwardOrder;
            const auto Result = TransferPerfMux::RunRound(Request);
            TransferPerfMux::PrintRound(Result);
            AllValid = Result.Valid() && AllValid;
        }
    }
    std::printf(
        "TransferPerfMux: lane-counts=1,2,4 rounds=%zu total-bytes-per-lane=%zu "
        "block-bytes=%zu fragment-bytes=%zu valid=%s\n",
        TransferPerfMux::RoundCount, TransferPerfMux::TotalBytes,
        TransferPerfMux::BlockSize, TransferPerfMux::FragmentBytes,
        AllValid ? "yes" : "no");
    return AllValid ? 0 : 1;
}
