/**
 * @file TransferPerfMux.hpp
 * @brief Mux 多 lane 性能场景的配置、结果与入口契约。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace TransferPerfMux
{
    inline constexpr std::uint64_t InitialHash = 1469598103934665603ULL;
    inline constexpr std::size_t TotalBytes = 64ULL * 1024 * 1024;
    inline constexpr std::size_t BlockSize = 64ULL * 1024;
    inline constexpr std::size_t FragmentBytes = 7;
    inline constexpr std::size_t RoundCount = 5;
    inline constexpr std::size_t MaxLaneCount = 4;
    inline constexpr std::array<std::size_t, 3> LaneCounts{1, 2, 4};

    struct MuxLaneResult final
    {
        std::size_t LaneId{0};
        std::size_t Sent{0};
        std::size_t Received{0};
        std::size_t ServerInputBytes{0};
        std::size_t PartialIo{0};
        std::size_t Errors{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::uint64_t ServerInputHash{InitialHash};
        std::uint64_t ClientOutputHash{InitialHash};
        bool ClientFinSubmitted{false};
        bool ClientFinDrained{false};
        bool ServerPeerEof{false};
        bool ServerFinSubmitted{false};
        bool ServerFinDrained{false};
        bool ClientPeerEof{false};
        bool ClientCleanup{false};
        bool ServerCleanup{false};
        bool NaturalExit{false};

        [[nodiscard]] auto Valid() const -> bool
        {
            return Errors == 0 && Sent == TotalBytes && Received == TotalBytes &&
                   ServerInputBytes == TotalBytes && PartialIo > 0 &&
                   ExpectedInputHash == ServerInputHash &&
                   ExpectedInputHash == ClientOutputHash && ClientFinSubmitted &&
                   ClientFinDrained && ServerPeerEof && ServerFinSubmitted &&
                   ServerFinDrained && ClientPeerEof && ClientCleanup &&
                   ServerCleanup && NaturalExit;
        }
    };

    struct MuxRoundResult final
    {
        std::size_t Round{0};
        std::size_t LaneCount{0};
        bool ForwardOrder{true};
        std::array<MuxLaneResult, MaxLaneCount> Lanes{};
        std::array<bool, MaxLaneCount> LaneSpawned{};
        std::array<bool, MaxLaneCount> LaneReceived{};
        std::size_t PartialIo{0};
        std::size_t Errors{0};
        bool ClientSessionCleanup{false};
        bool ServerSessionCleanup{false};
        bool NaturalExit{false};

        [[nodiscard]] auto Valid() const -> bool
        {
            if (Errors != 0 || PartialIo == 0 || !ClientSessionCleanup ||
                !ServerSessionCleanup || !NaturalExit ||
                (LaneCount != 1 && LaneCount != 2 && LaneCount != 4))
            {
                return false;
            }
            for (std::size_t Index = 0; Index < LaneCount; ++Index)
            {
                if (!LaneSpawned[Index] || !LaneReceived[Index] || !Lanes[Index].Valid())
                {
                    return false;
                }
            }
            return true;
        }
    };

    struct LaneInput final
    {
        std::size_t Total{TotalBytes};
        std::size_t Block{BlockSize};
        std::size_t Fragment{FragmentBytes};
    };

    struct RoundRequest final
    {
        LaneInput Input{};
        std::size_t Round{0};
        std::size_t LaneCount{1};
        bool ForwardOrder{true};
        bool ServerFirst{true};
        std::uint64_t ExpectedInputHash{InitialHash};
        MuxRoundResult *Result{nullptr};
    };

    [[nodiscard]] auto RunRound(RoundRequest Request) -> MuxRoundResult;
    auto PrintRound(const MuxRoundResult &Result) -> void;
}
