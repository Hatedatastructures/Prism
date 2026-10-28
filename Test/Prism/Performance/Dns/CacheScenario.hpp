/**
 * @file CacheScenario.hpp
 * @brief DNS cache 对照实验的参数、trace 与语义校验接口。
 */

#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Prism::Network::Dns::Compare
{
    enum class Variant
    {
        Current,
        Intrusive,
        Clock
    };

    enum class Distribution
    {
        Uniform,
        Hotspot
    };

    enum class WorkloadKind
    {
        GetOnly,
        Mixed
    };

    enum class OperationKind
    {
        Get,
        Insert,
        Overwrite,
        Expire,
        EvictExpired
    };

    struct Options
    {
        Variant Selected{Variant::Current};
        Distribution AccessDistribution{Distribution::Uniform};
        WorkloadKind Workload{WorkloadKind::GetOnly};
        std::size_t Capacity{64};
        std::size_t Executors{1};
        std::size_t Operations{100000};
        std::uint32_t HitPercent{95};
        std::uint64_t Seed{1};
        bool ValidateOnly{false};
    };

    struct CacheKey
    {
        std::string Domain;
        bool Negative{false};
    };

    struct Operation
    {
        std::uint32_t KeyIndex{0};
        bool ExpectedHit{false};
        OperationKind Kind{OperationKind::Get};
        bool Negative{false};
        bool ExpectedPresent{false};
        bool ExpectedNegative{false};
        bool RequireHit{false};
        bool RequireMiss{false};
        std::uint32_t ValueVersion{0};
        std::uint32_t ExpectedVersion{0};
        std::uint32_t TtlSeconds{86400};
    };

    struct OperationMix
    {
        std::uint64_t Gets{0};
        std::uint64_t Inserts{0};
        std::uint64_t Overwrites{0};
        std::uint64_t Expirations{0};
        std::uint64_t EvictExpired{0};
        std::uint64_t NegativeInserts{0};
        std::uint64_t RequiredHitProbes{0};
        std::uint64_t RequiredMissProbes{0};
        std::uint64_t DynamicGets{0};
    };

    struct Scenario
    {
        Options Settings;
        boost::asio::ip::address ExpectedAddress;
        boost::asio::ip::address AlternateAddress;
        std::vector<CacheKey> Keys;
        std::vector<Operation> Trace;
        OperationMix Mix;
        std::uint64_t TraceHash{14695981039346656037ull};
    };

} // namespace Prism::Network::Dns::Compare
