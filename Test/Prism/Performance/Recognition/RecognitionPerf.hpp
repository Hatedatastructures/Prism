/**
 * @file RecognitionPerf.hpp
 * @brief RecognitionPerf 的 allocation、配置 pipeline 与 owner compare 共享契约。
 */

#pragma once

#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <charconv>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Prism::Recognition::Perf
{
    /**
     * @brief 同步验证普通及对齐分配计数，并释放本次验证拥有的分配。
     * @return 各分配入口的计数、字节数及对齐均正确时返回 true。
     * @details 调用者须串行执行；不接收外部所有权，不提供取消或半关闭。
     */
    [[nodiscard]] auto ValidateAllocationInstrumentation() -> bool;

    /**
     * @brief 在固定 trace 上执行 CID、SNI 和账户 owner 的完整五轮矩阵。
     * @return 所有场景正确时返回 0，准备或操作失败时返回非零。
     * @details 同步入口拥有局部 worker 和测量数据，结束前等待本次线程；
     *          调用者须串行执行，不提供外部取消或半关闭。
     */
    [[nodiscard]] auto RunOwnerCompare() -> int;

    /**
     * @brief 按值接收预热数、采样轮数及每轮试验数，执行配置识别矩阵。
     * @return 所有识别结果正确时返回 0，准备或操作失败时返回非零。
     * @details 同步入口在当前线程驱动局部 executor，持有临时传输至操作结束；
     *          调用者须串行执行，不提供外部取消或半关闭。
     */
    [[nodiscard]] auto RunConfiguredCompare(std::size_t Warmup, std::size_t Samples,
                                           std::size_t Trials) -> int;

    struct AllocationSnapshot final
    {
        std::size_t Count{0}; std::size_t Bytes{0};
        std::size_t AlignedCount{0}; std::size_t AlignedBytes{0};
    };
    struct Measurement final
    {
        std::uint64_t ElapsedNanoseconds{0}; std::size_t ReadCalls{0}; AllocationSnapshot Allocations;
        Prism::Recognition::CandidateId Candidate{Prism::Recognition::InvalidCandidate};
        std::uint16_t CryptoTrials{0}; bool Success{false};
    };
    struct Scenario final
    {
        Prism::Recognition::RecognitionMode Mode{Prism::Recognition::RecognitionMode::Configured};
        std::string_view ModeName; std::string_view Protocol; std::size_t CandidateCount{0};
        std::vector<std::byte> Wire; Prism::Recognition::SharedProfile Profile;
        Prism::Recognition::CandidateId ExpectedCandidate{Prism::Recognition::InvalidCandidate};
    };
    struct MetricContext final { std::size_t Warmup{0}; std::size_t TrialsPerSample{0}; };
    inline constexpr std::array<std::uint8_t, 16> FixedUuid{
        0x1FU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U,
        0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU};
    inline constexpr std::string_view FixedUuidText = "1f202122-2324-2526-2728-292a2b2c2d2e";
    inline constexpr std::string_view OwnerInputContract =
        "cid=11223344;overlap_cid=1122;other_cid=55667788;alias_cid=91929394;"
        "sni=EDGE.EXAMPLE.COM.|client.api.example.com|client.deep.api.example.com|"
        "b.a.deep.api.example.com|unknown.example.com|<empty>;"
        "account=owner-password/wrong-password;uuid=1f202122-2324-2526-2728-292a2b2c2d2e";
    inline constexpr std::array<std::size_t, 3> OwnerCidScales{8U, 64U, 1024U};
    inline constexpr std::array<std::size_t, 3> OwnerConcurrencies{1U, 2U, 4U};
    inline constexpr std::size_t OwnerRoundCount = 5U;
    inline constexpr std::uint64_t OwnerTraceId = 0x7B6D'1A2C'44E9'9031ULL;
    inline constexpr std::string_view OwnerCompareVersion =
        "preview-owner-compare-v4-fixed-input-preflight";
    inline constexpr std::string_view OwnerVariantA = "production_component_owner_path";
    inline constexpr std::string_view OwnerVariantB = "candidate_lower_bound_not_equivalent";
    inline constexpr std::string_view OwnerProductionEntryGap =
        "Session/Configuration owner is not safely reachable from this Performance leaf; "
        "A measures production owner components and Perf_Recognition measures the production Pipeline";
    inline constexpr std::uint64_t OwnerPlatformSampleIntervalMs = 1U;
    inline constexpr std::size_t OwnerRepeatCycles = 10000U;
    struct OwnerTrace final
    {
        std::array<std::uint8_t, 16> Uuid{FixedUuid};
        std::vector<std::byte> Cid, OverlapCid, OtherCid, AliasCid;
        std::vector<std::vector<std::byte>> AdditionalCids, CidPackets;
        std::vector<std::string> Sni;
        std::vector<Prism::Recognition::CandidateId> SniExpected;
        std::vector<std::pair<std::string, Prism::Recognition::CandidateId>> SniRoutes;
        std::size_t Capacity{0}, AliasCount{1};
        std::vector<std::string> Credentials; std::uint64_t Hash{0};
    };
    [[nodiscard]] auto HashOwnerTrace(const OwnerTrace &Trace) noexcept -> std::uint64_t;
    [[nodiscard]] auto ValidateOwnerTraceHash(const OwnerTrace &Trace) noexcept -> bool;
    struct PlatformSample final
    {
        std::optional<std::uint64_t> Cpu100ns, CurrentRssBytes, CurrentCommitBytes, LifetimePeakRssBytes;
    };
    struct OwnerMeasurement final
    {
        std::vector<std::uint64_t> Timings; std::size_t Errors{0}, Operations{0}; AllocationSnapshot Allocations;
        PlatformSample Before, After; std::optional<std::uint64_t> RoundPeakRssBytes, RoundPeakCommitBytes, LifetimePeakRssBytes;
        std::size_t PlatformSamples{0}; std::uint64_t WallNanoseconds{0}; bool PreflightOk{true}; std::string PreflightError;
    };
    struct OwnerCaseResult final { std::string Owner, Variant; bool Correct{false}; };
    struct OwnerPreflight final
    {
        bool HashValid{false};
        bool CorrectnessValid{false};
        bool CleanupValid{false};
        std::size_t Errors{0};
        std::string Error;
    };
    struct OwnerPreflightReport final
    {
        std::string_view Variant;
        std::string_view SemanticModel;
        const OwnerTrace &Trace;
        const OwnerPreflight &Preflight;
    };
    [[nodiscard]] auto PrintOwnerPreflight(const OwnerPreflightReport &Report) -> bool;
    inline std::atomic<std::size_t> AllocationCount{0};
    inline std::atomic<std::size_t> AllocationBytes{0};
    inline std::atomic<std::size_t> AlignedAllocationCount{0};
    inline std::atomic<std::size_t> AlignedAllocationBytes{0};
    inline std::atomic<bool> AllocationMeasurementEnabled{true};
    inline auto ResetAllocationCounters() -> void
    {
        AllocationCount.store(0, std::memory_order_relaxed);
        AllocationBytes.store(0, std::memory_order_relaxed);
        AlignedAllocationCount.store(0, std::memory_order_relaxed);
        AlignedAllocationBytes.store(0, std::memory_order_relaxed);
    }
    [[nodiscard]] inline auto ReadAllocationCounters() -> AllocationSnapshot
    {
        return {AllocationCount.load(std::memory_order_relaxed),
                AllocationBytes.load(std::memory_order_relaxed),
                AlignedAllocationCount.load(std::memory_order_relaxed),
                AlignedAllocationBytes.load(std::memory_order_relaxed)};
    }
}
