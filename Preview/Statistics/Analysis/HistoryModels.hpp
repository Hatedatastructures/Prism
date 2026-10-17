/** @file HistoryModels.hpp @brief 观测历史存储与查询的唯一值契约。 */
#pragma once
#include <Preview/Statistics/Analysis/Histogram.hpp>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Preview::Statistics
{
    enum class HistoryScope : std::uint8_t
    { Process, Worker, Account, Group, Ingress, ProtocolType, ProtocolInstance };
    enum class HistoryMetric : std::uint8_t
    { Traffic, RecognitionAdmission, DnsResolution, TcpConnect };

    struct HistoryQuality final
    {
        std::uint64_t Dropped{0};
        std::uint64_t AggregationFailures{0};
        bool Incomplete{false};
    };

    /** @brief 每条记录表示一个窗口的增量；禁止把累计计数重复相加。 */
    struct HistoryRecord final
    {
        HistoryScope Scope{HistoryScope::Process};
        std::string Key;
        std::string InstanceKey;
        std::string Incarnation;
        std::uint64_t Generation{0};
        std::uint64_t Timestamp{0};
        std::uint64_t ResolutionMilliseconds{1'000U};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
        std::uint64_t Events{0};
        std::uint64_t Errors{0};
        std::optional<std::uint64_t> Active;
        LatencyHistogram Latency;
        HistoryQuality Quality;
        HistoryMetric Metric{HistoryMetric::Traffic};
    };

    /** @brief 半开时间范围 [From,To)，Key 为配置持久标识，非跨重启的运行时数字。 */
    struct HistoryQuery final
    {
        HistoryScope Scope{HistoryScope::Process};
        std::string Key;
        std::uint64_t From{0};
        std::uint64_t To{0};
        std::size_t MaxPoints{1'200U};
        HistoryMetric Metric{HistoryMetric::Traffic};
    };

    struct HistoryGap final
    {
        std::uint64_t From{0};
        std::uint64_t To{0};
        std::string Reason;
    };

    struct HistoryResult final
    {
        std::uint64_t SampledAt{0};
        std::uint64_t From{0};
        std::uint64_t To{0};
        std::uint64_t ResolutionMilliseconds{0};
        std::string Coverage;
        std::vector<HistoryGap> Gaps;
        std::vector<HistoryRecord> Items;
        bool Available{false};
        std::string Failure;
    };

    inline constexpr std::uint64_t HistoryMemoryRetention{15U * 60U * 1'000U};
    inline constexpr std::uint64_t HistoryTenSecondRetention{24U * 60U * 60U * 1'000U};
    inline constexpr std::uint64_t HistoryMinuteRetention{7U * HistoryTenSecondRetention};
    inline constexpr std::uint64_t HistoryRetention{30U * HistoryTenSecondRetention};
}
