/** @file HistoryCollector.hpp @brief 控制执行域的真实观察窗口与分辨率聚合 owner。 */
#pragma once
#include <Prism/Statistics/Analysis/HistoryCatalog.hpp>
#include <Prism/Statistics/Analysis/HistorySeries.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace Prism::Runtime::Detail
{
    /** @brief 仅应用控制 executor 调用；归属以事件 Generation 对应的冻结配置为准。 */
    class HistoryCollector final
    {
    public:
        static constexpr std::size_t MaxPendingSeries{65'536U};
        static constexpr std::size_t MaxMemoryRecords{65'536U};
        static constexpr std::size_t MaxPersistenceRecords{65'536U};

        auto Configure(Prism::Statistics::HistoryCatalog Catalog) -> void;

        /** @brief owner 退休后才移除身份目录；已聚合历史仍拥有字符串值。 */
        auto RetireGeneration(std::uint64_t Generation) -> void;

        /** @brief 成功消费的观察只聚合一次；失败不改变业务，下一窗口公开不完整标记。 */
        [[nodiscard]] auto Record(const Prism::Foundation::TrafficEvent &Event) noexcept -> bool;

        /** @brief 当前 flush 后形成实际窗口；延迟队列仅有消费时间，覆盖文案明确这一边界。 */
        auto Sample(std::uint64_t Now, Prism::Statistics::HistoryQuality Quality) noexcept -> void;

        [[nodiscard]] auto TakePersistenceBatch() -> std::vector<Prism::Statistics::HistoryRecord>;

        [[nodiscard]] auto Query(const Prism::Statistics::HistoryQuery &Request, std::uint64_t Now) const
            -> Prism::Statistics::HistoryResult;

    private:
        using Key = std::tuple<std::uint64_t, Prism::Statistics::HistoryScope, std::string,
            Prism::Statistics::HistoryMetric>;
        struct Series final { Prism::Statistics::HistoryScope Scope; std::string Key; };

        auto Add(const Prism::Statistics::HistoryCatalog &Catalog, Series IdentityValue,
            const Prism::Foundation::TrafficEvent &Event) -> void;

        auto SampleOwned(std::uint64_t Now, Prism::Statistics::HistoryQuality Quality) -> void;

        auto AddPersistent(const Prism::Statistics::HistoryRecord &Value, std::uint64_t Resolution) -> void;

        auto ClosePersistent(std::uint64_t Now) -> void;

        std::map<std::uint64_t, Prism::Statistics::HistoryCatalog> Catalogs_;
        std::map<Key, Prism::Statistics::HistoryRecord> Pending_;
        std::deque<Prism::Statistics::HistoryRecord> Memory_;
        std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t,
            Prism::Statistics::HistoryScope, std::string, Prism::Statistics::HistoryMetric>,
            Prism::Statistics::HistoryRecord> PersistentWindows_;
        std::vector<Prism::Statistics::HistoryRecord> Persistence_;
        std::uint64_t LastSample_{0};
        bool PendingFailure_{false};
    };
}
