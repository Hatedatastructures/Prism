/** @file HistoryCatalog.hpp @brief 发布代次的数值归属到持久配置身份映射。 */
#pragma once
#include <Preview/Statistics/Analysis/HistoryModels.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace Preview::Statistics
{
    struct HistoryAccount final
    {
        std::uint64_t NumericId{0};
        std::string Key;
        std::string GroupKey;
    };

    struct HistoryProtocol final
    {
        std::uint64_t NumericId{0};
        std::string Key;
        std::uint64_t Type{0};
    };

    struct HistoryIngress final
    {
        std::uint64_t NumericId{0};
        std::string Key;
        std::uint8_t Transport{0};
    };

    /** @brief 冷路径按本代配置编译；观察热路径只携带数值，不查字符串。 */
    struct HistoryCatalog final
    {
        std::string InstanceKey;
        std::string Incarnation;
        std::uint64_t Generation{0};
        std::vector<HistoryAccount> Accounts;
        std::vector<HistoryProtocol> Protocols;
        std::vector<HistoryIngress> Ingresses;
    };
}
