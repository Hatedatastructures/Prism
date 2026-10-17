/** @file Quota.hpp
 * @brief 并发使用可选上限；字节字段仍表示可归还的内存预约量。
 */
#pragma once
#include <cstdint>
#include <optional>
namespace Preview::Account
{
    struct QuotaPolicy final
    {
        std::optional<std::uint32_t> MaxConnections;
        std::optional<std::uint32_t> MaxStreams;
        std::uint64_t MaxBytes{0U};
    };
}
