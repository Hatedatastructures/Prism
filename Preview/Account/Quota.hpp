/** @file Quota.hpp
 * @brief 不可变账户额度政策；零表示该业务限制不启用。
 */
#pragma once
#include <cstdint>
namespace Preview::Account
{
    struct QuotaPolicy final
    {
        std::uint32_t MaxConnections{0U};
        std::uint32_t MaxStreams{0U};
        std::uint64_t MaxBytes{0U};
    };
}
