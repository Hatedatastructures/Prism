/** @file QueryType.hpp @brief DNS wire 查询与资源记录类型的唯一枚举。 */
#pragma once
#include <cstdint>
namespace Preview::Network::Dns
{
    /** @brief 外部 wire 的规定编号；未知类型可按原始十六位值保留。 */
    enum class QType : std::uint16_t
    {
        A = 1, Ns = 2, Cname = 5, Soa = 6, Mx = 15, Txt = 16, Aaaa = 28, Opt = 41
    };
}
