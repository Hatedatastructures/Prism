/**
 * @file Common.hpp
 * @brief adapter 公共工具（handler 共享，避免重复实现）
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Runtime::Detail
{

    /**
     * @brief UUID 二进制 → 小写十六进制字符串
     * @param u 16 字节 UUID
     * @return 32 字符十六进制串（统计/日志标识用，不泄露密钥）
     */
    [[nodiscard]] inline auto UuidHex(const std::array<std::uint8_t, 16> &u) -> std::string
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string s(32, '0');
        for (std::size_t I = 0; I < 16; ++I)
        {
            s[2 * I] = digits[u[I] >> 4];
            s[2 * I + 1] = digits[u[I] & 0xf];
        }
        return s;
    }

} // namespace Preview::Runtime::Detail
