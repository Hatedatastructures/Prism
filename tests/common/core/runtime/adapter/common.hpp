/**
 * @file common.hpp
 * @brief adapter 公共工具（handler 共享，避免重复实现）
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace preview::runtime::detail
{

    /**
     * @brief UUID 二进制 → 小写十六进制字符串
     * @param u 16 字节 UUID
     * @return 32 字符十六进制串（统计/日志标识用，不泄露密钥）
     */
    [[nodiscard]] inline auto uuid_hex(const std::array<std::uint8_t, 16> &u) -> std::string
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string s(32, '0');
        for (std::size_t i = 0; i < 16; ++i)
        {
            s[2 * i] = digits[u[i] >> 4];
            s[2 * i + 1] = digits[u[i] & 0xf];
        }
        return s;
    }

} // namespace preview::runtime::detail