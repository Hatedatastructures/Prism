/** @file Limits.hpp @brief 管理 HTTP 请求和 JSON 响应的唯一容量定义。 */
#pragma once
#include <cstddef>
namespace Preview::Operations
{
    inline constexpr std::size_t MaxRequestHeaderBytes = 16U * 1024U;
    inline constexpr std::size_t MaxReloadBodyBytes = 64U * 1024U;
    inline constexpr std::size_t MaxRequestBytes = MaxRequestHeaderBytes + MaxReloadBodyBytes;
    inline constexpr std::size_t MaxInFlightRequestBytes = MaxRequestBytes * 8U;
    inline constexpr std::size_t MaxRequestLineBytes = 2048U;
    inline constexpr std::size_t MaxHeaderCount = 32U;
    inline constexpr std::size_t MaxResponseBytes = 2U * 1024U * 1024U;
} // namespace Preview::Operations
