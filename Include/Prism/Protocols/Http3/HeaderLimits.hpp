/**
 * @file HeaderLimits.hpp
 * @brief HTTP/3 QPACK 与 native nghttp3 共用的头字段资源额度。
 */
#pragma once
#include <cstddef>
namespace Prism::Http3::HeaderLimits
{
    inline constexpr std::size_t MaxHeaderSectionBytes = 64U * 1024U;
    inline constexpr std::size_t MaxHeaderFields = 128U;
    inline constexpr std::size_t MaxFieldBytes = 16U * 1024U;
    inline constexpr std::size_t MaxConcurrentSections = 64U;
    inline constexpr std::size_t MaxPendingEvents = 256U;
    inline constexpr std::size_t MaxPendingEventBytes = 4U * 1024U * 1024U;
}
