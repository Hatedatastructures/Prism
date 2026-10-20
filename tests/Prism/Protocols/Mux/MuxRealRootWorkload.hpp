/** @file MuxRealRootWorkload.hpp @brief 真实 Mux root 测量场景的固定负载契约。 */
#pragma once

#include <cstddef>
#include <string_view>

namespace Prism::Testing::MuxRealRoot
{
    inline constexpr std::size_t RealTotalBytes = 64U * 1024U * 1024U;
    inline constexpr std::size_t RealBlockBytes = 64U * 1024U;
    inline constexpr std::string_view RealLiteral{"T4-REAL-ROOT-LITERAL"};
}
