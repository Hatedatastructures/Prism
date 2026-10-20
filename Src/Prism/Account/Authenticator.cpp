/**
 * @file Authenticator.cpp
 * @brief 认证凭据的固定时间文本比较实现。
 */
#include <Prism/Account/Authenticator.hpp>

#include <algorithm>
#include <cstdint>

namespace Prism
{
    auto ConstantTimeEqual(const std::string_view Left, const std::string_view Right) noexcept -> bool
    {
        auto Difference = static_cast<std::uint8_t>(Left.size() != Right.size());
        const auto Length = (std::max)(Left.size(), Right.size());
        for (std::size_t Index = 0U; Index < Length; ++Index)
        {
            std::uint8_t A = 0U, B = 0U;
            if (Index < Left.size()) { A = static_cast<std::uint8_t>(Left[Index]); }
            if (Index < Right.size()) { B = static_cast<std::uint8_t>(Right[Index]); }
            Difference = static_cast<std::uint8_t>(Difference | (A ^ B));
        }
        return Difference == 0U;
    }
} // namespace Prism
