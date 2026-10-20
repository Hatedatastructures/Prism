/**
 * @file Address.cpp
 * @brief Common 地址文本解析实现。
 */

#include <Prism/Protocols/Common/Address.hpp>

namespace Prism::Protocol::Common
{
    [[nodiscard]] auto ParseIpv4Text(
        const std::string_view Text,
        std::array<std::uint8_t, 4> &Output) -> bool
    {
        Output.fill(0);
        std::size_t Segment = 0;
        std::size_t Value = 0;
        bool HasDigit = false;
        for (const char Character : Text)
        {
            if (Character == '.')
            {
                if (!HasDigit || Segment >= 3)
                {
                    Output.fill(0);
                    return false;
                }
                Output[Segment++] = static_cast<std::uint8_t>(Value);
                Value = 0;
                HasDigit = false;
            }
            else if (Character >= '0' && Character <= '9')
            {
                const auto Digit = static_cast<std::size_t>(Character - '0');
                if (Value > (255 - Digit) / 10)
                {
                    Output.fill(0);
                    return false;
                }
                Value = Value * 10 + Digit;
                HasDigit = true;
            }
            else
            {
                Output.fill(0);
                return false;
            }
        }
        if (Segment != 3 || !HasDigit)
        {
            Output.fill(0);
            return false;
        }
        Output[3] = static_cast<std::uint8_t>(Value);
        return true;
    }
} // namespace Prism::Protocol::Common
