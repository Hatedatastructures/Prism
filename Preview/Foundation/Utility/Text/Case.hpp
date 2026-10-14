/** @file Case.hpp
 * @brief 受控标识的一次 ASCII PascalCase 转换，输出能力由调用方提供。
 */
#pragma once
#include <string_view>

namespace Preview::Text
{
    /** @brief 只转换受控标识，不改写用户身份、地址或原生错误。 */
    template <typename Writer>
    inline auto TransformPascalCase(const std::string_view Input, Writer&& Output)
        noexcept(noexcept(Output(' '))) -> void
    {
        bool Capitalize = true;
        for (const auto Raw : Input)
        {
            auto Character = static_cast<unsigned char>(Raw);
            if (Character == '_' || Character == '-') { Capitalize = true; continue; }
            if (Capitalize && Character >= 'a' && Character <= 'z') { Character -= 'a' - 'A'; }
            Output(static_cast<char>(Character));
            Capitalize = false;
        }
    }
}
