/** @file FixedText.cpp
 * @brief 受控标识的固定容量 PascalCase 格式化实现。
 */
#include <Prism/Foundation/Utility/Text/FixedText.hpp>

#include <Prism/Foundation/Utility/Text/Case.hpp>

#include <string_view>

namespace Prism::Text
{
    auto PascalCaseValue(const std::string_view Value) noexcept -> FixedText<128U>
    {
        FixedText<128U> Result;
        TransformPascalCase(Value, [&Result](const char Character) noexcept { Result.PushBack(Character); });
        return Result;
    }
}
