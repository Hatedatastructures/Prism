/** @file RuntimeOptions.cpp
 * @brief 受控 Diagnose 标识的 PascalCase 格式化实现。
 */
#include <Prism/Foundation/Utility/Diagnose/RuntimeOptions.hpp>

#include <Prism/Foundation/Utility/Text/Case.hpp>

#include <string>
#include <string_view>

namespace Prism::Diagnose
{
    auto PascalCaseToken(const std::string_view Value) -> std::string
    {
        std::string Result;
        Result.reserve(Value.size());
        Prism::Text::TransformPascalCase(Value, [&Result](const char Character) { Result.push_back(Character); });
        return Result;
    }
}
