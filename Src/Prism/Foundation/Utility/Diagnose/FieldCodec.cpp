/** @file FieldCodec.cpp
 * @brief Diagnose 拥有型字段 UTF-8 限长实现。
 */
#include <Prism/Foundation/Utility/Diagnose/FieldCodec.hpp>

#include <Prism/Foundation/Utility/Text/Truncate.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Diagnose::Detail
{
    auto TruncateUtf8(const std::string_view Input, const std::size_t Maximum)
        -> std::pair<std::string, bool>
    {
        if (Input.size() <= Maximum)
        {
            return {std::string(Input), false};
        }
        std::string Result(Input.substr(0U, Maximum));
        const auto Size = Text::FinishTruncatedUtf8(std::span(Result.data(), Result.size()));
        Result.resize(Size);
        return {std::move(Result), true};
    }
}
