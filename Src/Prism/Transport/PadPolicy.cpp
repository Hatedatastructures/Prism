/** @file PadPolicy.cpp @brief 冷配置文本到不可变填充区间的解析实现。 */
#include <Prism/Transport/PadPolicy.hpp>

#include <charconv>
#include <expected>
#include <string_view>
#include <system_error>
#include <vector>

namespace Prism::Transport
{
    auto ParsePadTargets(std::string_view Text) -> std::expected<std::vector<PadTarget>, Fault::Failure>
    {
        std::vector<PadTarget> Result;
        if (Text.empty()) return Result;
        while (!Text.empty())
        {
            if (Result.size() == 64) return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg});
            const auto Comma = Text.find(',');
            const auto Item = Text.substr(0, Comma);
            const auto Dash = Item.find('-');
            const auto Minimum = Item.substr(0, Dash);
            auto Maximum = Minimum;
            if (Dash != std::string_view::npos) Maximum = Item.substr(Dash + 1);
            PadTarget Range;
            if (Minimum.empty() || Maximum.empty()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            const auto Low = std::from_chars(Minimum.data(), Minimum.data() + Minimum.size(), Range.MinVal);
            const auto High = std::from_chars(Maximum.data(), Maximum.data() + Maximum.size(), Range.MaxVal);
            if (Low.ec != std::errc{} || High.ec != std::errc{} || Low.ptr != Minimum.data() + Minimum.size() ||
                High.ptr != Maximum.data() + Maximum.size() || Range.MinVal > Range.MaxVal)
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            Result.push_back(Range);
            if (Comma == std::string_view::npos) break;
            Text.remove_prefix(Comma + 1);
            if (Text.empty()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }
        return Result;
    }
}
