/** @file FixedText.hpp
 * @brief 有界观察文本；不分配，截断具有独立标志。
 */
#pragma once
#include <Preview/Foundation/Utility/Text/Case.hpp>
#include <array>
#include <charconv>
#include <cstddef>
#include <format>
#include <string_view>

namespace Preview::Text
{
    template <std::size_t Capacity>
    class FixedText final
    {
    public:
        FixedText() = default;
        explicit FixedText(const std::string_view Value) noexcept { Append(Value); }
        auto Append(const std::string_view Value) noexcept -> void
        {
            for (const auto Character : Value) { PushBack(Character); }
        }
        auto PushBack(const char Character) noexcept -> void
        {
            if (Size_ < Capacity) { Storage_[Size_++] = Character; }
            else { Truncated_ = true; }
        }
        template <typename Number>
        auto AppendNumber(const Number Value) noexcept -> void
        {
            const auto Result = std::to_chars(Storage_.data() + Size_, Storage_.data() + Capacity, Value);
            if (Result.ec == std::errc{}) { Size_ = static_cast<std::size_t>(Result.ptr - Storage_.data()); }
            else { Truncated_ = true; }
        }
        [[nodiscard]] auto View() const & noexcept -> std::string_view { return {Storage_.data(), Size_}; }
        auto View() const && -> std::string_view = delete;
        [[nodiscard]] auto Empty() const noexcept -> bool { return Size_ == 0U; }
        [[nodiscard]] auto Truncated() const noexcept -> bool { return Truncated_; }
    private:
        std::array<char, Capacity> Storage_{};
        std::size_t Size_{0U};
        bool Truncated_{false};
    };
    /** @brief 受控枚举 token 的固定格式化；不适用于任意用户名或地址。 */
    [[nodiscard]] inline auto PascalCaseValue(const std::string_view Value) noexcept -> FixedText<128U>
    {
        FixedText<128U> Result;
        TransformPascalCase(Value, [&Result](const char Character) noexcept { Result.PushBack(Character); });
        return Result;
    }
}

/** @brief 标准格式化 ABI；具体消息仍在后台按固定参数快照渲染。 */
template <std::size_t Capacity>
struct std::formatter<Preview::Text::FixedText<Capacity>> : std::formatter<std::string_view>
{
    template <typename FormatContext>
    auto format(const Preview::Text::FixedText<Capacity>& Value, FormatContext& Context) const
        -> typename FormatContext::iterator
    {
        return std::formatter<std::string_view>::format(Value.View(), Context);
    }
};
