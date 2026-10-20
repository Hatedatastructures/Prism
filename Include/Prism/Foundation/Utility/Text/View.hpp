/** @file View.hpp
 * @brief 标准文本与正式 FixedText 的无分配同步借用合同。
 */
#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>

namespace Prism::Text
{
    template <std::size_t Capacity> class FixedText;
    template <typename Value>
    struct ViewInputType : std::false_type {};
    template <typename Allocator>
    struct ViewInputType<std::basic_string<char, std::char_traits<char>, Allocator>> : std::true_type {};
    template <std::size_t Capacity>
    struct ViewInputType<FixedText<Capacity>> : std::true_type {};
    template <>
    struct ViewInputType<std::string_view> : std::true_type {};
    /** @brief 排除任意用户转换与自定义 char_traits；领域类型先显式取得稳定 View。 */
    template <typename Value>
    inline constexpr bool ViewInput = ViewInputType<std::remove_cvref_t<Value>>::value ||
        std::is_same_v<std::remove_cvref_t<Value>, const char*> ||
        std::is_same_v<std::remove_cvref_t<Value>, char*> ||
        (std::is_array_v<std::remove_reference_t<Value>> &&
            std::is_same_v<std::remove_cv_t<std::remove_extent_t<std::remove_reference_t<Value>>>, char>);
    /**
     * @brief 同步借用精确正式文本类型；无用户代码、分配或异常。
     * @details 指针输入必须为有效 NUL 终止文本；文本存储在同步消费返回前保持有效。
     *          FixedText 不增加隐式转换，返回值不拥有输入；取消/关闭/executor 不适用。
     */
    template <typename Value> requires ViewInput<Value>
    [[nodiscard]] auto BorrowView(const Value& Input) noexcept -> std::string_view
    {
        if constexpr (ViewInputType<std::remove_cvref_t<Value>>::value && requires { Input.View(); })
        {
            return Input.View();
        }
        else { return std::string_view(Input); }
    }
}
