/**
 * @file FieldCodec.hpp
 * @brief Diagnose 字段类型约束和边界编码。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>
#include <Prism/Foundation/Utility/Text/View.hpp>
#include <Prism/Foundation/Utility/Text/Truncate.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace Prism::Diagnose
{

    /**
     * @brief 编译期判断 key 与值类型是否符合字段定义。
     * @details 文本字段只接受无分配、无用户转换的正式 Text::ViewInput；其他字段要求去除 cv/ref 后的值类型
     * 与字段定义中的 ValueType 完全相同。
     * @tparam Key 待检查的类型化字段 key。
     * @tparam Value 待写入字段的值类型。
     */
    template <typename Key, typename Value>
    [[nodiscard]] constexpr auto ComputeFieldValueCompatibility() noexcept -> bool
    {
        using KeyType = std::remove_cvref_t<Key>;
        using Definition = typename KeyType::DefinitionType;
        if constexpr (IsTextFieldKind(Definition::Kind))
        {
            return Text::ViewInput<Value>;
        }
        else
        {
            return std::same_as<std::remove_cvref_t<Value>, typename Definition::ValueType>;
        }
    }

    template <typename Key, typename Value>
    inline constexpr bool FieldValueCompatibleValue = ComputeFieldValueCompatibility<Key, Value>();

    /**
     * @brief 约束字段 key 与提交值之间的类型兼容性。
     * @details 仅当 Key 定义了 DefinitionType，且 Value 满足该字段的文本转换或精确类型规则时成立。
     * @tparam Key 待检查的类型化字段 key。
     * @tparam Value 待写入字段的值类型。
     */
    template <typename Key, typename Value>
    concept FieldValueCompatible = requires { typename std::remove_cvref_t<Key>::DefinitionType; } &&
        FieldValueCompatibleValue<Key, Value>;

    /**
     * @brief 可安全跨越异步提交边界的自有字段值。
     * @details 文本已复制到本对象，并由字段策略执行脱敏和长度限制，因此不再依赖调用方文本的生命周期。
     */
    struct EncodedFieldValue final
    {
        FieldId Id{}; ///< 被编码字段的稳定 ID。
        FieldValueKind Kind{FieldValueKind::Unsigned}; ///< 编码后的值类型。
        std::uint64_t Unsigned{0U}; ///< 数值、枚举和强类型 ID 的编码结果。
        bool Boolean{false}; ///< 布尔字段值。
        std::string Text{}; ///< 已拥有、已限长并按策略脱敏的 UTF-8 文本。
        bool Truncated{false}; ///< 文本是否因最大长度约束被截断。
    };

    namespace Detail
    {

        /**
         * @brief 将 UTF-8 文本限制在指定字节数内。
         * @details 截断时尽量保持字符边界，并在可用长度允许时追加固定截断标记。
         * 若上限不大于标记长度，则仅保留标记前缀。
         * @param Input 原始文本。
         * @param Maximum 输出文本的最大字节数。
         * @return 第一项为限长后的字符串，第二项表示是否发生截断。
         */
        [[nodiscard]] auto TruncateUtf8(std::string_view Input, std::size_t Maximum)
            -> std::pair<std::string, bool>;

        /**
         * @brief 将整数、枚举或强类型 ID 转换为无符号存储值。
         * @tparam Value 输入值类型；支持枚举、提供 Value() 的 ID 类型或可转换为 uint64_t 的整数类型。
         * @param Input 待转换的值。
         * @return 枚举底层值、ID 的 Value() 结果或整数输入对应的 uint64_t 值。
         */
        template <typename Value>
        [[nodiscard]] auto ToUnsigned(const Value& Input) noexcept -> std::uint64_t
        {
            if constexpr (std::is_enum_v<Value>)
            {
                return static_cast<std::uint64_t>(std::to_underlying(Input));
            }
            else if constexpr (requires { Input.Value(); })
            {
                return static_cast<std::uint64_t>(Input.Value());
            }
            else
            {
                return static_cast<std::uint64_t>(Input);
            }
        }

    } // namespace Detail

    /**
     * @brief 将类型化字段值编码为自有快照值。
     * @details 文本会先复制，再按字段策略脱敏，最后按最大 UTF-8 字节数截断；
     * 布尔值单独存储，数值、枚举和强类型 ID 编码为 uint64_t。
     * @tparam Definition 字段的编译期元数据类型。
     * @tparam Value 输入值的实际类型，须满足 FieldValueCompatible。
     * @param Key 与 Definition 对应的类型化字段 key。
     * @param Input 要编码的字段值。
     * @return 含字段 ID、编码类别和自有编码值的快照对象。
     */
    template <typename Definition, typename Value>
        requires FieldValueCompatible<FieldKey<Definition>, Value>
    [[nodiscard]] auto EncodeFieldValue(const FieldKey<Definition> Key, Value&& Input) -> EncodedFieldValue
    {
        EncodedFieldValue Result;
        Result.Id = Key.Id;
        Result.Kind = Definition::Kind;
        if constexpr (IsTextFieldKind(Definition::Kind))
        {
            auto Text = std::string(Prism::Text::BorrowView(Input));
            if constexpr (Definition::Sensitive)
            {
                Text = Prism::Text::RedactSensitiveText(Text);
            }
            auto [Bounded, WasTruncated] = Detail::TruncateUtf8(Text, Definition::MaxLength);
            Result.Text = std::move(Bounded);
            Result.Truncated = WasTruncated;
        }
        else if constexpr (Definition::Kind == FieldValueKind::Boolean)
        {
            Result.Boolean = static_cast<bool>(Input);
        }
        else
        {
            Result.Unsigned = Detail::ToUnsigned(Input);
        }
        return Result;
    }

} // namespace Prism::Diagnose
