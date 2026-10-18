/**
 * @file ContextDecoder.hpp
 * @brief 按 RenderMode 渲染后台已经解码的拥有型记录。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldCatalog.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Diagnose::Detail
{

    /**
     * @brief 渲染人类可读或结构化消息。
     * @details 只在后台或控制线程读取已拥有记录；请求快照统一由 ContextSnapshot 完成。
     */
    class ContextDecoder final
    {
    public:
        /**
         * @brief 将上下文和消息拼成人类可读正文。
         * @param Context 已捕获的前缀和扩展字段。
         * @param Message 消息正文。
         * @return 按前缀、字段、正文顺序组合的字符串；不添加时间戳或级别。
         */
        [[nodiscard]] static auto RenderHuman(const CapturedContext& Context, const std::string_view Message)
            -> std::string
        {
            std::string Result(Context.Prefix.View());
            for (const auto& Field : Context.Fields)
            {
                if (!Result.empty())
                {
                    Result.push_back(' ');
                }
                Result.push_back('[');
                Result.append(FieldName(Field.Id));
                Result.push_back('=');
                AppendHumanValue(Result, Field);
                Result.push_back(']');
            }
            if (!Message.empty())
            {
                if (!Result.empty())
                {
                    Result.push_back(' ');
                }
                AppendHumanText(Result, Message);
            }
            return Result;
        }

        /**
         * @brief 将一条记录渲染为单行 JSON。
         * @param Record 含时间、序号、级别、提交类型、身份、字段和消息的记录。
         * @return 以换行符结尾的 UTF-8 JSON 文本；顶层 JSON 键使用大驼峰。
         */
        [[nodiscard]] static auto RenderStructured(const SubmissionRecord& Record) -> std::string
        {
            std::string Output;
            Output.reserve(128U + Record.Message.size());
            Output.append("{\"Timestamp\":");
            AppendUnsigned(Output, Record.TimestampMilliseconds);
            Output.append(",\"Sequence\":");
            AppendUnsigned(Output, Record.Sequence);
            Output.append(",\"Level\":");
            AppendJsonString(Output, LogLevelName(Record.Level));
            Output.append(",\"Kind\":");
            if (Record.Kind == SubmissionKind::Audit) { AppendJsonString(Output, "Audit"); }
            else { AppendJsonString(Output, "Ordinary"); }
            Output.append(",\"Worker\":");
            AppendOptionalId(Output, Record.Context.Prefix.Worker());
            Output.append(",\"Session\":");
            AppendOptionalId(Output, Record.Context.Prefix.Session());
            Output.append(",\"Fields\":{");
            for (std::size_t Index = 0; Index < Record.Context.Fields.size(); ++Index)
            {
                if (Index != 0U)
                {
                    Output.push_back(',');
                }
                const auto& Field = Record.Context.Fields[Index];
                AppendJsonString(Output, FieldName(Field.Id));
                Output.push_back(':');
                AppendJsonValue(Output, Field);
            }
            Output.append("},\"Message\":");
            AppendJsonString(Output, Record.Message);
            if (Record.MessageTruncated) { Output.append(",\"MessageTruncated\":true"); }
            Output.append("}\n");
            return Output;
        }

        /**
         * @brief 根据记录的渲染模式选择人类或结构化输出。
         * @param Record 待渲染的拥有型记录。
         * @return 格式化后的消息正文。
         */
        [[nodiscard]] static auto Render(const SubmissionRecord& Record) -> std::string
        {
            if (Record.Context.Mode == RenderMode::Structured)
            {
                return RenderStructured(Record);
            }
            return RenderHuman(Record.Context, Record.Message);
        }

    private:
        /**
         * @brief 按字段 ID 查询用于输出的字段名称。
         * @param Id 字段 ID。
         * @return 目录中该字段的名称；未知 ID 返回空视图。
         */
        [[nodiscard]] static auto FieldName(const FieldId Id) noexcept -> std::string_view
        {
            if (const auto Descriptor = FieldCatalog::Find(Id))
            {
                return Descriptor->Name;
            }
            return {};
        }

        /**
         * @brief 将字段值以人类可读形式追加到输出字符串。
         * @param Output 接收追加内容的字符串。
         * @param Field 要格式化的拥有型字段。
         */
        static auto AppendHumanValue(std::string& Output, const CapturedField& Field) -> void
        {
            if (IsTextFieldKind(Field.Kind))
            {
                AppendHumanText(Output, Field.Text);
            }
            else if (Field.Kind == FieldValueKind::Boolean)
            {
                if (Field.Boolean)
                {
                    Output.append("true");
                }
                else
                {
                    Output.append("false");
                }
            }
            else
            {
                AppendUnsigned(Output, Field.Unsigned);
            }
        }

        /**
         * @brief 将人类可读文本中的控制字节转义，保持每条日志占一行。
         * @param Output 接收转义文本的字符串。
         * @param Value 待写入的人类可读文本。
         */
        static auto AppendHumanText(std::string& Output, const std::string_view Value) -> void
        {
            constexpr char Hex[] = "0123456789ABCDEF";
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                if (Byte == '\n')
                {
                    Output.append("\\n");
                }
                else if (Byte == '\r')
                {
                    Output.append("\\r");
                }
                else if (Byte == '\t')
                {
                    Output.append("\\t");
                }
                else if (Byte < 0x20U || Byte == 0x7FU)
                {
                    Output.append("\\x");
                    Output.push_back(Hex[(Byte >> 4U) & 0x0FU]);
                    Output.push_back(Hex[Byte & 0x0FU]);
                }
                else
                {
                    Output.push_back(Character);
                }
            }
        }

        /**
         * @brief 将字段值以 JSON 字符串、布尔值或数字形式追加到输出。
         * @param Output 接收追加内容的 JSON 字符串。
         * @param Field 要序列化的拥有型字段。
         */
        static auto AppendJsonValue(std::string& Output, const CapturedField& Field) -> void
        {
            if (IsTextFieldKind(Field.Kind))
            {
                AppendJsonString(Output, Field.Text);
            }
            else if (Field.Kind == FieldValueKind::Boolean)
            {
                if (Field.Boolean)
                {
                    Output.append("true");
                }
                else
                {
                    Output.append("false");
                }
            }
            else
            {
                AppendUnsigned(Output, Field.Unsigned);
            }
        }

        /**
         * @brief 将可选强类型 ID 追加为 JSON 数字或 null。
         * @tparam Id 提供 Value() 数值访问器的强类型 ID。
         * @param Output 接收追加内容的 JSON 字符串。
         * @param Value 可选 ID；空值输出为 null。
         */
        template <typename Id>
        static auto AppendOptionalId(std::string& Output, const std::optional<Id> Value) -> void
        {
            if (Value)
            {
                AppendUnsigned(Output, Value->Value());
            }
            else
            {
                Output.append("null");
            }
        }

        /**
         * @brief 将整数值以十进制形式追加到输出字符串。
         * @tparam Value std::to_chars 支持的整数类型。
         * @param Output 接收数字文本的字符串。
         * @param Number 要转换的数值。
         */
        template <typename Value>
        static auto AppendUnsigned(std::string& Output, const Value Number) -> void
        {
            std::array<char, 32> Buffer{};
            const auto Converted = std::to_chars(Buffer.data(), Buffer.data() + Buffer.size(), Number);
            if (Converted.ec == std::errc{})
            {
                Output.append(Buffer.data(), Converted.ptr);
            }
        }

        /**
         * @brief 将文本追加为转义后的 JSON 字符串。
         * @param Output 接收 JSON 字符串的目标。
         * @param Value 待序列化的 UTF-8 文本。
         * @details 转义引号、反斜线和控制字节；非法 UTF-8 字节替换为 U+FFFD。
         */
        static auto AppendJsonString(std::string& Output, const std::string_view Value) -> void
        {
            constexpr char Hex[] = "0123456789ABCDEF";
            Output.push_back('"');
            for (std::size_t Index = 0; Index < Value.size();)
            {
                const auto Byte = static_cast<unsigned char>(Value[Index]);
                if (Byte == '"' || Byte == '\\')
                {
                    Output.push_back('\\');
                    Output.push_back(static_cast<char>(Byte));
                    ++Index;
                }
                else if (Byte < 0x20U)
                {
                    Output.append("\\u00");
                    Output.push_back(Hex[(Byte >> 4U) & 0x0FU]);
                    Output.push_back(Hex[Byte & 0x0FU]);
                    ++Index;
                }
                else
                {
                    const auto Length = ValidUtf8Length(Value, Index);
                    if (Length == 0U)
                    {
                        Output.append("\\uFFFD");
                        ++Index;
                    }
                    else
                    {
                        Output.append(Value.substr(Index, Length));
                        Index += Length;
                    }
                }
            }
            Output.push_back('"');
        }

        /**
         * @brief 检查指定位置是否开始有效且完整的 UTF-8 字符。
         * @param Value 待检查的文本视图。
         * @param Index 要检查的字节偏移，调用方须保证小于 Value.size()。
         * @return 字符占用的字节数；非法、不完整或非规范编码返回 0。
         */
        [[nodiscard]] static auto ValidUtf8Length(const std::string_view Value,
            const std::size_t Index) noexcept -> std::size_t
        {
            const auto First = static_cast<unsigned char>(Value[Index]);
            if (First <= 0x7FU)
            {
                return 1U;
            }
            std::size_t Length = 0U;
            if (First >= 0xC2U && First <= 0xDFU)
            {
                Length = 2U;
            }
            else if (First >= 0xE0U && First <= 0xEFU)
            {
                Length = 3U;
            }
            else if (First >= 0xF0U && First <= 0xF4U)
            {
                Length = 4U;
            }
            else
            {
                return 0U;
            }
            if (Length > Value.size() - Index)
            {
                return 0U;
            }
            for (std::size_t Offset = 1U; Offset < Length; ++Offset)
            {
                const auto Byte = static_cast<unsigned char>(Value[Index + Offset]);
                if ((Byte & 0xC0U) != 0x80U)
                {
                    return 0U;
                }
                if (Offset == 1U &&
                    ((First == 0xE0U && Byte < 0xA0U) || (First == 0xEDU && Byte > 0x9FU) ||
                        (First == 0xF0U && Byte < 0x90U) || (First == 0xF4U && Byte > 0x8FU)))
                {
                    return 0U;
                }
            }
            return Length;
        }

        /**
         * @brief 返回日志输出使用的大驼峰级别名称。
         * @param Level 日志级别。
         * @return 对应名称；未知枚举值回退为 "Off"。
         */
        [[nodiscard]] static auto LogLevelName(const LogLevel Level) noexcept -> std::string_view
        {
            return Prism::Diagnose::LogLevelName(Level);
        }
    };

} // namespace Prism::Diagnose::Detail
