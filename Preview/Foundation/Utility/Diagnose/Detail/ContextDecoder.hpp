/**
 * @file ContextDecoder.hpp
 * @brief 按 RenderMode 捕获并渲染 Diagnose 上下文。
 */
#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldCatalog.hpp>
#include <Preview/Statistics/Redaction.hpp>
#include <Preview/Statistics/Trace.hpp>

namespace Preview::Diagnose::Detail
{

    /**
     * @brief 捕获上下文字段并渲染人类可读或结构化消息。
     * @details Capture() 会把选中的字段复制为拥有型快照，并在复制文本时执行脱敏和长度限制；
     *          Render() 只读取该快照，不依赖原始 ContextState 的生命周期。
     */
    class ContextDecoder final
    {
    public:
        /**
         * @brief 按输出模式和字段选择捕获上下文。
         * @param Context 要捕获的上下文状态。
         * @param Mode 人类精简、人类带字段或结构化输出模式。
         * @param Selection HumanWithFields 模式下控制身份字段是否输出；Structured 模式包含目录中的全部字段。
         * @return 含渲染模式、固定前缀和拥有型字段值的上下文快照。
         * @details CompactHuman 只复制 Worker/Session 前缀，不遍历字段目录。
         */
        [[nodiscard]] static auto Capture(const ContextState &Context, const RenderMode Mode,
                                          const Preview::Statistics::TraceSelection Selection = {})
            -> CapturedContext
        {
            CapturedContext Result;
            Result.Mode = Mode;
            if (Context.Auxiliary_)
            {
                Result.Prefix = Context.Auxiliary_->Prefix;
            }
            if (Mode == RenderMode::CompactHuman)
            {
                return Result;
            }

            // 扩展模式才遍历冻结目录，并按 Selection 和字段可见性选择快照内容。
            for (const auto &Descriptor : FieldCatalog::Descriptors())
            {
                if (!IsSelected(Descriptor, Mode, Selection))
                {
                    continue;
                }
                if (Descriptor.ContextIdentity && Mode == RenderMode::Structured)
                {
                    continue;
                }
                if (Descriptor.ContextIdentity)
                {
                    if (const auto Identity = IdentityValue(Context, Descriptor.Id))
                    {
                        CapturedField Field;
                        Field.Id = Descriptor.Id;
                        Field.Kind = FieldValueKind::Unsigned;
                        Field.Unsigned = *Identity;
                        Result.Fields.push_back(std::move(Field));
                    }
                    continue;
                }
                const auto *Binding = FindBinding(Context, Descriptor.Id);
                if (Binding == nullptr)
                {
                    continue;
                }
                Result.Fields.push_back(CaptureField(*Binding, Descriptor));
            }
            return Result;
        }

        /**
         * @brief 将上下文和消息拼成人类可读正文。
         * @param Context 已捕获的前缀和扩展字段。
         * @param Message 消息正文。
         * @return 按前缀、字段、正文顺序组合的字符串；不添加时间戳或级别。
         */
        [[nodiscard]] static auto RenderHuman(const CapturedContext &Context, const std::string_view Message)
            -> std::string
        {
            std::string Result(Context.Prefix.View());
            for (const auto &Field : Context.Fields)
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
         * @param Record 含时间、线程、序号、级别、提交类型、身份、字段和消息的记录。
         * @return 以换行符结尾的 UTF-8 JSON 文本；Worker/Session 只输出在顶层身份属性。
         */
        [[nodiscard]] static auto RenderStructured(const SubmissionRecord &Record) -> std::string
        {
            std::string Output;
            Output.reserve(128U + Record.Message.size());
            Output.append("{\"timestamp\":");
            AppendUnsigned(Output, Record.TimestampMilliseconds);
            Output.append(",\"thread\":");
            AppendUnsigned(Output, Record.ThreadId);
            Output.append(",\"sequence\":");
            AppendUnsigned(Output, Record.Sequence);
            Output.append(",\"level\":");
            AppendJsonString(Output, LogLevelName(Record.Level));
            Output.append(",\"kind\":");
            AppendJsonString(Output, Record.Kind == SubmissionKind::Audit ? "audit" : "ordinary");
            Output.append(",\"worker\":");
            AppendOptionalId(Output, Record.Context.Prefix.Worker());
            Output.append(",\"session\":");
            AppendOptionalId(Output, Record.Context.Prefix.Session());
            Output.append(",\"fields\":{");
            for (std::size_t Index = 0; Index < Record.Context.Fields.size(); ++Index)
            {
                if (Index != 0U)
                {
                    Output.push_back(',');
                }
                const auto &Field = Record.Context.Fields[Index];
                AppendJsonString(Output, FieldName(Field.Id));
                Output.push_back(':');
                AppendJsonValue(Output, Field);
            }
            Output.append("},\"message\":");
            AppendJsonString(Output, Record.Message);
            Output.append("}\n");
            return Output;
        }

        /**
         * @brief 根据记录的渲染模式选择人类或结构化输出。
         * @param Record 待渲染的拥有型记录。
         * @return 格式化后的消息正文。
         */
        [[nodiscard]] static auto Render(const SubmissionRecord &Record) -> std::string
        {
            if (Record.Context.Mode == RenderMode::Structured)
            {
                return RenderStructured(Record);
            }
            return RenderHuman(Record.Context, Record.Message);
        }

    private:
        /**
         * @brief 判断字段是否包含在本次捕获结果中。
         * @param Descriptor 字段的可见性和身份元数据。
         * @param Mode 当前渲染模式。
         * @param Selection HumanWithFields 模式的身份字段选择。
         * @return Structured 模式，或所选且可见的扩展字段返回 true。
         * @details Structured 模式总是包含目录字段；HumanWithFields 模式只对 Worker、Session、Correlation、Stream 应用 Selection。
         */
        [[nodiscard]] static auto IsSelected(const FieldDescriptor &Descriptor, const RenderMode Mode,
                                             const Preview::Statistics::TraceSelection &Selection) noexcept
            -> bool
        {
            if (Mode == RenderMode::Structured)
            {
                return true;
            }
            if (Descriptor.Id == FieldId::Correlation)
            {
                return Selection.IncludeCorrelation;
            }
            if (Descriptor.Id == FieldId::Stream)
            {
                return Selection.IncludeStream;
            }
            if (Descriptor.Id == FieldId::Worker)
            {
                return Selection.IncludeWorker;
            }
            if (Descriptor.Id == FieldId::Session)
            {
                return Selection.IncludeSession;
            }
            if (Mode == RenderMode::HumanWithFields)
            {
                return Descriptor.Visibility == FieldVisibility::HumanVisible;
            }
            return false;
        }
        /**
         * @brief 在上下文的 inline 区和长期字段区中查找绑定。
         * @param Context 要搜索的上下文。
         * @param Id 目标字段 ID。
         * @return 找到时返回指向上下文内部绑定的非拥有指针；未找到时返回 nullptr。
         * @note 返回指针不得在 ContextState 销毁或修改后继续使用。
         */
        [[nodiscard]] static auto FindBinding(const ContextState &Context, const FieldId Id) noexcept
            -> const FieldBinding *
        {
            for (std::size_t Index = 0; Index < Context.InlineCount_; ++Index)
            {
                if (Context.Inline_[Index].Id == Id)
                {
                    return &Context.Inline_[Index];
                }
            }
            if (Context.Auxiliary_)
            {
                for (const auto &Binding : Context.Auxiliary_->Overflow)
                {
                    if (Binding.Id == Id)
                    {
                        return &Binding;
                    }
                }
            }
            return nullptr;
        }

        /**
         * @brief 从上下文前缀中读取 Worker 或 Session 的数值身份。
         * @param Context 身份所在的上下文。
         * @param Id 必须是 Worker 或 Session 字段 ID。
         * @return 找到对应身份时返回其数值；未设置或字段 ID 不属于身份字段时返回空值。
         */
        [[nodiscard]] static auto IdentityValue(const ContextState &Context, const FieldId Id) noexcept
            -> std::optional<std::uint64_t>
        {
            if (Id == FieldId::Worker)
            {
                if (const auto Value = Context.WorkerId())
                {
                    return Value->Value();
                }
            }
            else if (Id == FieldId::Session)
            {
                if (const auto Value = Context.SessionId())
                {
                    return Value->Value();
                }
            }
            return {};
        }

        /**
         * @brief 将无拥有权绑定复制为可跨越异步边界的字段值。
         * @param Binding 上下文中的原始字段绑定。
         * @param Descriptor 对应字段的脱敏和长度策略。
         * @return 完整拥有文本、数值或布尔载荷的快照字段。
         * @details 文本先复制，再执行敏感信息脱敏和 UTF-8 字节限长；截断标志会合并原绑定和本次处理结果。
         */
        [[nodiscard]] static auto CaptureField(const FieldBinding &Binding, const FieldDescriptor &Descriptor)
            -> CapturedField
        {
            CapturedField Result;
            Result.Id = Binding.Id;
            Result.Kind = Binding.Kind;
            Result.Truncated = Binding.Truncated;
            if (IsTextFieldKind(Binding.Kind))
            {
                auto Text = std::string(Binding.Payload.Text);
                if (Descriptor.Sensitive)
                {
                    Text = Preview::Statistics::RedactSensitiveText(Text);
                }
                auto [Bounded, WasTruncated] = TruncateUtf8(Text, Descriptor.MaxLength);
                Result.Text = std::move(Bounded);
                Result.Truncated = Result.Truncated || WasTruncated;
            }
            else if (Binding.Kind == FieldValueKind::Boolean)
            {
                Result.Boolean = Binding.Payload.Boolean;
            }
            else
            {
                Result.Unsigned = Binding.Payload.Unsigned;
            }
            return Result;
        }

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
        static auto AppendHumanValue(std::string &Output, const CapturedField &Field) -> void
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
        static auto AppendHumanText(std::string &Output, const std::string_view Value) -> void
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
        static auto AppendJsonValue(std::string &Output, const CapturedField &Field) -> void
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
        static auto AppendOptionalId(std::string &Output, const std::optional<Id> Value) -> void
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
        static auto AppendUnsigned(std::string &Output, const Value Number) -> void
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
        static auto AppendJsonString(std::string &Output, const std::string_view Value) -> void
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
                if (Offset == 1U && ((First == 0xE0U && Byte < 0xA0U) || (First == 0xEDU && Byte > 0x9FU) ||
                                     (First == 0xF0U && Byte < 0x90U) || (First == 0xF4U && Byte > 0x8FU)))
                {
                    return 0U;
                }
            }
            return Length;
        }

        /**
         * @brief 返回结构化输出使用的小写级别名称。
         * @param Level 日志级别。
         * @return 对应的小写名称；未知枚举值回退为 "info"。
         */
        [[nodiscard]] static auto LogLevelName(const LogLevel Level) noexcept -> std::string_view
        {
            switch (Level)
            {
            case LogLevel::Trace: return "trace";
            case LogLevel::Debug: return "debug";
            case LogLevel::Info: return "info";
            case LogLevel::Access: return "access";
            case LogLevel::Warn: return "warning";
            case LogLevel::Error: return "error";
            case LogLevel::Critical: return "critical";
            case LogLevel::Off: return "off";
            }
            return "info";
        }
    };

} // namespace Preview::Diagnose::Detail
