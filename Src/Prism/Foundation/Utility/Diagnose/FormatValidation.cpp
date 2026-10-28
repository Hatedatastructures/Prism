/**
 * @file FormatValidation.cpp
 * @brief 标准格式动态值与累计工作量验证实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Submission/Message.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>

namespace Prism::Diagnose::Detail
{
    namespace
    {
        /**
         * @brief 无异常读取已经编译期检查的标准格式，校验运行时 width/precision/整数 c 值。
         * @details 标准 formatter 仍负责实际输出。采用显式 classic locale，排除外部用户 facet 的无界行为。
         *          每字段同时累计原文本扫描、debug 转义、浮点精度和最多四字节 fill 的输出工作量。
         *          负动态值/字符越界是 InvalidArgument；合法值超过观察额度是 OversizedMsg。
         */
    class FormatValidation final
    {
        struct Specifier final
        {
            std::size_t Width{0U};
            std::size_t Precision{0U};
            std::size_t FillBytes{1U};
            bool HasPrecision{false};
            char Presentation{'\0'};
        };
        using Failure = Prism::Fault::Failure;
        using Code = Prism::Fault::Code;
    public:
        FormatValidation(const std::string_view Format, const std::span<const FormatValue> Values,
            const FormattingLimits& Limits) noexcept : Format_(Format), Values_(Values), Limits_(Limits) {}
        [[nodiscard]] auto Validate() noexcept -> Failure
        {
            if (!Spend(Format_.size())) { return {Code::OversizedMsg}; }
            while (Position_ < Format_.size())
            {
                const auto Character = Format_[Position_++];
                if (Character != '{' && Character != '}') { continue; }
                if (Position_ < Format_.size() && Format_[Position_] == Character) { ++Position_; continue; }
                if (Character == '}') { return {Code::InvalidArgument}; }
                const auto Index = ReadIndex();
                if (Failure_.Failed()) { return Failure_; }
                Specifier Spec;
                if (Peek() == ':')
                {
                    ++Position_;
                    ReadSpecifier(Spec);
                    if (Failure_.Failed()) { return Failure_; }
                }
                if (Peek() != '}' || Index >= Values_.size()) { return {Code::InvalidArgument}; }
                ++Position_;
                const auto Checked = CheckField(Values_[Index], Spec);
                if (Checked.Failed()) { return Checked; }
            }
            return {};
        }
    private:
        [[nodiscard]] auto Peek() const noexcept -> char
        {
            if (Position_ < Format_.size()) { return Format_[Position_]; }
            return '\0';
        }
        [[nodiscard]] static auto Digit(const char Value) noexcept -> bool { return Value >= '0' && Value <= '9'; }
        [[nodiscard]] static auto Alignment(const char Value) noexcept -> bool { return Value == '<' || Value == '>' || Value == '^'; }
        [[nodiscard]] auto ReadNumber() noexcept -> std::size_t
        {
            std::size_t Number = 0U;
            while (Digit(Peek()))
            {
                const auto Value = static_cast<std::size_t>(Format_[Position_++] - '0');
                if (Number > (std::numeric_limits<std::size_t>::max() - Value) / 10U)
                {
                    Failure_ = {Code::OversizedMsg};
                    return 0U;
                }
                Number = Number * 10U + Value;
            }
            return Number;
        }
        [[nodiscard]] auto ReadIndex() noexcept -> std::size_t
        {
            if (Digit(Peek()))
            {
                if (Automatic_) { Failure_ = {Code::InvalidArgument}; return 0U; }
                Manual_ = true;
                return ReadNumber();
            }
            if (Manual_) { Failure_ = {Code::InvalidArgument}; return 0U; }
            Automatic_ = true;
            return NextIndex_++;
        }
        [[nodiscard]] auto ReadAmount(const std::size_t Maximum) noexcept -> std::size_t
        {
            auto Amount = std::size_t{0U};
            if (Peek() == '{')
            {
                ++Position_;
                const auto Index = ReadIndex();
                if (Failure_.Failed() || Index >= Values_.size() || Peek() != '}')
                {
                    Failure_ = {Code::InvalidArgument};
                    return 0U;
                }
                ++Position_;
                const auto& Value = Values_[Index];
                if (Value.Kind == FormatValueKind::Signed && Value.Signed >= 0)
                {
                    if (static_cast<std::uint64_t>(Value.Signed) > std::numeric_limits<std::size_t>::max())
                    {
                        Failure_ = {Code::OversizedMsg};
                        return 0U;
                    }
                    Amount = static_cast<std::size_t>(Value.Signed);
                }
                else if (Value.Kind == FormatValueKind::Unsigned)
                {
                    if (Value.Unsigned > std::numeric_limits<std::size_t>::max())
                    {
                        Failure_ = {Code::OversizedMsg};
                        return 0U;
                    }
                    Amount = static_cast<std::size_t>(Value.Unsigned);
                }
                else { Failure_ = {Code::InvalidArgument}; return 0U; }
            }
            else if (Digit(Peek())) { Amount = ReadNumber(); }
            else { Failure_ = {Code::InvalidArgument}; return 0U; }
            if (Amount > Maximum) { Failure_ = {Code::OversizedMsg}; }
            return Amount;
        }
        auto ReadSpecifier(Specifier& Spec) noexcept -> void
        {
            const auto Remaining = Format_.size() - Position_;
            if (Remaining == 0U) { Failure_ = {Code::InvalidArgument}; return; }
            std::size_t FillBytes = 1U;
            const auto First = static_cast<unsigned char>(Peek());
            if (First >= 0xC2U && First <= 0xDFU) { FillBytes = 2U; }
            else if (First >= 0xE0U && First <= 0xEFU) { FillBytes = 3U; }
            else if (First >= 0xF0U && First <= 0xF4U) { FillBytes = 4U; }
            if (Remaining > FillBytes && Alignment(Format_[Position_ + FillBytes]))
            {
                Spec.FillBytes = FillBytes;
                Position_ += FillBytes + 1U;
            }
            else if (Alignment(Peek())) { ++Position_; }
            if (Peek() == '+' || Peek() == '-' || Peek() == ' ') { ++Position_; }
            if (Peek() == '#') { ++Position_; }
            if (Peek() == '0') { ++Position_; }
            if (Digit(Peek()) || Peek() == '{') { Spec.Width = ReadAmount(Limits_.MaximumWidth); }
            if (Failure_.Failed()) { return; }
            if (Peek() == '.')
            {
                ++Position_;
                Spec.HasPrecision = true;
                Spec.Precision = ReadAmount(Limits_.MaximumPrecision);
            }
            if (Failure_.Failed()) { return; }
            if (Peek() == 'L') { ++Position_; }
            if (Peek() != '}') { Spec.Presentation = Peek(); ++Position_; }
        }
        [[nodiscard]] auto CheckField(const FormatValue& Value, const Specifier& Spec) noexcept -> Failure
        {
            if (Spec.Presentation == 'c')
            {
                if (Value.Kind == FormatValueKind::Signed &&
                    (Value.Signed < std::numeric_limits<char>::min() || Value.Signed > std::numeric_limits<char>::max()))
                {
                    return {Code::InvalidArgument};
                }
                if (Value.Kind == FormatValueKind::Unsigned &&
                    Value.Unsigned > static_cast<std::uint64_t>(std::numeric_limits<char>::max()))
                {
                    return {Code::InvalidArgument};
                }
            }
            std::size_t Produced = 128U;
            std::size_t Scanned = 0U;
            if (Value.Kind == FormatValueKind::Text)
            {
                Scanned = Value.TextBytes;
                Produced = Value.TextBytes;
                if (Spec.HasPrecision) { Produced = (std::min)(Produced, Spec.Precision * 4U); }
                if (Spec.Presentation == '?') { Produced = Produced * 10U + 2U; }
            }
            else if (Value.Kind == FormatValueKind::Float)
            {
                auto Precision = std::size_t{64U};
                if (Spec.HasPrecision) { Precision = Spec.Precision; }
                Produced = Value.FloatIntegerDigits + Precision + 64U;
                Scanned = Precision;
            }
            if (!Spend(Scanned) || !Spend(Produced) || !Spend(Spec.Width * Spec.FillBytes)) { return {Code::OversizedMsg}; }
            return {};
        }
        [[nodiscard]] auto Spend(const std::size_t Amount) noexcept -> bool
        {
            if (Amount > Limits_.WorkBytes - Spent_) { return false; }
            Spent_ += Amount;
            return true;
        }
        const std::string_view Format_;
        const std::span<const FormatValue> Values_;
        const FormattingLimits& Limits_;
        std::size_t Position_{0U}, NextIndex_{0U}, Spent_{0U};
        bool Automatic_{false}, Manual_{false};
        Failure Failure_{};
    };
    }

    auto ValidateFormat(const std::string_view Format, const std::span<const FormatValue> Values,
        const FormattingLimits& Limits) noexcept -> Prism::Fault::Failure
    {
        FormatValidation Validation(Format, Values, Limits);
        return Validation.Validate();
    }
}
