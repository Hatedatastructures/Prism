/**
 * @file Redaction.hpp
 * @brief 中立文本的边界脱敏；字段比较不分配，引号值尊重反斜线转义。
 */

#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <span>
#include <string_view>

namespace Prism::Text
{

    /** @brief 判断 ASCII 字段名字节；不依赖 locale。 */
    [[nodiscard]] auto IsFieldNameCharacter(char Value) noexcept -> bool;

    /** @brief 逐字节比较 ASCII 字段名，不分配也不依赖全局 locale。 */
    [[nodiscard]] auto EqualsInsensitive(std::string_view Left,
        std::string_view Right) noexcept -> bool;

    /** @brief 无分配检查固定敏感字段集合。 */
    [[nodiscard]] auto IsSensitiveField(std::string_view Name) noexcept -> bool;

    /** @brief 判断 Authorization 字段的 ASCII 大小写等价名称。 */
    [[nodiscard]] auto IsAuthorizationField(std::string_view Name) noexcept -> bool;

    /** @brief 检查完整 Bearer scheme 边界，避免前缀误判。 */
    [[nodiscard]] auto IsBearerScheme(std::string_view Value) noexcept -> bool;

    [[nodiscard]] auto LooksLikeAssignment(std::string_view Input,
        std::size_t Position) noexcept -> bool;

    /** @brief 一个已识别 Authorization Bearer 字段的语法位置；只同步借用输入。 */
    struct AuthorizationValue final
    {
        std::string_view Input;
        std::size_t Position;
        char Separator;
    };

    /** @brief 输出 Bearer 脱敏值并返回下一字段位置，保留冒号/等号语法的区别。 */
    template <typename OutputType>
    [[nodiscard]] inline auto AppendRedactedBearer(AuthorizationValue Value,
                                                  OutputType &Output) -> std::size_t
    {
        const auto Input = Value.Input;
        const auto Separator = Value.Separator;
        auto Probe = Value.Position;
        if (Separator == ':')
        {
            Output.Append(Input.substr(Probe, 6U));
            Probe += 6U;
            while (Probe < Input.size() &&
                   std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                Output.PushBack(Input[Probe++]);
            }
            Output.Append("<redacted>");
            while (Probe < Input.size() &&
                   !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                   Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
            {
                ++Probe;
            }
        }
        else
        {
            Output.Append("<redacted>");
            Probe += 6U;
            const auto NextField = Probe;
            while (Probe < Input.size() &&
                   std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                ++Probe;
            }
            if (LooksLikeAssignment(Input, Probe))
            {
                Probe = NextField;
            }
            else
            {
                while (Probe < Input.size() &&
                       !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                       Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
                {
                    ++Probe;
                }
            }
        }
        return Probe;
    }

    /**
     * @brief 脱敏常见 key=value、key:value 和 JSON 风格的敏感字段。
     */
    template <typename OutputType>
    inline auto AppendRedactedText(std::string_view Input, OutputType &Output) -> void
    {

        std::size_t Index = 0;
        while (Index < Input.size())
        {
            const bool Boundary = Index == 0 || !IsFieldNameCharacter(Input[Index - 1]);
            if (!Boundary || !IsFieldNameCharacter(Input[Index]))
            {
                Output.PushBack(Input[Index++]);
                continue;
            }

            const auto NameStart = Index;
            while (Index < Input.size() && IsFieldNameCharacter(Input[Index]))
            {
                ++Index;
            }
            const auto NameEnd = Index;
            const auto Name = Input.substr(NameStart, NameEnd - NameStart);

            auto Probe = NameEnd;
            if (Probe < Input.size() && (Input[Probe] == '"' || Input[Probe] == '\''))
            {
                ++Probe;
            }
            while (Probe < Input.size() && std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                ++Probe;
            }
            if (Probe >= Input.size() || (Input[Probe] != '=' && Input[Probe] != ':') ||
                !IsSensitiveField(Name))
            {
                Output.Append(Input.substr(NameStart, NameEnd - NameStart));
                continue;
            }

            const char Separator = Input[Probe];
            Output.Append(Input.substr(NameStart, Probe - NameStart + 1));
            ++Probe;
            while (Probe < Input.size() && std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                Output.PushBack(Input[Probe++]);
            }

            if ((Separator == ':' || Separator == '=') && IsAuthorizationField(Name) &&
                Probe < Input.size() && IsBearerScheme(Input.substr(Probe)))
            {
                Index = AppendRedactedBearer({Input, Probe, Separator}, Output);

                continue;
            }

            if (Probe < Input.size() && (Input[Probe] == '"' || Input[Probe] == '\''))
            {
                const char Quote = Input[Probe++];
                Output.PushBack(Quote);
                Output.Append("<redacted>");
                while (Probe < Input.size() && Input[Probe] != Quote)
                {
                    if (Input[Probe] == '\\' && Probe + 1U < Input.size())
                    {
                        Probe += 2U;
                    }
                    else
                    {
                        ++Probe;
                    }
                }
                if (Probe < Input.size())
                {
                    Output.PushBack(Input[Probe++]);
                }
            }
            else
            {
                Output.Append("<redacted>");
                while (Probe < Input.size() && !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                       Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
                {
                    ++Probe;
                }
            }
            Index = Probe;
        }
    }

    /** @brief 固定目标文本写入器；容量满后只记录截断，不分配。 */
    class BoundedText final
    {
    public:
        explicit BoundedText(const std::span<char> Output) noexcept : Output_(Output) {}
        auto PushBack(const char Value) noexcept -> void;
        auto Append(const std::string_view Value) noexcept -> void;
        auto operator+=(const std::string_view Value) noexcept -> BoundedText&;
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
        [[nodiscard]] auto Truncated() const noexcept -> bool { return Truncated_; }
    private:
        std::span<char> Output_;
        std::size_t Size_{0U};
        bool Truncated_{false};
    };

    /** @brief 动态字符串只在后台/冷路径使用，领域操作名称不受 std 容器拼写影响。 */
    class StringWriter final
    {
    public:
        explicit StringWriter(std::string& Output) noexcept;
        auto Append(const std::string_view Value) -> void;
        auto PushBack(const char Value) -> void;

    private:
        std::string& Output_;
    };

    /** @brief 在线程消费或冷路径创建拥有型脱敏字符串。 */
    [[nodiscard]] auto RedactSensitiveText(std::string_view Input) -> std::string;

} // namespace Prism::Text
