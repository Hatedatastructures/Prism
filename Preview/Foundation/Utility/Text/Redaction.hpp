/**
 * @file Redaction.hpp
 * @brief 中立文本的边界脱敏；字段比较不分配，引号值尊重反斜线转义。
 */

#pragma once

#include <cctype>
#include <string>
#include <span>
#include <string_view>

namespace Preview::Text
{

    /** @brief 判断 ASCII 字段名字节；不依赖 locale。 */
    [[nodiscard]] inline auto IsFieldNameCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        return (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
            (Byte >= '0' && Byte <= '9') || Value == '_' || Value == '-';
    }

    /** @brief 逐字节比较 ASCII 字段名，不分配也不依赖全局 locale。 */
    [[nodiscard]] inline auto EqualsInsensitive(const std::string_view Left,
        const std::string_view Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        for (std::size_t Index = 0U; Index < Left.size(); ++Index)
        {
            auto A = static_cast<unsigned char>(Left[Index]);
            auto B = static_cast<unsigned char>(Right[Index]);
            if (A >= 'A' && A <= 'Z') { A += 'a' - 'A'; }
            if (B >= 'A' && B <= 'Z') { B += 'a' - 'A'; }
            if (A != B) { return false; }
        }
        return true;
    }

    /** @brief 无分配检查固定敏感字段集合。 */
    [[nodiscard]] inline auto IsSensitiveField(std::string_view Name) noexcept -> bool
    {
        constexpr std::string_view Names[]{"password", "passwd", "token", "secret", "psk",
            "credential", "credentials", "authorization", "private_key", "private-key", "key",
            "access_token", "access-token", "refresh_token", "refresh-token", "api_key", "api-key",
            "client_secret", "client-secret", "secret_key", "secret-key"};
        for (const auto Expected : Names)
        {
            if (EqualsInsensitive(Name, Expected))
            {
                return true;
            }
        }
        return false;
    }

    /** @brief 判断 Authorization 字段的 ASCII 大小写等价名称。 */
    [[nodiscard]] inline auto IsAuthorizationField(std::string_view Name) noexcept -> bool
    {
        return EqualsInsensitive(Name, "authorization");
    }

    /** @brief 检查完整 Bearer scheme 边界，避免前缀误判。 */
    [[nodiscard]] inline auto IsBearerScheme(const std::string_view Value) noexcept -> bool
    {
        if (Value.size() < 6U ||
            (Value.size() > 6U &&
             std::isspace(static_cast<unsigned char>(Value[6])) == 0))
        {
            return false;
        }
        return EqualsInsensitive(Value.substr(0U, 6U), "bearer");
    }

    [[nodiscard]] inline auto LooksLikeAssignment(const std::string_view Input,
                                                  std::size_t Position) noexcept -> bool
    {
        while (Position < Input.size() &&
               std::isspace(static_cast<unsigned char>(Input[Position])) != 0)
        {
            ++Position;
        }
        const auto NameStart = Position;
        while (Position < Input.size() && IsFieldNameCharacter(Input[Position]))
        {
            ++Position;
        }
        return Position > NameStart && Position < Input.size() &&
               (Input[Position] == '=' || Input[Position] == ':');
    }

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
        auto PushBack(const char Value) noexcept -> void
        {
            if (Size_ < Output_.size()) { Output_[Size_++] = Value; }
            else { Truncated_ = true; }
        }
        auto Append(const std::string_view Value) noexcept -> void
        {
            for (const auto Character : Value) { PushBack(Character); }
        }
        auto operator+=(const std::string_view Value) noexcept -> BoundedText&
        {
            Append(Value);
            return *this;
        }
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
        explicit StringWriter(std::string& Output) noexcept : Output_(Output) {}
        auto Append(const std::string_view Value) -> void { Output_.append(Value); }
        auto PushBack(const char Value) -> void { Output_.push_back(Value); }
    private:
        std::string& Output_;
    };

    /** @brief 在线程消费或冷路径创建拥有型脱敏字符串。 */
    [[nodiscard]] inline auto RedactSensitiveText(const std::string_view Input) -> std::string
    {
        std::string Output;
        Output.reserve(Input.size());
        StringWriter Writer(Output);
        AppendRedactedText(Input, Writer);
        return Output;
    }

} // namespace Preview::Text
