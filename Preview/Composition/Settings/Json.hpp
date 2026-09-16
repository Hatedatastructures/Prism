/**
 * @file Json.hpp
 * @brief 最小 JSON 解析器（T5-9）
 * @details 自包含 JSON 子集（settings/loader 用）：
 *          - object / array / string / number / bool / null
 *          - 递归下降，深度上限 32
 *          - 字符串转义（\" \\ \/ \b \f \n \r \t \uXXXX）
 * @note 测试库自包含实现；生产用 glaze（src/prism）
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Preview::Settings
{

    /**
     * @class JsonError
     * @brief JSON 解析错误
     */
    class JsonError
    {
    public:
        std::size_t offset{0}; ///< 出错偏移
        std::string Message{}; ///< 错误描述

        [[nodiscard]] auto What() const -> std::string_view
        {
            return Message;
        }
    };

    struct JsonValue;

    /// JSON 数组（间接层，允许递归）
    struct JsonArray
    {
        std::vector<JsonValue> items;
    };

    /// JSON 对象（间接层，允许递归）
    struct JsonObject
    {
        std::map<std::string, JsonValue> members;
    };

    /// JSON 值（variant 表示）
    struct JsonValue
    {
        std::variant<std::nullptr_t, bool, double, std::string, JsonArray, JsonObject> Data;
    };

    namespace detail
    {
        /// 当前解析位置
        struct Cursor
        {
            std::string_view text; ///< 输入
            std::size_t pos{0};    ///< 当前位置
        };

        /// 跳过空白
        inline auto SkipWs(Cursor &c) -> void
        {
            while (c.pos < c.text.size() &&
                   (c.text[c.pos] == ' ' || c.text[c.pos] == '\t' || c.text[c.pos] == '\n' ||
                    c.text[c.pos] == '\r'))
            {
                ++c.pos;
            }
        }

        /// 解析失败
        [[nodiscard]] inline auto Fail(Cursor &c, std::string_view msg) -> JsonError
        {
            return JsonError{c.pos, std::string(msg)};
        }

        /// 解析字符串
        [[nodiscard]] inline auto ParseString(Cursor &c, std::string &out) -> JsonError
        {
            if (c.pos >= c.text.size() || c.text[c.pos] != '"')
            {
                return Fail(c, "expected string");
            }
            ++c.pos;
            while (c.pos < c.text.size())
            {
                const char ch = c.text[c.pos];
                if (ch == '"')
                {
                    ++c.pos;
                    return {};
                }
                if (ch == '\\')
                {
                    ++c.pos;
                    if (c.pos >= c.text.size())
                    {
                        return Fail(c, "unterminated escape");
                    }
                    switch (c.text[c.pos])
                    {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u':
                    {
                        // \uXXXX：简化为码点转 UTF-8（仅 BMP）
                        if (c.pos + 4 >= c.text.size())
                        {
                            return Fail(c, "bad \\u escape");
                        }
                        std::uint32_t Cp = 0;
                        for (int I = 1; I <= 4; ++I)
                        {
                            const char h = c.text[c.pos + I];
                            Cp <<= 4;
                            if (h >= '0' && h <= '9')
                            {
                                Cp |= static_cast<std::uint32_t>(h - '0');
                            }
                            else if (h >= 'a' && h <= 'f')
                            {
                                Cp |= static_cast<std::uint32_t>(h - 'a' + 10);
                            }
                            else if (h >= 'A' && h <= 'F')
                            {
                                Cp |= static_cast<std::uint32_t>(h - 'A' + 10);
                            }
                            else
                            {
                                return Fail(c, "bad hex in \\u");
                            }
                        }
                        c.pos += 4;
                        if (Cp < 0x80)
                        {
                            out.push_back(static_cast<char>(Cp));
                        }
                        else if (Cp < 0x800)
                        {
                            out.push_back(static_cast<char>(0xC0 | (Cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (Cp & 0x3F)));
                        }
                        else
                        {
                            out.push_back(static_cast<char>(0xE0 | (Cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((Cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (Cp & 0x3F)));
                        }
                        break;
                    }
                    default: return Fail(c, "unknown escape");
                    }
                    ++c.pos;
                    continue;
                }
                out.push_back(ch);
                ++c.pos;
            }
            return Fail(c, "unterminated string");
        }

        /// 解析数字
        [[nodiscard]] inline auto ParseNumber(Cursor &c, double &out) -> JsonError
        {
            const auto Start = c.pos;
            while (c.pos < c.text.size())
            {
                const char ch = c.text[c.pos];
                if ((ch >= '0' && ch <= '9') || ch == '-' || ch == '+' || ch == '.' || ch == 'e' ||
                    ch == 'E')
                {
                    ++c.pos;
                }
                else
                {
                    break;
                }
            }
            const auto Token = c.text.substr(Start, c.pos - Start);
            if (Token.empty())
            {
                return Fail(c, "expected number");
            }
            try
            {
                out = std::stod(std::string(Token));
            }
            catch (...)
            {
                return Fail(c, "bad number");
            }
            return {};
        }

        /// 解析值（递归下降）
        [[nodiscard]] inline auto ParseValue(Cursor &c, JsonValue &out, int depth) -> JsonError;

        /// 解析数组
        [[nodiscard]] inline auto ParseArray(Cursor &c, JsonValue &out, int depth) -> JsonError
        {
            auto &arr = out.Data.emplace<JsonArray>().items;
            ++c.pos; // [
            SkipWs(c);
            if (c.pos < c.text.size() && c.text[c.pos] == ']')
            {
                ++c.pos;
                return {};
            }
            while (c.pos < c.text.size())
            {
                JsonValue elem;
                auto Err = ParseValue(c, elem, depth);
                if (!Err.Message.empty())
                {
                    return Err;
                }
                arr.push_back(std::move(elem));
                SkipWs(c);
                if (c.pos >= c.text.size())
                {
                    return Fail(c, "unterminated array");
                }
                if (c.text[c.pos] == ']')
                {
                    ++c.pos;
                    return {};
                }
                if (c.text[c.pos] != ',')
                {
                    return Fail(c, "expected , or ]");
                }
                ++c.pos;
                SkipWs(c);
            }
            return Fail(c, "unterminated array");
        }

        /// 解析对象
        [[nodiscard]] inline auto ParseObject(Cursor &c, JsonValue &out, int depth) -> JsonError
        {
            auto &obj = out.Data.emplace<JsonObject>().members;
            ++c.pos; // {
            SkipWs(c);
            if (c.pos < c.text.size() && c.text[c.pos] == '}')
            {
                ++c.pos;
                return {};
            }
            while (c.pos < c.text.size())
            {
                SkipWs(c);
                std::string key;
                auto Err = ParseString(c, key);
                if (!Err.Message.empty())
                {
                    return Err;
                }
                SkipWs(c);
                if (c.pos >= c.text.size() || c.text[c.pos] != ':')
                {
                    return Fail(c, "expected :");
                }
                ++c.pos;
                SkipWs(c);
                JsonValue val;
                Err = ParseValue(c, val, depth);
                if (!Err.Message.empty())
                {
                    return Err;
                }
                obj.emplace(std::move(key), std::move(val));
                SkipWs(c);
                if (c.pos >= c.text.size())
                {
                    return Fail(c, "unterminated object");
                }
                if (c.text[c.pos] == '}')
                {
                    ++c.pos;
                    return {};
                }
                if (c.text[c.pos] != ',')
                {
                    return Fail(c, "expected , or }");
                }
                ++c.pos;
            }
            return Fail(c, "unterminated object");
        }

        inline auto ParseValue(Cursor &c, JsonValue &out, int depth) -> JsonError
        {
            if (depth > 32)
            {
                return Fail(c, "nesting too deep");
            }
            SkipWs(c);
            if (c.pos >= c.text.size())
            {
                return Fail(c, "unexpected end");
            }
            const char ch = c.text[c.pos];
            switch (ch)
            {
            case '{':
                return ParseObject(c, out, depth + 1);
            case '[':
                return ParseArray(c, out, depth + 1);
            case '"':
            {
                std::string s;
                auto Err = ParseString(c, s);
                out.Data = std::move(s);
                return Err;
            }
            case 't':
                if (c.text.substr(c.pos, 4) == "true")
                {
                    c.pos += 4;
                    out.Data = true;
                    return {};
                }
                return Fail(c, "bad literal");
            case 'f':
                if (c.text.substr(c.pos, 5) == "false")
                {
                    c.pos += 5;
                    out.Data = false;
                    return {};
                }
                return Fail(c, "bad literal");
            case 'n':
                if (c.text.substr(c.pos, 4) == "null")
                {
                    c.pos += 4;
                    out.Data = nullptr;
                    return {};
                }
                return Fail(c, "bad literal");
            default:
            {
                double Num = 0;
                auto Err = ParseNumber(c, Num);
                out.Data = Num;
                return Err;
            }
            }
        }
    } // namespace detail

    /**
     * @brief 解析 JSON 文本
     * @param text 输入
     * @param out 解析结果
     * @return 空 = 成功；否则 JsonError
     */
    [[nodiscard]] inline auto ParseJson(std::string_view text, JsonValue &out) -> JsonError
    {
        detail::Cursor c{text, 0};
        auto Err = detail::ParseValue(c, out, 0);
        if (!Err.Message.empty())
        {
            return Err;
        }
        detail::SkipWs(c);
        if (c.pos != text.size())
        {
            return detail::Fail(c, "trailing content");
        }
        return {};
    }

    /// 便捷访问：按路径取值（如 "a.b.0"）
    [[nodiscard]] inline auto Lookup(const JsonValue &root, std::string_view Path)
        -> const JsonValue *
    {
        const JsonValue *cur = &root;
        std::size_t Start = 0;
        while (Start <= Path.size())
        {
            const auto Dot = Path.find('.', Start);
            std::size_t SegLen = std::string_view::npos;
            if (Dot != std::string_view::npos)
            {
                SegLen = Dot - Start;
            }
            const auto Seg = Path.substr(Start, SegLen);
            if (cur->Data.index() == 4) // JsonArray
            {
                const auto &arr = std::get<JsonArray>(cur->Data).items;
                const auto Idx = std::strtoul(std::string(Seg).c_str(), nullptr, 10);
                if (Idx >= arr.size())
                {
                    return nullptr;
                }
                cur = &arr[Idx];
            }
            else if (cur->Data.index() == 5) // JsonObject
            {
                const auto &obj = std::get<JsonObject>(cur->Data).members;
                const auto It = obj.find(std::string(Seg));
                if (It == obj.end())
                {
                    return nullptr;
                }
                cur = &It->second;
            }
            else
            {
                return nullptr;
            }
            if (Dot == std::string_view::npos)
            {
                break;
            }
            Start = Dot + 1;
        }
        return cur;
    }

} // namespace Preview::Settings
