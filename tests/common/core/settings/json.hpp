/**
 * @file json.hpp
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

namespace preview::settings
{

    /**
     * @class json_error
     * @brief JSON 解析错误
     */
    class json_error
    {
    public:
        std::size_t offset{0}; ///< 出错偏移
        std::string message{}; ///< 错误描述

        [[nodiscard]] auto what() const -> std::string_view
        {
            return message;
        }
    };

    struct json_value;

    /// JSON 数组（间接层，允许递归）
    struct json_array
    {
        std::vector<json_value> items;
    };

    /// JSON 对象（间接层，允许递归）
    struct json_object
    {
        std::map<std::string, json_value> members;
    };

    /// JSON 值（variant 表示）
    struct json_value
    {
        std::variant<std::nullptr_t, bool, double, std::string, json_array, json_object> data;
    };

    namespace detail
    {
        /// 当前解析位置
        struct cursor
        {
            std::string_view text; ///< 输入
            std::size_t pos{0};    ///< 当前位置
        };

        /// 跳过空白
        inline auto skip_ws(cursor &c) -> void
        {
            while (c.pos < c.text.size() &&
                   (c.text[c.pos] == ' ' || c.text[c.pos] == '\t' || c.text[c.pos] == '\n' ||
                    c.text[c.pos] == '\r'))
            {
                ++c.pos;
            }
        }

        /// 解析失败
        [[nodiscard]] inline auto fail(cursor &c, std::string_view msg) -> json_error
        {
            return json_error{c.pos, std::string(msg)};
        }

        /// 解析字符串
        [[nodiscard]] inline auto parse_string(cursor &c, std::string &out) -> json_error
        {
            if (c.pos >= c.text.size() || c.text[c.pos] != '"')
            {
                return fail(c, "expected string");
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
                        return fail(c, "unterminated escape");
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
                            return fail(c, "bad \\u escape");
                        }
                        std::uint32_t cp = 0;
                        for (int i = 1; i <= 4; ++i)
                        {
                            const char h = c.text[c.pos + i];
                            cp <<= 4;
                            if (h >= '0' && h <= '9')
                            {
                                cp |= static_cast<std::uint32_t>(h - '0');
                            }
                            else if (h >= 'a' && h <= 'f')
                            {
                                cp |= static_cast<std::uint32_t>(h - 'a' + 10);
                            }
                            else if (h >= 'A' && h <= 'F')
                            {
                                cp |= static_cast<std::uint32_t>(h - 'A' + 10);
                            }
                            else
                            {
                                return fail(c, "bad hex in \\u");
                            }
                        }
                        c.pos += 4;
                        if (cp < 0x80)
                        {
                            out.push_back(static_cast<char>(cp));
                        }
                        else if (cp < 0x800)
                        {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        else
                        {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: return fail(c, "unknown escape");
                    }
                    ++c.pos;
                    continue;
                }
                out.push_back(ch);
                ++c.pos;
            }
            return fail(c, "unterminated string");
        }

        /// 解析数字
        [[nodiscard]] inline auto parse_number(cursor &c, double &out) -> json_error
        {
            const auto start = c.pos;
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
            const auto token = c.text.substr(start, c.pos - start);
            if (token.empty())
            {
                return fail(c, "expected number");
            }
            try
            {
                out = std::stod(std::string(token));
            }
            catch (...)
            {
                return fail(c, "bad number");
            }
            return {};
        }

        /// 解析值（递归下降）
        [[nodiscard]] inline auto parse_value(cursor &c, json_value &out, int depth) -> json_error;

        /// 解析数组
        [[nodiscard]] inline auto parse_array(cursor &c, json_value &out, int depth) -> json_error
        {
            auto &arr = out.data.emplace<json_array>().items;
            ++c.pos; // [
            skip_ws(c);
            if (c.pos < c.text.size() && c.text[c.pos] == ']')
            {
                ++c.pos;
                return {};
            }
            while (c.pos < c.text.size())
            {
                json_value elem;
                auto err = parse_value(c, elem, depth);
                if (!err.message.empty())
                {
                    return err;
                }
                arr.push_back(std::move(elem));
                skip_ws(c);
                if (c.pos >= c.text.size())
                {
                    return fail(c, "unterminated array");
                }
                if (c.text[c.pos] == ']')
                {
                    ++c.pos;
                    return {};
                }
                if (c.text[c.pos] != ',')
                {
                    return fail(c, "expected , or ]");
                }
                ++c.pos;
                skip_ws(c);
            }
            return fail(c, "unterminated array");
        }

        /// 解析对象
        [[nodiscard]] inline auto parse_object(cursor &c, json_value &out, int depth) -> json_error
        {
            auto &obj = out.data.emplace<json_object>().members;
            ++c.pos; // {
            skip_ws(c);
            if (c.pos < c.text.size() && c.text[c.pos] == '}')
            {
                ++c.pos;
                return {};
            }
            while (c.pos < c.text.size())
            {
                skip_ws(c);
                std::string key;
                auto err = parse_string(c, key);
                if (!err.message.empty())
                {
                    return err;
                }
                skip_ws(c);
                if (c.pos >= c.text.size() || c.text[c.pos] != ':')
                {
                    return fail(c, "expected :");
                }
                ++c.pos;
                skip_ws(c);
                json_value val;
                err = parse_value(c, val, depth);
                if (!err.message.empty())
                {
                    return err;
                }
                obj.emplace(std::move(key), std::move(val));
                skip_ws(c);
                if (c.pos >= c.text.size())
                {
                    return fail(c, "unterminated object");
                }
                if (c.text[c.pos] == '}')
                {
                    ++c.pos;
                    return {};
                }
                if (c.text[c.pos] != ',')
                {
                    return fail(c, "expected , or }");
                }
                ++c.pos;
            }
            return fail(c, "unterminated object");
        }

        inline auto parse_value(cursor &c, json_value &out, int depth) -> json_error
        {
            if (depth > 32)
            {
                return fail(c, "nesting too deep");
            }
            skip_ws(c);
            if (c.pos >= c.text.size())
            {
                return fail(c, "unexpected end");
            }
            const char ch = c.text[c.pos];
            switch (ch)
            {
            case '{':
                return parse_object(c, out, depth + 1);
            case '[':
                return parse_array(c, out, depth + 1);
            case '"':
            {
                std::string s;
                auto err = parse_string(c, s);
                out.data = std::move(s);
                return err;
            }
            case 't':
                if (c.text.substr(c.pos, 4) == "true")
                {
                    c.pos += 4;
                    out.data = true;
                    return {};
                }
                return fail(c, "bad literal");
            case 'f':
                if (c.text.substr(c.pos, 5) == "false")
                {
                    c.pos += 5;
                    out.data = false;
                    return {};
                }
                return fail(c, "bad literal");
            case 'n':
                if (c.text.substr(c.pos, 4) == "null")
                {
                    c.pos += 4;
                    out.data = nullptr;
                    return {};
                }
                return fail(c, "bad literal");
            default:
            {
                double num = 0;
                auto err = parse_number(c, num);
                out.data = num;
                return err;
            }
            }
        }
    } // namespace detail

    /**
     * @brief 解析 JSON 文本
     * @param text 输入
     * @param out 解析结果
     * @return 空 = 成功；否则 json_error
     */
    [[nodiscard]] inline auto parse_json(std::string_view text, json_value &out) -> json_error
    {
        detail::cursor c{text, 0};
        auto err = detail::parse_value(c, out, 0);
        if (!err.message.empty())
        {
            return err;
        }
        detail::skip_ws(c);
        if (c.pos != text.size())
        {
            return detail::fail(c, "trailing content");
        }
        return {};
    }

    /// 便捷访问：按路径取值（如 "a.b.0"）
    [[nodiscard]] inline auto lookup(const json_value &root, std::string_view path)
        -> const json_value *
    {
        const json_value *cur = &root;
        std::size_t start = 0;
        while (start <= path.size())
        {
            const auto dot = path.find('.', start);
            std::size_t seg_len = std::string_view::npos;
            if (dot != std::string_view::npos)
            {
                seg_len = dot - start;
            }
            const auto seg = path.substr(start, seg_len);
            if (cur->data.index() == 4) // json_array
            {
                const auto &arr = std::get<json_array>(cur->data).items;
                const auto idx = std::strtoul(std::string(seg).c_str(), nullptr, 10);
                if (idx >= arr.size())
                {
                    return nullptr;
                }
                cur = &arr[idx];
            }
            else if (cur->data.index() == 5) // json_object
            {
                const auto &obj = std::get<json_object>(cur->data).members;
                const auto it = obj.find(std::string(seg));
                if (it == obj.end())
                {
                    return nullptr;
                }
                cur = &it->second;
            }
            else
            {
                return nullptr;
            }
            if (dot == std::string_view::npos)
            {
                break;
            }
            start = dot + 1;
        }
        return cur;
    }

} // namespace preview::settings
