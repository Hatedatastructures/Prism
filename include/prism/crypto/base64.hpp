/**
 * @file base64.hpp
 * @brief Base64 编解码工具
 * @details 提供轻量级 Base64 编解码函数，用于 HTTP Basic 认证等场景。
 * 实现为 header-only inline 函数，与 sha224.hpp 风格一致。
 */
#pragma once

#include <string>
#include <cstdint>
#include <string_view>
#include <array>
#include <cctype>

/**
 * @brief Base64 编解码工具命名空间
 * @details 提供标准 Base64 编码和解码功能，遵循 RFC 4648 规范。
 */
namespace psm::crypto
{
    namespace detail
    {
        /**
         * @brief Base64 解码查找表
         * @details 将 ASCII 字符映射到对应的 6 位值，无效字符映射为 255。
         */
        constexpr auto make_decode_table() -> std::array<std::uint8_t, 256>
        {
            std::array<std::uint8_t, 256> table{};
            table.fill(255);

            // A-Z -> 0-25
            for (int i = 0; i < 26; ++i)
            {
                table[static_cast<std::size_t>('A' + i)] = static_cast<std::uint8_t>(i);
            }
            // a-z -> 26-51
            for (int i = 0; i < 26; ++i)
            {
                table[static_cast<std::size_t>('a' + i)] = static_cast<std::uint8_t>(26 + i);
            }
            // 0-9 -> 52-61
            for (int i = 0; i < 10; ++i)
            {
                table[static_cast<std::size_t>('0' + i)] = static_cast<std::uint8_t>(52 + i);
            }
            table[static_cast<std::size_t>('+')] = 62;
            table[static_cast<std::size_t>('/')] = 63;
            return table;
        }

        constexpr auto base64_decode_table = make_decode_table();
    } // namespace detail

    /**
     * @brief Base64 解码
     * @param input Base64 编码的字符串
     * @return 解码后的字符串
     * @details 将 Base64 编码字符串解码为原始数据。自动忽略空白字符，
     * 支持标准 Base64 和 URL-safe 变体（自动转换 - 和 _）。
     * 输入长度不是 4 的倍数时返回空字符串。
     * @note 遵循 RFC 4648 标准 Base64 解码规则。
     */
    [[nodiscard]] inline auto base64_decode(const std::string_view input) -> std::string
    {
        if (input.empty())
        {
            return {};
        }

        // 计算有效字符数（跳过空白），并检查长度合法性
        std::size_t valid_count = 0;
        std::size_t padding = 0;
        for (const auto c : input)
        {
            if (c == '=')
            {
                ++padding;
            }
            else if (!std::isspace(static_cast<unsigned char>(c)))
            {
                ++valid_count;
            }
        }

        if (padding > 2)
        {
            return {};
        }

        // 有效字符（不含 padding）必须是 4 的倍数
        const auto total = valid_count + padding;
        if (total % 4 != 0)
        {
            return {};
        }

        std::string result;
        result.reserve((valid_count / 4) * 3);

        std::uint8_t group[4]{};
        int group_count = 0;

        for (const auto c : input)
        {
            if (c == '=')
            {
                group[group_count++] = 0;
                if (group_count == 4)
                {
                    // 根据 padding 数量决定输出字节数
                    switch (padding)
                    {
                    case 1:
                        result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4)));
                        result.push_back(static_cast<char>(((group[1] & 0x0F) << 4) | (group[2] >> 2)));
                        break;
                    case 2:
                        result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4)));
                        break;
                    default:
                        break;
                    }
                    group_count = 0;
                    padding = 0;
                }
                continue;
            }

            if (std::isspace(static_cast<unsigned char>(c)))
            {
                continue;
            }

            // URL-safe 变体转换
            auto ch = static_cast<std::uint8_t>(c);
            if (ch == '-')
            {
                ch = '+';
            }
            else if (ch == '_')
            {
                ch = '/';
            }

            const auto value = detail::base64_decode_table[ch];
            if (value == 255)
            {
                return {};
            }

            group[group_count++] = value;
            if (group_count == 4)
            {
                result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4)));
                result.push_back(static_cast<char>(((group[1] & 0x0F) << 4) | (group[2] >> 2)));
                result.push_back(static_cast<char>(((group[2] & 0x03) << 6) | group[3]));
                group_count = 0;
            }
        }

        // 无 padding 的剩余组：按 RFC 4648 规范不应出现
        // 因为 Base64 要求输入按 3 字节分组，不足时必须补 padding
        return result;
    }
} // namespace psm::crypto
