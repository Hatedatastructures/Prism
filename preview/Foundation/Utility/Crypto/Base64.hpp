/**
 * @file Base64.hpp
 * @brief Base64 编解码工具
 * @details 提供轻量级 Base64 编解码函数，用于 HTTP Basic 认证等场景。
 * 实现为 Header-only inline 函数，与 Sha224.hpp 风格一致。
 * @note 已分叉，各自演进（与主库 foundation 无镜像同步约束）
 */
#pragma once

#include <preview/Foundation/Memory/Container.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace Preview::Crypto
{

    namespace detail
    {

        /**
         * @brief Base64 解码查找表
         * @details 将 ASCII 字符映射到对应的 6 位值，无效字符映射为 255。
         */
        [[nodiscard]] constexpr auto DecodeTbl() -> std::array<std::uint8_t, 256>
        {
            std::array<std::uint8_t, 256> Table{};
            Table.fill(255);

            // A-Z -> 0-25
            for (std::size_t I = 0; I < 26; ++I)
            {
                Table[static_cast<std::size_t>('A' + I)] = static_cast<std::uint8_t>(I);
            }
            // a-z -> 26-51
            for (std::size_t I = 0; I < 26; ++I)
            {
                Table[static_cast<std::size_t>('a' + I)] = static_cast<std::uint8_t>(26 + I);
            }
            // 0-9 -> 52-61
            for (std::size_t I = 0; I < 10; ++I)
            {
                Table[static_cast<std::size_t>('0' + I)] = static_cast<std::uint8_t>(52 + I);
            }
            Table[static_cast<std::size_t>('+')] = 62;
            Table[static_cast<std::size_t>('/')] = 63;
            return Table;
        }

        constexpr auto DecTable = DecodeTbl();
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
    [[nodiscard]] inline auto Base64Decode(std::string_view input) -> std::string
    {
        if (input.empty())
        {
            return {};
        }

        // 计算有效字符数（跳过空白），并检查长度合法性
        std::size_t ValidCount = 0;
        std::size_t Padding = 0;
        for (const auto c : input)
        {
            if (c == '=')
            {
                ++Padding;
            }
            else if (!std::isspace(static_cast<std::uint8_t>(c)))
            {
                ++ValidCount;
            }
        }

        if (Padding > 2)
        {
            return {};
        }

        // 有效字符（不含 padding）必须是 4 的倍数
        const auto Total = ValidCount + Padding;
        if (Total % 4 != 0)
        {
            return {};
        }

        std::string Result;
        Result.reserve((ValidCount / 4) * 3);

        std::uint8_t group[4]{};
        std::size_t GroupCount = 0;

        for (const auto c : input)
        {
            if (c == '=')
            {
                group[GroupCount++] = 0;
                if (GroupCount == 4)
                {
                    // 根据 padding 数量决定输出字节数
                    switch (Padding)
                    {
                    case 1:
                        Result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4)));
                        Result.push_back(static_cast<char>(((group[1] & 0x0F) << 4) | (group[2] >> 2)));
                        break;
                    case 2: Result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4))); break;
                    default: break;
                    }
                    GroupCount = 0;
                    Padding = 0;
                }
                continue;
            }

            if (std::isspace(static_cast<std::uint8_t>(c)))
            {
                continue;
            }

            // URL-safe 变体转换
            auto Ch = static_cast<std::uint8_t>(c);
            if (Ch == '-')
            {
                Ch = '+';
            }
            else if (Ch == '_')
            {
                Ch = '/';
            }

            const auto value = detail::DecTable[Ch];
            if (value == 255)
            {
                return {};
            }

            group[GroupCount++] = value;
            if (GroupCount == 4)
            {
                Result.push_back(static_cast<char>((group[0] << 2) | (group[1] >> 4)));
                Result.push_back(static_cast<char>(((group[1] & 0x0F) << 4) | (group[2] >> 2)));
                Result.push_back(static_cast<char>(((group[2] & 0x03) << 6) | group[3]));
                GroupCount = 0;
            }
        }

        // 无 padding 的剩余组：按 RFC 4648 规范不应出现
        // 因为 Base64 要求输入按 3 字节分组，不足时必须补 padding
        return Result;
    }

    namespace detail
    {

        /**
         * @brief Base64 编码查找表
         */
        constexpr char EncodeTbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";
    } // namespace detail

    /**
     * @brief Base64 编码
     * @param input 原始字节数据
     * @return Base64 编码后的字符串
     * @details 将原始字节编码为标准 Base64 字符串（含 padding）。
     * 遵循 RFC 4648 标准 Base64 编码规则。
     */
    [[nodiscard]] inline auto Base64Encode(std::span<const std::uint8_t> input) -> std::string
    {
        if (input.empty())
        {
            return {};
        }

        std::string Result;
        Result.reserve(((input.size() + 2) / 3) * 4);

        std::size_t I = 0;
        const std::size_t FullGroups = input.size() / 3;

        // 处理完整的 3 字节组
        for (std::size_t G = 0; G < FullGroups; ++G)
        {
            const auto Byte0 = input[I];
            const auto Byte1 = input[I + 1];
            const auto Byte2 = input[I + 2];
            I += 3;

            Result.push_back(detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(detail::EncodeTbl[((Byte1 & 0x0F) << 2) | (Byte2 >> 6)]);
            Result.push_back(detail::EncodeTbl[Byte2 & 0x3F]);
        }

        // 处理剩余字节
        const std::size_t Remaining = input.size() % 3;
        if (Remaining == 1)
        {
            const auto Byte0 = input[I];
            Result.push_back(detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(detail::EncodeTbl[(Byte0 & 0x03) << 4]);
            Result.push_back('=');
            Result.push_back('=');
        }
        else if (Remaining == 2)
        {
            const auto Byte0 = input[I];
            const auto Byte1 = input[I + 1];
            Result.push_back(detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(detail::EncodeTbl[(Byte1 & 0x0F) << 2]);
            Result.push_back('=');
        }

        return Result;
    }
} // namespace Preview::Crypto
