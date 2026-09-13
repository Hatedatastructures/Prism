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

    namespace Detail
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
    } // namespace Detail

    /**
     * @brief Base64 解码
     * @param input Base64 编码的字符串
     * @return 解码后的字符串
     * @details 将 Base64 编码字符串解码为原始数据。自动忽略空白字符，
     * 支持标准 Base64 和 URL-safe 变体（自动转换 - 和 _）。
     * 输入长度不是 4 的倍数时返回空字符串。
     * @note 遵循 RFC 4648 标准 Base64 解码规则。
     */
    [[nodiscard]] inline auto Base64Decode(std::string_view Input) -> std::string
    {
        if (Input.empty())
        {
            return {};
        }

        std::string Clean;
        Clean.reserve(Input.size());
        for (const auto Character : Input)
        {
            if (std::isspace(static_cast<std::uint8_t>(Character)))
            {
                continue;
            }
            auto Ch = static_cast<std::uint8_t>(Character);
            if (Ch == '-')
            {
                Ch = '+';
            }
            else if (Ch == '_')
            {
                Ch = '/';
            }
            if (Ch != '=' && Detail::DecTable[Ch] == 255)
            {
                return {};
            }
            Clean.push_back(static_cast<char>(Ch));
        }

        if (Clean.empty() || Clean.size() % 4 != 0)
        {
            return {};
        }

        std::size_t Padding = 0;
        if (Clean.back() == '=')
        {
            ++Padding;
            if (Clean.size() >= 2 && Clean[Clean.size() - 2] == '=')
            {
                ++Padding;
            }
        }
        if (Padding > 2)
        {
            return {};
        }
        const auto DataEnd = Clean.size() - Padding;
        if (Clean.substr(0, DataEnd).find('=') != std::string::npos)
        {
            return {};
        }

        std::string Result;
        Result.reserve((Clean.size() / 4) * 3 - Padding);
        for (std::size_t Offset = 0; Offset < Clean.size(); Offset += 4)
        {
            const auto V0 = Detail::DecTable[static_cast<std::uint8_t>(Clean[Offset])];
            const auto V1 = Detail::DecTable[static_cast<std::uint8_t>(Clean[Offset + 1])];
            if (V0 == 255 || V1 == 255)
            {
                return {};
            }
            const auto IsLast = Offset + 4 == Clean.size();
            const auto C2 = Clean[Offset + 2];
            const auto C3 = Clean[Offset + 3];
            if (C2 == '=')
            {
                if (!IsLast || Padding != 2 || C3 != '=' || (V1 & 0x0F) != 0)
                {
                    return {};
                }
                Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
                continue;
            }
            const auto V2 = Detail::DecTable[static_cast<std::uint8_t>(C2)];
            if (V2 == 255)
            {
                return {};
            }
            if (C3 == '=')
            {
                if (!IsLast || Padding != 1 || (V2 & 0x03) != 0)
                {
                    return {};
                }
                Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
                Result.push_back(static_cast<char>(((V1 & 0x0F) << 4) | (V2 >> 2)));
                continue;
            }
            const auto V3 = Detail::DecTable[static_cast<std::uint8_t>(C3)];
            if (V3 == 255 || (Padding != 0 && IsLast))
            {
                return {};
            }
            Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
            Result.push_back(static_cast<char>(((V1 & 0x0F) << 4) | (V2 >> 2)));
            Result.push_back(static_cast<char>(((V2 & 0x03) << 6) | V3));
        }
        return Result;
    }

    namespace Detail
    {

        /**
         * @brief Base64 编码查找表
         */
        constexpr char EncodeTbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";
    } // namespace Detail

    /**
     * @brief Base64 编码
     * @param input 原始字节数据
     * @return Base64 编码后的字符串
     * @details 将原始字节编码为标准 Base64 字符串（含 padding）。
     * 遵循 RFC 4648 标准 Base64 编码规则。
     */
    [[nodiscard]] inline auto Base64Encode(std::span<const std::uint8_t> Input) -> std::string
    {
        if (Input.empty())
        {
            return {};
        }

        std::string Result;
        Result.reserve(((Input.size() + 2) / 3) * 4);

        std::size_t I = 0;
        const std::size_t FullGroups = Input.size() / 3;

        // 处理完整的 3 字节组
        for (std::size_t G = 0; G < FullGroups; ++G)
        {
            const auto Byte0 = Input[I];
            const auto Byte1 = Input[I + 1];
            const auto Byte2 = Input[I + 2];
            I += 3;

            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(Detail::EncodeTbl[((Byte1 & 0x0F) << 2) | (Byte2 >> 6)]);
            Result.push_back(Detail::EncodeTbl[Byte2 & 0x3F]);
        }

        // 处理剩余字节
        const std::size_t Remaining = Input.size() % 3;
        if (Remaining == 1)
        {
            const auto Byte0 = Input[I];
            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[(Byte0 & 0x03) << 4]);
            Result.push_back('=');
            Result.push_back('=');
        }
        else if (Remaining == 2)
        {
            const auto Byte0 = Input[I];
            const auto Byte1 = Input[I + 1];
            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(Detail::EncodeTbl[(Byte1 & 0x0F) << 2]);
            Result.push_back('=');
        }

        return Result;
    }
} // namespace Preview::Crypto
