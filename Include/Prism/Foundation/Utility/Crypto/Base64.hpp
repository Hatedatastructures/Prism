/**
 * @file Base64.hpp
 * @brief Base64 编解码工具
 * @details 提供轻量级 Base64 编解码函数，用于 HTTP Basic 认证等场景。
 * 查找表保留为编译期常量，运行时编解码由 Foundation 实现库提供。
 */
#pragma once

#include <Prism/Foundation/Memory/Container.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Crypto
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
    [[nodiscard]] auto Base64Decode(std::string_view Input) -> std::string;

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
    [[nodiscard]] auto Base64Encode(std::span<const std::uint8_t> Input) -> std::string;
} // namespace Prism::Crypto
