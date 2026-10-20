/**
 * @file AuthId.hpp
 * @brief VMess UUID、cmdKey 与 AuthID
 * @details 负责 UUID 解析、cmdKey 派生、AuthID 明文校验字段和 AuthID
 *          的 AES-ECB 加密。认证头长度/载荷 wire 由 AuthHeader.hpp 负责。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <Prism/Protocols/Vmess/AuthKdf.hpp>

namespace Prism::Vmess
{

    namespace detail
    {

        [[nodiscard]] auto HexNibble(const char Character) noexcept -> int;

        /**
         * @brief CRC32-IEEE 校验
         * @param Data 输入数据
         * @return CRC32 值
         */
        [[nodiscard]] auto Crc32(std::span<const std::uint8_t> Data) -> std::uint32_t;

        /**
         * @brief 时间戳编码（大端 8 字节）
         * @param Ts 时间戳（秒）
         * @return 大端 8 字节
         */
        [[nodiscard]] auto EncodeTimestamp(std::int64_t Ts) -> std::array<std::uint8_t, 8>;

    } // namespace detail

    /**
     * @brief 由 UUID 16 字节派生 cmdKey
     * @param Uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey
     */
    [[nodiscard]] auto CmdKeyFromUuid(std::span<const std::uint8_t, 16> Uuid)
        -> std::array<std::uint8_t, 16>;

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param Uuid UUID 字符串
     * @param Output 输出 16 字节
     * @return 成功返回 true
     */
    [[nodiscard]] auto ParseUuid(
        std::string_view Uuid,
        std::span<std::uint8_t, 16> Output) -> bool;

    /**
     * @brief 构造标准 VMess AuthID
     * @param CmdKey 16 字节 cmdKey
     * @param TimeSec UTC 秒
     * @param RandomBytes 4 字节随机数
     * @return 加密后的 16 字节 AuthID
     */
    [[nodiscard]] auto CreateAuthId(std::span<const std::uint8_t, 16> CmdKey,
                                            std::int64_t TimeSec,
                                            std::span<const std::uint8_t, 4> RandomBytes)
        -> std::array<std::uint8_t, 16>;

} // namespace Prism::Vmess
