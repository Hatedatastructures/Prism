/**
 * @file AuthId.hpp
 * @brief VMess UUID、cmdKey 与 AuthID
 * @details 负责 UUID 解析、cmdKey 派生、AuthID 明文校验字段和 AuthID
 *          的 AES-ECB 加密。认证头长度/载荷 wire 由 AuthHeader.hpp 负责。
 */

#pragma once

#include <algorithm>
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

        [[nodiscard]] inline auto HexNibble(const char Character) noexcept -> int
        {
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0';
            }
            if (Character >= 'a' && Character <= 'f')
            {
                return Character - 'a' + 10;
            }
            if (Character >= 'A' && Character <= 'F')
            {
                return Character - 'A' + 10;
            }
            return -1;
        }

        /**
         * @brief CRC32-IEEE 校验
         * @param Data 输入数据
         * @return CRC32 值
         */
        [[nodiscard]] inline auto Crc32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t Crc = 0xFFFFFFFFU;
            for (const auto Byte : Data)
            {
                Crc ^= Byte;
                for (int I = 0; I < 8; ++I)
                {
                    if ((Crc & 1U) != 0U)
                    {
                        Crc = (Crc >> 1) ^ 0xEDB88320U;
                    }
                    else
                    {
                        Crc >>= 1;
                    }
                }
            }
            return Crc ^ 0xFFFFFFFFU;
        }

        /**
         * @brief 时间戳编码（大端 8 字节）
         * @param Ts 时间戳（秒）
         * @return 大端 8 字节
         */
        [[nodiscard]] inline auto EncodeTimestamp(std::int64_t Ts) -> std::array<std::uint8_t, 8>
        {
            std::array<std::uint8_t, 8> Output{};
            const auto U = static_cast<std::uint64_t>(Ts);
            for (std::size_t I = 0; I < 8; ++I)
            {
                Output[7 - I] = static_cast<std::uint8_t>((U >> (I * 8)) & 0xFF);
            }
            return Output;
        }

    } // namespace detail

    /**
     * @brief 由 UUID 16 字节派生 cmdKey
     * @param Uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey
     */
    [[nodiscard]] inline auto CmdKeyFromUuid(std::span<const std::uint8_t, 16> Uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> Input{};
        std::copy(Uuid.begin(), Uuid.end(), Input.begin());
        const auto Salt = detail::AsBytes(UuidSalt);
        std::copy(Salt.begin(), Salt.end(), Input.begin() + 16);
        return detail::Md5(Input);
    }

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param Uuid UUID 字符串
     * @param Output 输出 16 字节
     * @return 成功返回 true
     */
    [[nodiscard]] inline auto ParseUuid(
        std::string_view Uuid,
        std::span<std::uint8_t, 16> Output) -> bool
    {
        if (Uuid.size() != 36)
        {
            return false;
        }
        constexpr std::array<std::size_t, 5> GroupLengths{8, 4, 4, 4, 12};
        std::size_t InputPos = 0;
        std::size_t OutputPos = 0;
        for (std::size_t Group = 0; Group < GroupLengths.size(); ++Group)
        {
            for (std::size_t Byte = 0; Byte < GroupLengths[Group] / 2; ++Byte)
            {
                const int Hi = detail::HexNibble(Uuid[InputPos]);
                const int Lo = detail::HexNibble(Uuid[InputPos + 1]);
                if (Hi < 0 || Lo < 0)
                {
                    return false;
                }
                Output[OutputPos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
                InputPos += 2;
            }
            if (Group + 1 < GroupLengths.size())
            {
                if (Uuid[InputPos] != '-')
                {
                    return false;
                }
                ++InputPos;
            }
        }
        return InputPos == Uuid.size() && OutputPos == Output.size();
    }

    /**
     * @brief 构造标准 VMess AuthID
     * @param CmdKey 16 字节 cmdKey
     * @param TimeSec UTC 秒
     * @param RandomBytes 4 字节随机数
     * @return 加密后的 16 字节 AuthID
     */
    [[nodiscard]] inline auto CreateAuthId(std::span<const std::uint8_t, 16> CmdKey,
                                            std::int64_t TimeSec,
                                            std::span<const std::uint8_t, 4> RandomBytes)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Plain{};
        const auto Ts = detail::EncodeTimestamp(TimeSec);
        std::copy(Ts.begin(), Ts.end(), Plain.begin());
        std::copy(RandomBytes.begin(), RandomBytes.end(), Plain.begin() + TimestampLen);
        const auto Crc = detail::Crc32(std::span<const std::uint8_t>(Plain.data(), TimestampLen + AuthRandomLen));
        for (std::size_t I = 0; I < sizeof(Crc); ++I)
        {
            Plain[TimestampLen + AuthRandomLen + I] =
                static_cast<std::uint8_t>(Crc >> (8 * (sizeof(Crc) - 1 - I)));
        }
        const auto AuthKey = Kdf(CmdKey, KdfAuthId);
        return detail::AesEcbEncrypt(
            std::span<const std::uint8_t, 16>(AuthKey.data(), 16), Plain);
    }

} // namespace Prism::Vmess
