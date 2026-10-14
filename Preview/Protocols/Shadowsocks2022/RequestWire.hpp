/**
 * @file RequestWire.hpp
 * @brief Shadowsocks 2022 请求固定头和变长头 wire helper。
 * @details 只拥有请求头的无状态编码、解析和地址转换；增量
 *          Serializer/Parser 位于 RequestState.hpp。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <span>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /**
     * @brief 构造固定头明文
     * @param Type 头类型（0x00 请求 / 0x01 响应）
     * @param TimeSec UTC 秒
     * @param VarLen 变长头长度
     * @return 11 字节明文
     */
    [[nodiscard]] inline auto ParseFixedHeader(
        std::uint8_t Type,
        std::uint64_t TimeSec,
        std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>
    {
        std::array<std::uint8_t, FixedHdrPlain> Output{};
        Output[0] = Type;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output[1 + I] = static_cast<std::uint8_t>((TimeSec >> (56 - I * 8)) & 0xFF);
        }
        Output[9] = static_cast<std::uint8_t>((VarLen >> 8) & 0xFF);
        Output[10] = static_cast<std::uint8_t>(VarLen & 0xFF);
        return Output;
    }

    /**
     * @brief 解析出的固定头字段
     */
    struct FixedHeader
    {
        std::uint8_t Type{0};
        std::uint64_t TimeSec{0};
        std::uint16_t VarLen{0};
    };

    /**
     * @brief 解析固定头明文
     * @param Data 11 字节明文
     * @param Output 输出固定头字段
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseFixedHeader(
        std::span<const std::uint8_t> Data,
        FixedHeader &Output) -> Error
    {
        if (Data.size() < FixedHdrPlain)
        {
            return Error::NeedMore;
        }
        Output.Type = Data[0];
        Output.TimeSec = 0;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output.TimeSec = (Output.TimeSec << 8) | Data[1 + I];
        }
        Output.VarLen = static_cast<std::uint16_t>(Data[9]) << 8 | Data[10];
        return Error::None;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址为独立字节序列
     * @param AddressValue 目标地址
     * @return 编码后的地址
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!EncodeAddress(AddressValue, Output))
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 解析地址字节
     * @param Data 完整缓冲区
     * @param Output 输出目标地址
     * @param Offset 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Offset) -> Error
    {
        if (Offset >= Data.size())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[Offset++]);
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Offset]),
                static_cast<unsigned int>(Data[Offset + 1]),
                static_cast<unsigned int>(Data[Offset + 2]),
                static_cast<unsigned int>(Data[Offset + 3]));
            Output.Host = Buffer.data();
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Offset >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Offset < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        return Error::None;
    }

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param AddressValue 目标地址
     * @param PaddingLength padding 长度
     * @param Payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] inline auto BuildVarHeader(
        const Address &AddressValue,
        std::uint16_t PaddingLength,
        std::span<const std::uint8_t> Payload = {})
        -> std::vector<std::uint8_t>
    {
        auto Output = EncodeAddress(AddressValue);
        if (Output.empty())
        {
            return {};
        }
        constexpr auto MaxVarHeaderLength = (std::numeric_limits<std::uint16_t>::max)();
        if (PaddingLength > MaxVarHeaderLength - 2 ||
            Output.size() > MaxVarHeaderLength - 2 - PaddingLength ||
            Payload.size() > MaxVarHeaderLength - 2 - PaddingLength - Output.size())
        {
            return {};
        }
        Output.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
        for (std::uint16_t I = 0; I < PaddingLength; ++I)
        {
            Output.push_back(0);
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    /**
     * @brief 解析变长头明文
     * @param Data 变长头明文
     * @param Output 输出目标地址
     * @param Payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseVarHeader(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Off]),
                static_cast<unsigned int>(Data[Off + 1]),
                static_cast<unsigned int>(Data[Off + 2]),
                static_cast<unsigned int>(Data[Off + 3]));
            Output.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Off < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        const auto PaddingLength = static_cast<std::size_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < PaddingLength)
        {
            return Error::NeedMore;
        }
        Off += PaddingLength;
        Payload = Data.subspan(Off);
        return Error::None;
    }

} // namespace Preview::Shadowsocks2022
