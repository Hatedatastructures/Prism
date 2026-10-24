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
#include <limits>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace Prism::Shadowsocks2022
{

    /**
     * @brief 构造固定头明文
     * @param Type 头类型（0x00 请求 / 0x01 响应）
     * @param TimeSec UTC 秒
     * @param VarLen 变长头长度
     * @return 11 字节明文
     */
    [[nodiscard]] auto ParseFixedHeader(
        std::uint8_t Type,
        std::uint64_t TimeSec,
        std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>;

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
    [[nodiscard]] auto ParseFixedHeader(
        std::span<const std::uint8_t> Data,
        FixedHeader &Output) -> Error;

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
        return Prism::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址为独立字节序列
     * @param AddressValue 目标地址
     * @return 编码后的地址
     */
    [[nodiscard]] auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 解析地址字节
     * @param Data 完整缓冲区
     * @param Output 输出目标地址
     * @param Offset 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Offset) -> Error;

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param AddressValue 目标地址
     * @param PaddingLength padding 长度
     * @param Payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] auto BuildVarHeader(
        const Address &AddressValue,
        std::uint16_t PaddingLength,
        std::span<const std::uint8_t> Payload = {})
        -> std::vector<std::uint8_t>;

    /**
     * @brief 解析变长头明文
     * @param Data 变长头明文
     * @param Output 输出目标地址
     * @param Payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] auto ParseVarHeader(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::span<const std::uint8_t> &Payload) -> Error;

} // namespace Prism::Shadowsocks2022
