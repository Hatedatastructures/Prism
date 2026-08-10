/**
 * @file codec.hpp
 * @brief gRPC (gun) 传输帧编解码
 * @details gun 帧格式（mihomo gun-lite 兼容）：
 *   写：[0x00 压缩标志][u32 BE 长度][0x0A protobuf field1][uvarint][payload]
 *   读：跳过 [0x00][u32 BE][0x0A] 6 字节 → 读 uvarint → 读 payload
 *   长度 = 1 + varintLen + payloadLen；uvarint 为 protobuf LEB128。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psm::handshake::gun::codec
{

    /// 帧头固定开销（0x00 + u32 + 0x0A）
    inline constexpr std::size_t header_fixed_len = 6;

    /// 最大帧载荷（16MB，防恶意声明）
    inline constexpr std::size_t max_payload_len = 16 * 1024 * 1024;

    /// protobuf varint 最大字节数
    inline constexpr std::size_t max_varint_len = 5;

    /**
     * @brief 编码 protobuf varint（LEB128）
     * @param value 数值
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] auto encode_varint(std::uint32_t value, std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief 解码 protobuf varint
     * @param in 输入数据
     * @param value 输出数值
     * @return 消耗字节数，0 表示数据不足或非法
     */
    [[nodiscard]] auto decode_varint(std::span<const std::uint8_t> in, std::uint32_t &value) -> std::size_t;

    /**
     * @brief 编码一个 gun 帧
     * @param payload 帧载荷
     * @param out 输出缓冲区（需 ≥ header_fixed_len + 5 + payload.size()）
     * @return 写入字节数，0 表示缓冲区不足
     */
    [[nodiscard]] auto encode_frame(std::span<const std::uint8_t> payload, std::span<std::uint8_t> out)
        -> std::size_t;

    /**
     * @struct frame_header
     * @brief 解析出的帧头信息
     */
    struct frame_header
    {
        std::size_t payload_len{0};  ///< 载荷长度
        std::size_t header_len{0};   ///< 帧头总长度（含 varint）
    };

    /**
     * @brief 解析帧头
     * @param in 输入数据（至少含 6 字节定长头）
     * @param header 输出帧头信息
     * @return 解析是否成功（数据不足或长度非法返回 false）
     */
    [[nodiscard]] auto parse_frame_header(std::span<const std::uint8_t> in, frame_header &header) -> bool;

} // namespace psm::handshake::gun::codec
