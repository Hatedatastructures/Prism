/**
 * @file Codec.hpp
 * @brief gRPC (gun) 帧编解码（纯函数）
 * @details 实现 gRPC 消息的 HTTP/2 DATA frame 编解码（gun-lite）：
 *          - EncodeVarint / DecodeVarint：protobuf LEB128
 *          - EncodeFrame：[0x00][u32 BE len][0x0A][uvarint][payload]
 *          - ParseFrameHeader：帧头解析
 * @note 参考 gun-lite 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Prism/Protocols/Gun/CodecTypes.hpp>

namespace Prism::Gun
{

    /**
     * @brief 编码 protobuf varint（LEB128）
     * @param Value 数值
     * @param Output 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] auto EncodeVarint(
        std::uint32_t Value,
        std::span<std::uint8_t> Output) -> std::size_t;

    /**
     * @brief 解码 protobuf varint
     * @param Input 输入数据
     * @param Value 输出数值
     * @return 消耗字节数，0 = 数据不足或非法
     */
    [[nodiscard]] auto DecodeVarint(
        std::span<const std::uint8_t> Input,
        std::uint32_t &Value)
        -> std::size_t;

    /// 解析出的帧头信息
    struct FrameHeader
    {
        /// 载荷长度
        std::size_t PayloadLen{0};
        /// 帧头总长度（含 varint）
        std::size_t HeaderLen{0};
    };

    /**
     * @brief 编码一个 gun 帧
     * @param Payload 帧载荷
     * @return 帧字节 [0x00][u32 BE len][0x0A][uvarint][payload]
     */
    [[nodiscard]] auto EncodeFrame(
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析帧头
     * @param Input 输入数据（至少含 6 字节定长头）
     * @param Header 输出帧头信息
     * @return true = 解析成功（数据不足或长度非法返回 false）
     */
    [[nodiscard]] auto ParseFrameHeader(
        std::span<const std::uint8_t> Input,
        FrameHeader &Header)
        -> bool;

} // namespace Prism::Gun
