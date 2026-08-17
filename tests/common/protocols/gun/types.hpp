/**
 * @file types.hpp
 * @brief gRPC (gun) 协议基础类型
 * @details gun 是 gRPC-over-HTTP/2 伪装方案（对齐 mihomo transport/gun）：
 *          帧格式（gun-lite 兼容）：
 *          写：[0x00 压缩标志][u32 BE 长度][0x0A protobuf field1][uvarint][payload]
 *          读：跳过 [0x00][u32 BE][0x0A] 6 字节 → 读 uvarint → 读 payload
 *          本测试库实现纯逻辑帧编解码。
 * @note 参考 gun-lite 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace preview::gun
{

    /// 帧头固定开销（0x00 + u32 + 0x0A）
    inline constexpr std::size_t header_fixed_len = 6;

    /// 最大帧载荷（16MB，防恶意声明）
    inline constexpr std::size_t max_payload_len = 16 * 1024 * 1024;

    /// protobuf varint 最大字节数
    inline constexpr std::size_t max_varint_len = 5;

} // namespace preview::gun
