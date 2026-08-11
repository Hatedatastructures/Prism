/**
 * @file types.hpp
 * @brief smux 协议基础类型（兼容 Mihomo/xtaci/smux v1）
 * @details 定义 smux 多路复用协议的常量、命令枚举与帧头结构。
 *          帧头为 8 字节定长：[Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE]。
 * @note 协议规范见 include/prism/protocol/multiplex/smux/frame.hpp。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace psmtest::mux::smux
{

    /// 命令类型（对齐 xtaci/smux）
    enum class command : std::uint8_t
    {
        /// 新建流
        syn = 0,
        /// 半关闭流
        fin = 1,
        /// 数据推送
        push = 2,
        /// 心跳（不回复）
        nop = 3,
    };

    /// 协议版本号
    inline constexpr std::uint8_t protocol_version = 0x01;

    /// 帧头大小（8 字节）
    inline constexpr std::size_t frame_hdrsize = 8;

    /// 最大帧数据大小（64KB）
    inline constexpr std::size_t max_frame_length = 65535;

    /// smux 帧头
    struct frame_header
    {
        /// 协议版本号
        std::uint8_t version{protocol_version};
        /// 命令类型
        command cmd{command::push};
        /// 负载长度（小端序）
        std::uint16_t length{0};
        /// 流标识符（小端序，0 = 会话级）
        std::uint32_t stream_id{0};
    };

} // namespace psmtest::mux::smux
