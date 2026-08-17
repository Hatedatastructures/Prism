/**
 * @file types.hpp
 * @brief sing-mux（h2mux）协议基础类型
 * @details sing-mux 是 sing-box 的多路复用协议，9 字节定长帧头
 *          （对齐 sing-box singmux frame）：
 *          [Type 1B][Length 4B BE][StreamID 4B BE] = 9 字节。
 * @note 协议规范见 src/prism/protocol/multiplex/h2mux/。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace preview::mux::h2mux
{

    /// 帧类型（对齐 sing-mux）
    enum class frame_type : std::uint8_t
    {
        /// 数据帧
        data = 0,
        /// 窗口更新
        window_update = 1,
        /// 心跳
        ping = 2,
        /// 关闭流
        close = 3,
    };

    /// 帧头大小（9 字节）
    inline constexpr std::size_t frame_hdrsize = 9;

    /// 最大帧长度（16MB，sing-mux 限制）
    inline constexpr std::uint32_t max_frame_length = 16 * 1024 * 1024;

    /// sing-mux 帧头
    struct frame_header
    {
        /// 帧类型
        frame_type type{frame_type::data};
        /// 负载长度（大端序）
        std::uint32_t length{0};
        /// 流标识符（大端序）
        std::uint32_t stream_id{0};
    };

} // namespace preview::mux::h2mux
