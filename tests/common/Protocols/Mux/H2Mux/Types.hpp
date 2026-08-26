/**
 * @file Types.hpp
 * @brief sing-mux（h2mux）协议基础类型
 * @details sing-mux 是 sing-box 的多路复用协议，9 字节定长帧头
 *          （对齐 sing-box singmux Frame）：
 *          [Type 1B][Length 4B BE][StreamID 4B BE] = 9 字节。
 * @note 协议规范见 src/prism/Protocol/multiplex/h2mux/。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace Preview::Mux::H2Mux
{

    /// 帧类型（对齐 sing-mux）
    enum class FrameType : std::uint8_t
    {
        /// 数据帧
        Data = 0,
        /// 窗口更新
        WindowUpdate = 1,
        /// 心跳
        Ping = 2,
        /// 关闭流
        Close = 3,
    };

    /// 帧头大小（9 字节）
    inline constexpr std::size_t FrameHdrsize = 9;

    /// 最大帧长度（16MB，sing-mux 限制）
    inline constexpr std::uint32_t MaxFrameLength = 16 * 1024 * 1024;

    /// sing-mux 帧头
    struct FrameHeader
    {
        /// 帧类型
        FrameType Type{FrameType::Data};
        /// 负载长度（大端序）
        std::uint32_t length{0};
        /// 流标识符（大端序）
        std::uint32_t StreamId{0};
    };

} // namespace Preview::Mux::H2Mux