/**
 * @file types.hpp
 * @brief yamux 协议基础类型（兼容 Hashicorp/yamux）
 * @details 定义 yamux 多路复用协议的常量、消息类型、标志位与帧头结构。
 *          帧头为 12 字节定长，多字节字段大端序：
 *          [Version 1B][Type 1B][Flags 2B][StreamID 4B][Length 4B]。
 * @note 协议规范见 include/prism/protocol/multiplex/yamux/frame.hpp。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace preview::mux::yamux
{

    /// 协议版本号（yamux 规范固定为 0）
    inline constexpr std::uint8_t protocol_version = 0x00;

    /// 帧头大小（12 字节）
    inline constexpr std::size_t frame_hdrsize = 12;

    /// 初始流窗口（256KB）
    inline constexpr std::uint32_t default_window = 256 * 1024;

    /// 消息类型（帧头 Type 字段）
    enum class message_type : std::uint8_t
    {
        /// 数据帧
        data = 0x00,
        /// 窗口更新
        window_update = 0x01,
        /// 心跳
        ping = 0x02,
        /// 会话终止
        go_away = 0x03,
    };

    /// 标志位（2 字节，可组合）
    enum class flags : std::uint16_t
    {
        /// 无标志
        none = 0x0000,
        /// 同步（打开流 / 心跳请求）
        syn = 0x0001,
        /// 确认（确认流 / 心跳响应）
        ack = 0x0002,
        /// 半关闭
        fin = 0x0004,
        /// 重置
        rst = 0x0008,
    };

    /**
     * @brief 标志位按位与
     * @param a 左操作数
     * @param b 右操作数
     * @return 按位与结果
     */
    [[nodiscard]] constexpr auto operator&(flags a, flags b) noexcept -> flags
    {
        return static_cast<flags>(static_cast<std::uint16_t>(a) & static_cast<std::uint16_t>(b));
    }

    /**
     * @brief 检查标志组合
     * @param f 标志组合
     * @param flag 待检查标志
     * @return true = 包含该标志
     */
    [[nodiscard]] constexpr auto has_flag(flags f, flags flag) noexcept -> bool
    {
        return (f & flag) != flags::none;
    }

    /// GoAway 终止原因码
    enum class away_code : std::uint32_t
    {
        /// 协议错误
        protocol_error = 1,
    };

    /// yamux 帧头
    struct frame_header
    {
        /// 协议版本
        std::uint8_t version{protocol_version};
        /// 消息类型
        message_type type{message_type::data};
        /// 标志位组合
        flags flag{flags::none};
        /// 流标识符（0 = 会话级）
        std::uint32_t stream_id{0};
        /// 长度字段（Data = 载荷长，WinUpd = 窗口增量，Ping = ping id，GoAway = 原因码）
        std::uint32_t length{0};

        /**
         * @brief 是否会话级消息
         * @return true = 会话级消息
         */
        [[nodiscard]] auto is_session() const noexcept -> bool
        {
            return stream_id == 0;
        }
    };

} // namespace preview::mux::yamux
