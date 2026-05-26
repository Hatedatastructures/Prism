/**
 * @file frame.hpp
 * @brief AnyTLS 帧格式定义
 * @details 定义 AnyTLS 多路复用帧格式。7 字节 header：
 * [cmd:1][stream_id:4 BE][length:2 BE]
 * 命令编号与 mihomo/anytls 协议规范一致。
 */
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>


namespace psm::stealth::anytls
{


    constexpr std::size_t frame_header_size = 7;


    /**
     * @enum command
     * @brief AnyTLS 帧命令类型
     * @details 编号与 mihomo anytls 协议规范一致：
     * 0=waste, 1=syn, 2=psh, 3=fin, 4=settings, 5=alert,
     * 6=update_padding, 7=synack, 8=heart_req, 9=heart_resp,
     * 10=server_settings
     */
    enum class command : std::uint8_t
    {
        waste = 0x00,            // 丢弃（padding）
        syn = 0x01,              // 创建新流（C→S）
        psh = 0x02,              // 数据推送（双向）
        fin = 0x03,              // 关闭流（双向）
        settings = 0x04,         // 客户端 Settings（C→S）
        alert = 0x05,            // 告警/错误
        update_padding = 0x06,   // 更新 padding 方案（S→C）
        synack = 0x07,           // 流打开确认（S→C，v2+）
        heart_req = 0x08,        // 心跳请求
        heart_resp = 0x09,       // 心跳响应
        server_settings = 0x0A   ///< 服务端 Settings（S→C，v2+）
    }; // enum class command


    /**
     * @struct frame_header
     * @brief AnyTLS 帧头（7 字节）
     */
    struct frame_header
    {
        command cmd{command::waste};
        std::uint32_t stream_id{0};
        std::uint16_t length{0};

        /**
         * @brief 序列化帧头到字节数组
         * @return 7 字节序列化结果
         */
        [[nodiscard]] auto serialize() const
            -> std::array<std::uint8_t, frame_header_size>
        {
            std::array<std::uint8_t, frame_header_size> buf{};
            buf[0] = static_cast<std::uint8_t>(cmd);
            buf[1] = static_cast<std::uint8_t>((stream_id >> 24) & 0xFF);
            buf[2] = static_cast<std::uint8_t>((stream_id >> 16) & 0xFF);
            buf[3] = static_cast<std::uint8_t>((stream_id >> 8) & 0xFF);
            buf[4] = static_cast<std::uint8_t>(stream_id & 0xFF);
            buf[5] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
            buf[6] = static_cast<std::uint8_t>(length & 0xFF);
            return buf;
        }

        /**
         * @brief 从字节缓冲区解析帧头
         * @param data 至少 7 字节的缓冲区
         * @return 解析后的帧头
         */
        [[nodiscard]] static auto parse(std::span<const std::uint8_t> data)
            -> std::optional<frame_header>
        {
            if (data.size() < frame_header_size)
            {
                return std::nullopt;
            }
            frame_header hdr;
            hdr.cmd = static_cast<command>(data[0]);
            hdr.stream_id = (static_cast<std::uint32_t>(data[1]) << 24) |
                            (static_cast<std::uint32_t>(data[2]) << 16) |
                            (static_cast<std::uint32_t>(data[3]) << 8) |
                            static_cast<std::uint32_t>(data[4]);
            hdr.length = (static_cast<std::uint16_t>(data[5]) << 8) |
                         static_cast<std::uint16_t>(data[6]);
            return hdr;
        }
    }; // struct frame_header
} // namespace psm::stealth::anytls
