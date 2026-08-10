/**
 * @file yamux.hpp
 * @brief Yamux 多路复用帧编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          帧 = [version 1B=0][type 1B][flags 2B BE][streamID 4B BE][length 4B BE][data]
 *          type：DATA/SYN/ACK/FIN/RST/PING/GO_AWAY
 *          命名空间 psm_test::yamux，参考 hashicorp/yamux。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::yamux
{

    inline constexpr std::uint8_t version = 0;
    inline constexpr std::size_t frame_header_len = 12;

    enum class type : std::uint8_t
    {
        data = 0,
        syn = 1,
        ack = 2,
        fin = 3,
        rst = 4,
        ping = 5,
        go_away = 6,
    };

    namespace flag
    {
        inline constexpr std::uint16_t syn = 0x1;
        inline constexpr std::uint16_t ack = 0x2;
        inline constexpr std::uint16_t fin = 0x4;
        inline constexpr std::uint16_t rst = 0x8;
    } // namespace flag

    /// 构造帧
    [[nodiscard]] inline auto build_frame(const type frame_type, const std::uint16_t flags,
                                          const std::uint32_t stream_id, const view data) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_u8(static_cast<std::uint8_t>(frame_type));
        w.write_u16(flags);
        w.write_u32(stream_id);
        w.write_u32(static_cast<std::uint32_t>(data.size()));
        w.write_bytes(data);
        return w.data();
    }

    /// 解析帧
    struct frame
    {
        std::uint8_t ver{0};
        std::uint8_t type{0};
        std::uint16_t flags{0};
        std::uint32_t stream_id{0};
        std::size_t data_offset{0};
        bool valid{false};
    };

    [[nodiscard]] inline auto parse_frame(const view data) -> frame
    {
        frame f;
        if (data.size() < frame_header_len)
            return f;
        if (data[0] != version)
            return f;
        f.ver = data[0];
        f.type = data[1];
        f.flags = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
        f.stream_id = static_cast<std::uint32_t>(data[4]) << 24
            | static_cast<std::uint32_t>(data[5]) << 16
            | static_cast<std::uint32_t>(data[6]) << 8 | data[7];
        const auto len = static_cast<std::size_t>(static_cast<std::uint32_t>(data[8]) << 24
            | static_cast<std::uint32_t>(data[9]) << 16
            | static_cast<std::uint32_t>(data[10]) << 8 | data[11]);
        if (data.size() < frame_header_len + len)
            return f;
        f.data_offset = frame_header_len;
        f.valid = true;
        return f;
    }

} // namespace psm_test::yamux
