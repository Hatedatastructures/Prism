/**
 * @file h2mux.hpp
 * @brief H2Mux（sing-box HTTP/2 多路复用）扩展帧编解码
 * @details 纯逻辑（无锁）：
 *          在 HTTP/2 帧上扩展自定义帧（StreamRequest/StreamResponse）：
 *          帧 = [h2 帧头 9B][扩展帧载荷]
 *          StreamRequest = [类型 1B=0x9A? 见说明][请求头]
 *          命名空间 psm_test::h2mux，参考 sing-box h2mux。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::h2mux
{

    /// HTTP/2 帧头（9 字节）
    [[nodiscard]] inline auto build_h2_frame(const std::uint8_t frame_type,
                                             const std::uint8_t flags,
                                             const std::uint32_t stream_id,
                                             const view payload) -> buffer
    {
        byte_writer w;
        w.write_u8(static_cast<std::uint8_t>(payload.size() >> 16));
        w.write_u8(static_cast<std::uint8_t>(payload.size() >> 8));
        w.write_u8(static_cast<std::uint8_t>(payload.size() & 0xFF));
        w.write_u8(frame_type);
        w.write_u8(flags);
        w.write_u32(stream_id & 0x7FFFFFFF);
        w.write_bytes(payload);
        return w.data();
    }

    /// 解析 HTTP/2 帧头
    struct h2_frame
    {
        std::uint8_t type{0};
        std::uint8_t flags{0};
        std::uint32_t stream_id{0};
        std::size_t payload_offset{9};
        bool valid{false};
    };

    [[nodiscard]] inline auto parse_h2_frame(const view data) -> h2_frame
    {
        h2_frame f;
        if (data.size() < 9)
            return f;
        const auto len = static_cast<std::size_t>(data[0]) << 16
            | static_cast<std::size_t>(data[1]) << 8 | data[2];
        if (data.size() < 9 + len)
            return f;
        f.type = data[3];
        f.flags = data[4];
        f.stream_id = static_cast<std::uint32_t>(data[5]) << 24
            | static_cast<std::uint32_t>(data[6]) << 16
            | static_cast<std::uint32_t>(data[7]) << 8 | data[8];
        f.stream_id &= 0x7FFFFFFF;
        f.valid = true;
        return f;
    }

} // namespace psm_test::h2mux
