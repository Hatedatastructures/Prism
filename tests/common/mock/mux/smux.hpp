/**
 * @file smux.hpp
 * @brief SMUX 多路复用帧编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          帧 = [ver 1B][cmd 1B][length 2B BE][streamID 4B BE][data]
 *          cmd：SYN/ACK/FIN/RST/PSH/NOP
 *          命名空间 psm_test::smux，参考 xtaci/smux（mihomo 依赖）。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::smux
{

    inline constexpr std::uint8_t version = 1;
    inline constexpr std::size_t frame_header_len = 8;

    enum class cmd : std::uint8_t
    {
        syn = 0,
        ack = 1,
        fin = 2,
        rst = 3,
        psh = 4,
        nop = 5,
    };

    /// 构造帧
    [[nodiscard]] inline auto build_frame(const cmd command, const std::uint32_t stream_id,
                                          const view data) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_u8(static_cast<std::uint8_t>(command));
        w.write_u16(static_cast<std::uint16_t>(data.size()));
        w.write_u32(stream_id);
        w.write_bytes(data);
        return w.data();
    }

    /// 解析帧
    struct frame
    {
        std::uint8_t ver{0};
        std::uint8_t cmd{0};
        std::uint32_t stream_id{0};
        std::size_t data_offset{0};
        bool valid{false};
    };

    /// 从流缓冲解析一帧（不足一帧返回 invalid；不消费数据）
    [[nodiscard]] inline auto parse_frame(const view data) -> frame
    {
        frame f;
        if (data.size() < frame_header_len)
            return f;
        if (data[0] != version)
            return f;
        f.ver = data[0];
        f.cmd = data[1];
        const auto len = static_cast<std::size_t>((data[2] << 8) | data[3]);
        f.stream_id = static_cast<std::uint32_t>(data[4]) << 24
            | static_cast<std::uint32_t>(data[5]) << 16
            | static_cast<std::uint32_t>(data[6]) << 8 | data[7];
        if (data.size() < frame_header_len + len)
            return f;
        f.data_offset = frame_header_len;
        f.valid = true;
        return f;
    }

} // namespace psm_test::smux
