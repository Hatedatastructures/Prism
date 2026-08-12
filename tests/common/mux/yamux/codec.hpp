/**
 * @file codec.hpp
 * @brief yamux 帧编解码（纯函数，零状态，大端序）
 * @details 帧格式：[Version 1B][Type 1B][Flags 2B BE][StreamID 4B BE][Length 4B BE]，
 *          Length 字段含义随 Type 变化（Data = 载荷长）。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/parser.hpp>
#include <common/mux/codec.hpp>
#include <common/mux/yamux/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace psmtest::mux::yamux
{

    /// @brief 编码帧头为 12 字节大端序数组
    /// @param hdr 帧头
    /// @return 编码后的字节数组
    [[nodiscard]] inline auto build_header(const frame_header &hdr) noexcept
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        std::array<std::uint8_t, frame_hdrsize> out{};
        out[0] = hdr.version;
        out[1] = static_cast<std::uint8_t>(hdr.type);
        out[2] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(hdr.flag) >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(hdr.flag) & 0xFF);
        out[4] = static_cast<std::uint8_t>((hdr.stream_id >> 24) & 0xFF);
        out[5] = static_cast<std::uint8_t>((hdr.stream_id >> 16) & 0xFF);
        out[6] = static_cast<std::uint8_t>((hdr.stream_id >> 8) & 0xFF);
        out[7] = static_cast<std::uint8_t>(hdr.stream_id & 0xFF);
        out[8] = static_cast<std::uint8_t>((hdr.length >> 24) & 0xFF);
        out[9] = static_cast<std::uint8_t>((hdr.length >> 16) & 0xFF);
        out[10] = static_cast<std::uint8_t>((hdr.length >> 8) & 0xFF);
        out[11] = static_cast<std::uint8_t>(hdr.length & 0xFF);
        return out;
    }

    /// @brief 构造完整帧（帧头 + 载荷）
    /// @param hdr 帧头（length 自动填充）
    /// @param payload 载荷
    /// @return 完整帧
    [[nodiscard]] inline auto build(const frame_header &hdr, std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto hdr_copy = hdr;
        if (hdr_copy.type == message_type::data)
            hdr_copy.length = static_cast<std::uint32_t>(payload.size());
        const auto header = build_header(hdr_copy);
        std::vector<std::uint8_t> out;
        out.reserve(frame_hdrsize + payload.size());
        out.insert(out.end(), header.begin(), header.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /// @brief 构造 WindowUpdate 帧（SYN/ACK 打开/确认流）
    /// @param f 标志位
    /// @param stream_id 流标识符
    /// @param delta 窗口增量
    /// @return 12 字节帧
    [[nodiscard]] inline auto build_winupd(flags f, std::uint32_t stream_id, std::uint32_t delta) noexcept
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{
            .type = message_type::window_update,
            .flag = f,
            .stream_id = stream_id,
            .length = delta,
        };
        return build_header(hdr);
    }

    /// @brief 构造 Ping 帧
    /// @param f 标志位（SYN 请求 / ACK 响应）
    /// @param ping_id 心跳标识
    /// @return 12 字节帧
    [[nodiscard]] inline auto build_ping(flags f, std::uint32_t ping_id) noexcept
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{
            .type = message_type::ping,
            .flag = f,
            .stream_id = 0,
            .length = ping_id,
        };
        return build_header(hdr);
    }

    /// @brief 构造 GoAway 帧
    /// @param code 终止原因码
    /// @return 12 字节帧
    [[nodiscard]] inline auto build_goaway(away_code code) noexcept
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{
            .type = message_type::go_away,
            .flag = flags::none,
            .stream_id = 0,
            .length = static_cast<std::uint32_t>(code),
        };
        return build_header(hdr);
    }

    /// @brief 构造 Data 帧
    /// @param f 标志位（none/SYN/FIN/RST）
    /// @param stream_id 流标识符
    /// @param payload 载荷
    /// @return 完整帧
    [[nodiscard]] inline auto build_data(flags f, std::uint32_t stream_id,
                                         std::span<const std::uint8_t> payload) noexcept
        -> std::vector<std::uint8_t>
    {
        const frame_header hdr{
            .type = message_type::data,
            .flag = f,
            .stream_id = stream_id,
        };
        return build(hdr, payload);
    }

    /// @brief 构造 Data(SYN) 帧（sing-mux 兼容新流创建）
    [[nodiscard]] inline auto build_syn(std::uint32_t stream_id,
                                        std::span<const std::uint8_t> payload) noexcept
        -> std::vector<std::uint8_t>
    {
        return build_data(flags::syn, stream_id, payload);
    }

    /// @brief 构造 Data(FIN) 帧
    [[nodiscard]] inline auto build_fin(std::uint32_t stream_id) noexcept
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{
            .type = message_type::data,
            .flag = flags::fin,
            .stream_id = stream_id,
        };
        return build_header(hdr);
    }

    /// @brief 解析 12 字节帧头
    /// @param data 至少 12 字节
    /// @param out 输出帧头
    /// @return 错误码
    [[nodiscard]] inline auto parse_header(std::span<const std::uint8_t> data, frame_header &out) noexcept
        -> error
    {
        if (data.size() < frame_hdrsize)
            return error::need_more;
        out.version = data[0];
        if (out.version != protocol_version)
            return error::bad_magic;
        out.type = static_cast<message_type>(data[1]);
        switch (out.type)
        {
            case message_type::data:
            case message_type::window_update:
            case message_type::ping:
            case message_type::go_away:
                break;
            default:
                return error::bad_message;
        }
        out.flag = static_cast<flags>(
            static_cast<std::uint16_t>(data[2]) << 8 |
            static_cast<std::uint16_t>(data[3]));
        out.stream_id = static_cast<std::uint32_t>(data[4]) << 24 |
                        static_cast<std::uint32_t>(data[5]) << 16 |
                        static_cast<std::uint32_t>(data[6]) << 8 |
                        static_cast<std::uint32_t>(data[7]);
        out.length = static_cast<std::uint32_t>(data[8]) << 24 |
                     static_cast<std::uint32_t>(data[9]) << 16 |
                     static_cast<std::uint32_t>(data[10]) << 8 |
                     static_cast<std::uint32_t>(data[11]);
        return error::none;
    }

    /// @brief 校验负载（yamux 无额外校验）
    [[nodiscard]] inline auto parse_payload(frame_header &, std::span<const std::uint8_t>) -> error
    {
        return error::none;
    }

    /**
     * @struct codec
     * @brief yamux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 frame_codec concept：帧构造与帧事件判定。
     *          开流 = WindowUpdate(SYN)，数据/半关/重置均为 Data 帧
     *          + 对应标志位。
     */
    struct codec
    {
        /// 帧类型
        using frame_type = frame_header;

        /// 帧头长度
        static inline constexpr std::size_t header_len = frame_hdrsize;

        /// 最大负载长度（yamux 无硬限制，取 16MB）
        static inline constexpr std::size_t max_payload_len = 16 * 1024 * 1024;

        /// @brief 由帧头计算负载长度
        /// @param frame 帧头
        /// @return 负载长度（非 Data 帧恒为 0）
        [[nodiscard]] static auto payload_len(const frame_type &frame) noexcept -> std::size_t
        {
            return frame.type == message_type::data ? frame.length : 0;
        }

        /// @brief 解析帧头
        /// @param data 帧头字节
        /// @param out 输出帧头
        /// @return 错误码
        static auto parse_header(std::span<const std::uint8_t> data, frame_type &out) -> error
        {
            return yamux::parse_header(data, out);
        }

        /// @brief 解析负载
        /// @param frame 帧头
        /// @param data 负载字节
        /// @return 错误码（恒为 none）
        static auto parse_payload(frame_type &frame, std::span<const std::uint8_t> data) -> error
        {
            return yamux::parse_payload(frame, data);
        }

        /// @brief 帧事件判定
        /// @param frame 帧头
        /// @return 流事件（Data+SYN=开流 / Data+FIN=半关 / Data+RST=重置 /
        ///          Data=数据 / 其余=rst 忽略）
        [[nodiscard]] static auto frame_event(const frame_type &frame) noexcept -> mux::stream_event
        {
            if (frame.type == message_type::data)
            {
                if (has_flag(frame.flag, flags::syn))
                    return mux::stream_event::open;
                if (has_flag(frame.flag, flags::fin))
                    return mux::stream_event::fin;
                if (has_flag(frame.flag, flags::rst))
                    return mux::stream_event::rst;
                return mux::stream_event::data;
            }
            return mux::stream_event::rst; // winupd/ping/goaway：会话级，忽略
        }

        /// @brief 会话级控制帧判定
        /// @param frame 帧头
        /// @return true = 会话级（window_update / ping / go_away，忽略）
        [[nodiscard]] static auto is_control(const frame_type &frame) noexcept -> bool
        {
            return frame.type != message_type::data;
        }

        /// @brief 取帧流标识
        /// @param frame 帧头
        /// @return 流标识符
        [[nodiscard]] static auto frame_stream_id(const frame_type &frame) noexcept -> std::uint32_t
        {
            return frame.stream_id;
        }

        /// @brief 构造开流帧（WindowUpdate+SYN，Length = 初始窗口）
        /// @param id 流标识符
        /// @return 完整帧
        [[nodiscard]] static auto build_open(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            const auto frame = yamux::build_winupd(flags::syn, id, default_window);
            return {frame.begin(), frame.end()};
        }

        /// @brief 构造数据帧（Data）
        /// @param id 流标识符
        /// @param data 负载
        /// @return 完整帧
        [[nodiscard]] static auto build_data(std::uint32_t id, std::span<const std::uint8_t> data)
            -> std::vector<std::uint8_t>
        {
            return yamux::build_data(flags::none, id, data);
        }

        /// @brief 构造 FIN 帧（Data+FIN，半关）
        /// @param id 流标识符
        /// @return 完整帧
        [[nodiscard]] static auto build_fin(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            const auto frame = yamux::build_fin(id);
            return {frame.begin(), frame.end()};
        }

        /// @brief 构造 RST 帧（Data+RST，重置流）
        /// @param id 流标识符
        /// @return 完整帧
        [[nodiscard]] static auto build_rst(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            return yamux::build_data(flags::rst, id, {});
        }
    };

    static_assert(mux::frame_codec<codec>, "yamux::codec 必须满足 frame_codec");

} // namespace psmtest::mux::yamux
