/**
 * @file codec.hpp
 * @brief sing-mux（h2mux）帧编解码（纯函数，零状态，大端序）
 * @details 帧格式：[Type 1B][Length 4B BE][StreamID 4B BE] = 9 字节，
 *          与 sing-box singmux 协议兼容。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/parser.hpp>
#include <common/mux/codec.hpp>
#include <common/mux/h2mux/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace psmtest::mux::h2mux
{

    /// @brief 构造 sing-mux 帧
    /// @param type 帧类型
    /// @param stream_id 流标识符
    /// @param payload 负载
    /// @return 完整帧
    [[nodiscard]] inline auto build(frame_type type, std::uint32_t stream_id,
                                    std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(frame_hdrsize + payload.size());
        out.push_back(static_cast<std::uint8_t>(type));
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(payload.size() & 0xFF));
        out.push_back(static_cast<std::uint8_t>((stream_id >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((stream_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((stream_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(stream_id & 0xFF));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /// @brief 构造 DATA 帧
    [[nodiscard]] inline auto build_data(std::uint32_t stream_id, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        return build(frame_type::data, stream_id, payload);
    }

    /// @brief 构造 WindowUpdate 帧
    /// @param stream_id 流标识符
    /// @param delta 窗口增量
    /// @return 9 字节帧
    [[nodiscard]] inline auto build_winupd(std::uint32_t stream_id, std::uint32_t delta)
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const auto frame = build(frame_type::window_update, stream_id,
                                 std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(&delta),
                                     sizeof(delta)));
        std::array<std::uint8_t, frame_hdrsize> out{};
        std::memcpy(out.data(), frame.data(), frame_hdrsize);
        return out;
    }

    /// @brief 构造 Ping 帧
    /// @param ping_id 心跳标识（携带于负载 4 字节）
    /// @return 13 字节帧
    [[nodiscard]] inline auto build_ping(std::uint32_t ping_id) -> std::vector<std::uint8_t>
    {
        const auto payload = std::array<std::uint8_t, 4>{
            static_cast<std::uint8_t>((ping_id >> 24) & 0xFF),
            static_cast<std::uint8_t>((ping_id >> 16) & 0xFF),
            static_cast<std::uint8_t>((ping_id >> 8) & 0xFF),
            static_cast<std::uint8_t>(ping_id & 0xFF),
        };
        return build(frame_type::ping, 0, payload);
    }

    /// @brief 构造 Close 帧
    /// @param stream_id 流标识符
    /// @return 9 字节帧
    [[nodiscard]] inline auto build_close(std::uint32_t stream_id)
        -> std::array<std::uint8_t, frame_hdrsize>
    {
        const auto frame = build(frame_type::close, stream_id);
        std::array<std::uint8_t, frame_hdrsize> out{};
        std::memcpy(out.data(), frame.data(), frame_hdrsize);
        return out;
    }

    /// @brief 解析 9 字节帧头
    /// @param data 至少 9 字节
    /// @param out 输出帧头
    /// @return 错误码
    [[nodiscard]] inline auto parse_header(std::span<const std::uint8_t> data, frame_header &out) -> error
    {
        if (data.size() < frame_hdrsize)
            return error::need_more;
        out.type = static_cast<frame_type>(data[0]);
        out.length = static_cast<std::uint32_t>(data[1]) << 24 |
                     static_cast<std::uint32_t>(data[2]) << 16 |
                     static_cast<std::uint32_t>(data[3]) << 8 |
                     static_cast<std::uint32_t>(data[4]);
        if (out.length > max_frame_length)
            return error::bad_length;
        out.stream_id = static_cast<std::uint32_t>(data[5]) << 24 |
                        static_cast<std::uint32_t>(data[6]) << 16 |
                        static_cast<std::uint32_t>(data[7]) << 8 |
                        static_cast<std::uint32_t>(data[8]);
        return error::none;
    }

    /// @brief 校验负载
    [[nodiscard]] inline auto parse_payload(frame_header &, std::span<const std::uint8_t>) -> error
    {
        return error::none;
    }

    /// 帧编解码策略（供共享会话框架模板传参）
    struct codec
    {
        /// 帧类型
        using frame_type = frame_header;

        /// 帧头长度
        static inline constexpr std::size_t header_len = frame_hdrsize;

        /// 最大负载长度
        static inline constexpr std::size_t max_payload_len = max_frame_length;

        /// 由帧头计算负载长度
        [[nodiscard]] static auto payload_len(const frame_type &frame) noexcept -> std::size_t
        {
            return frame.length;
        }

        /// 解析帧头
        static auto parse_header(std::span<const std::uint8_t> data, frame_type &out) -> error
        {
            return h2mux::parse_header(data, out);
        }

        /// 解析负载
        static auto parse_payload(frame_type &frame, std::span<const std::uint8_t> data) -> error
        {
            return h2mux::parse_payload(frame, data);
        }

        /// 帧事件判定（DATA = 数据/隐式开流，CLOSE = 关闭，WINDOW_UPDATE/PING = 会话级）
        [[nodiscard]] static auto frame_event(const frame_type &frame) noexcept -> mux::stream_event
        {
            switch (frame.type)
            {
                case h2mux::frame_type::data:
                    return mux::stream_event::data;
                case h2mux::frame_type::close:
                    return mux::stream_event::fin;
                default:
                    return mux::stream_event::rst; // window_update/ping 忽略
            }
        }

        /// 帧流标识
        [[nodiscard]] static auto frame_stream_id(const frame_type &frame) noexcept -> std::uint32_t
        {
            return frame.stream_id;
        }

        /// 构造开流帧（h2mux 无 SYN：首数据帧即开流，此处为空帧）
        [[nodiscard]] static auto build_open(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            return build_data(id, {});
        }

        /// 构造数据帧
        [[nodiscard]] static auto build_data(std::uint32_t id, std::span<const std::uint8_t> data)
            -> std::vector<std::uint8_t>
        {
            return h2mux::build_data(id, data);
        }

        /// 构造 FIN 帧（CLOSE）
        [[nodiscard]] static auto build_fin(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            const auto frame = h2mux::build_close(id);
            return {frame.begin(), frame.end()};
        }
    };

    static_assert(mux::frame_codec<codec>, "h2mux::codec 必须满足 frame_codec");

} // namespace psmtest::mux::h2mux
