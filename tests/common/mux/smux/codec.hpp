/**
 * @file codec.hpp
 * @brief smux 帧编解码（纯函数，零状态）
 * @details 提供帧构造（build）与增量解析（parse），全部为无状态
 *          纯函数，通过 parser<config> 组合成状态机。
 *          帧格式：[Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE][Payload]
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <common/core/error.hpp>
#include <common/core/parser.hpp>
#include <common/mux/codec.hpp>
#include <common/mux/smux/types.hpp>

namespace psmtest::mux::smux
{

    /**
     * @brief 构造 smux 帧字节序列
     * @param hdr 帧头
     * @param payload 负载数据
     * @return 完整帧（帧头 + 负载）
     */
    [[nodiscard]] inline auto build(const frame_header &hdr, std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(frame_hdrsize + payload.size());
        out.push_back(hdr.version);
        out.push_back(static_cast<std::uint8_t>(hdr.cmd));
        out.push_back(static_cast<std::uint8_t>(hdr.length & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.length >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.stream_id & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.stream_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.stream_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.stream_id >> 24) & 0xFF));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 构造 SYN 帧
     * @param stream_id 流标识符
     * @return 8 字节帧
     */
    [[nodiscard]] inline auto build_syn(std::uint32_t stream_id) -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{.cmd = command::syn, .stream_id = stream_id};
        const auto frame = build(hdr);
        std::array<std::uint8_t, frame_hdrsize> out{};
        std::memcpy(out.data(), frame.data(), frame_hdrsize);
        return out;
    }

    /**
     * @brief 构造 FIN 帧
     * @param stream_id 流标识符
     * @return 8 字节帧
     */
    [[nodiscard]] inline auto build_fin(std::uint32_t stream_id) -> std::array<std::uint8_t, frame_hdrsize>
    {
        const frame_header hdr{.cmd = command::fin, .stream_id = stream_id};
        const auto frame = build(hdr);
        std::array<std::uint8_t, frame_hdrsize> out{};
        std::memcpy(out.data(), frame.data(), frame_hdrsize);
        return out;
    }

    /**
     * @brief 构造 PSH（数据）帧
     * @param stream_id 流标识符
     * @param payload 负载
     * @return 完整帧
     */
    [[nodiscard]] inline auto build_push(std::uint32_t stream_id, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        const frame_header hdr{
            .cmd = command::push,
            .length = static_cast<std::uint16_t>(payload.size()),
            .stream_id = stream_id,
        };
        return build(hdr, payload);
    }

    /**
     * @brief 解析 8 字节帧头
     * @param data 至少 8 字节
     * @param out 输出帧头
     * @return 错误码（bad_magic = 版本/命令非法）
     */
    [[nodiscard]] inline auto parse_header(std::span<const std::uint8_t> data, frame_header &out) -> error
    {
        if (data.size() < frame_hdrsize)
        {
            return error::need_more;
        }
        out.version = data[0];
        if (out.version != protocol_version)
        {
            return error::bad_magic;
        }
        out.cmd = static_cast<command>(data[1]);
        switch (out.cmd)
        {
        case command::syn:
        case command::fin:
        case command::push:
        case command::nop: break;
        default: return error::bad_message;
        }
        out.length = static_cast<std::uint16_t>(data[2]) | static_cast<std::uint16_t>(data[3]) << 8;
        if (out.length > max_frame_length)
        {
            return error::bad_length;
        }
        out.stream_id = static_cast<std::uint32_t>(data[4]) | static_cast<std::uint32_t>(data[5]) << 8 |
                        static_cast<std::uint32_t>(data[6]) << 16 | static_cast<std::uint32_t>(data[7]) << 24;
        return error::none;
    }

    /**
     * @brief 校验负载（smux 无额外校验，直接返回 none）
     * @return 恒为 error::none
     */
    [[nodiscard]] inline auto parse_payload(frame_header &, std::span<const std::uint8_t>) -> error
    {
        return error::none;
    }

    /**
     * @struct codec
     * @brief smux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 frame_codec concept：帧构造与帧事件判定。
     *          协议无独立 RST 帧，build_rst 以 FIN 帧近似（见下）。
     */
    struct codec
    {
        /// 帧类型
        using frame_type = frame_header;

        /// 帧头长度
        static inline constexpr std::size_t header_len = frame_hdrsize;

        /// 最大负载长度
        static inline constexpr std::size_t max_payload_len = max_frame_length;

        /**
         * @brief 由帧头计算负载长度
         * @param frame 帧头
         * @return 负载长度
         */
        [[nodiscard]] static auto payload_len(const frame_type &frame) noexcept -> std::size_t
        {
            return frame.length;
        }

        /**
         * @brief 解析帧头
         * @param data 帧头字节
         * @param out 输出帧头
         * @return 错误码
         */
        static auto parse_header(std::span<const std::uint8_t> data, frame_type &out) -> error
        {
            return smux::parse_header(data, out);
        }

        /**
         * @brief 解析负载
         * @param frame 帧头
         * @param data 负载字节
         * @return 错误码（恒为 none）
         */
        static auto parse_payload(frame_type &frame, std::span<const std::uint8_t> data) -> error
        {
            return smux::parse_payload(frame, data);
        }

        /**
         * @brief 帧事件判定
         * @param frame 帧头
         * @return 流事件（syn=开流 / fin=半关 / push=数据 / 其余=rst）
         */
        [[nodiscard]] static auto frame_event(const frame_type &frame) noexcept -> mux::stream_event
        {
            switch (frame.cmd)
            {
            case command::syn: return mux::stream_event::open;
            case command::fin: return mux::stream_event::fin;
            case command::push: return mux::stream_event::data;
            default: return mux::stream_event::rst; // nop 忽略
            }
        }

        /**
         * @brief 会话级控制帧判定
         * @param frame 帧头
         * @return true = 会话级（nop 心跳，忽略）
         */
        [[nodiscard]] static auto is_control(const frame_type &frame) noexcept -> bool
        {
            return frame.cmd == command::nop;
        }

        /**
         * @brief 取帧流标识
         * @param frame 帧头
         * @return 流标识符
         */
        [[nodiscard]] static auto frame_stream_id(const frame_type &frame) noexcept -> std::uint32_t
        {
            return frame.stream_id;
        }

        /**
         * @brief 构造开流帧（SYN）
         * @param id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto build_open(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            const auto frame = smux::build_syn(id);
            return {frame.begin(), frame.end()};
        }

        /**
         * @brief 构造数据帧（PSH）
         * @param id 流标识符
         * @param data 负载
         * @return 完整帧
         */
        [[nodiscard]] static auto build_data(std::uint32_t id, std::span<const std::uint8_t> data)
            -> std::vector<std::uint8_t>
        {
            return smux::build_push(id, data);
        }

        /**
         * @brief 构造 FIN 帧（半关）
         * @param id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto build_fin(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            const auto frame = smux::build_fin(id);
            return {frame.begin(), frame.end()};
        }

        /**
         * @brief 构造 RST 帧
         * @param id 流标识符
         * @return 完整帧
         * @warning smux 协议无 RST 帧，以 FIN 帧近似（对端按半关处理）
         */
        [[nodiscard]] static auto build_rst(std::uint32_t id) -> std::vector<std::uint8_t>
        {
            return build_fin(id);
        }
    };

    static_assert(mux::frame_codec<codec>, "smux::codec 必须满足 frame_codec");

} // namespace psmtest::mux::smux
