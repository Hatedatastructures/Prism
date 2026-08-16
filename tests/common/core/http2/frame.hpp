/**
 * @file frame.hpp
 * @brief HTTP/2 帧编解码（自包含实现，不依赖 nghttp2）
 * @details 9 字节帧头 + 各类帧载荷编解码：
 *          - frame_header：9 字节帧头（len24 + type + flags + stream_id31）
 *          - build_frame / parse_frame：通用帧组装/解析
 *          - 各帧载荷：DATA/HEADERS/SETTINGS/PING/GOAWAY/WINDOW_UPDATE/RST_STREAM
 * @note HPACK 头压缩见 codec.hpp；流状态机见 session.hpp
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <common/core/error.hpp>

namespace psmtest::http2
{

    /// 帧类型（RFC 7540 §6）
    enum class frame_type : std::uint8_t
    {
        data = 0x0,          ///< DATA
        headers = 0x1,       ///< HEADERS
        priority = 0x2,      ///< PRIORITY
        rst_stream = 0x3,    ///< RST_STREAM
        settings = 0x4,      ///< SETTINGS
        push_promise = 0x5,  ///< PUSH_PROMISE
        ping = 0x6,          ///< PING
        goaway = 0x7,        ///< GOAWAY
        window_update = 0x8, ///< WINDOW_UPDATE
        continuation = 0x9,  ///< CONTINUATION
    };

    /// 帧标志位（RFC 7540 §6）
    enum frame_flag : std::uint8_t
    {
        flag_none = 0x0,
        flag_end_stream = 0x1,    ///< END_STREAM
        flag_end_headers = 0x4,   ///< END_HEADERS
        flag_padded = 0x8,        ///< PADDED
        flag_priority = 0x20,     ///< PRIORITY
        flag_ack = 0x1,           ///< ACK
        flag_settings_ack = 0x1,  ///< SETTINGS ACK
    };

    /// 帧头（9 字节）
    struct frame_header
    {
        std::uint32_t length{0};      ///< 载荷长度（24 位）
        frame_type type{frame_type::data}; ///< 帧类型
        std::uint8_t flags{0};        ///< 标志位
        std::uint32_t stream_id{0};   ///< 流 ID（31 位）
    };

    /// SETTINGS 参数
    struct settings_entry
    {
        std::uint16_t id{0};     ///< 参数 ID
        std::uint32_t value{0};  ///< 参数值
    };

    /// GOAWAY 参数
    struct goaway_params
    {
        std::uint32_t last_stream_id{0}; ///< 最后处理的流 ID
        std::uint32_t error_code{0};     ///< 错误码
        std::vector<std::byte> debug;    ///< 调试数据
    };

    /// WINDOW_UPDATE 载荷
    struct window_update_params
    {
        std::uint32_t increment{0}; ///< 窗口增量（31 位）
    };

    /// RST_STREAM 载荷
    struct rst_stream_params
    {
        std::uint32_t error_code{0}; ///< 错误码
    };

    /// 帧头大小（固定 9 字节）
    constexpr std::size_t frame_header_size = 9;

    /// 最大帧载荷（默认 16384）
    constexpr std::size_t default_frame_payload = 16384;

    /// 初始流窗口（65535）
    constexpr std::uint32_t default_initial_window = 65535;

    /// 连接流 ID（0）
    constexpr std::uint32_t connection_stream_id = 0;

    /**
     * @brief 编码 24 位长度
     * @param len 长度值（≤ 0xFFFFFF）
     * @param out 输出缓冲区（3 字节）
     */
    inline void encode_len24(std::uint32_t len, std::span<std::byte, 3> out) noexcept
    {
        out[0] = static_cast<std::byte>((len >> 16) & 0xFF);
        out[1] = static_cast<std::byte>((len >> 8) & 0xFF);
        out[2] = static_cast<std::byte>(len & 0xFF);
    }

    /**
     * @brief 解码 24 位长度
     * @param in 输入缓冲区（3 字节）
     * @return 长度值
     */
    [[nodiscard]] inline auto decode_len24(std::span<const std::byte, 3> in) noexcept -> std::uint32_t
    {
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2]));
    }

    /**
     * @brief 编码 31 位流 ID / 窗口增量
     * @param val 值（≤ 0x7FFFFFFF）
     * @param out 输出缓冲区（4 字节）
     */
    inline void encode_u31(std::uint32_t val, std::span<std::byte, 4> out) noexcept
    {
        out[0] = static_cast<std::byte>((val >> 24) & 0x7F);
        out[1] = static_cast<std::byte>((val >> 16) & 0xFF);
        out[2] = static_cast<std::byte>((val >> 8) & 0xFF);
        out[3] = static_cast<std::byte>(val & 0xFF);
    }

    /**
     * @brief 解码 31 位值
     * @param in 输入缓冲区（至少 4 字节）
     * @return 值
     */
    [[nodiscard]] inline auto decode_u31(std::span<const std::byte> in) noexcept -> std::uint32_t
    {
        if (in.size() < 4)
        {
            return 0;
        }
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0]) & 0x7F) << 24) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[3]));
    }

    /**
     * @brief 构建帧（帧头 + 载荷）
     * @param type 帧类型
     * @param flags 标志位
     * @param stream_id 流 ID
     * @param payload 载荷（可空）
     * @return 完整帧字节（9 + payload.size()）
     */
    [[nodiscard]] inline auto build_frame(frame_type type, std::uint8_t flags, std::uint32_t stream_id,
                                          std::span<const std::byte> payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> frame;
        frame.reserve(frame_header_size + payload.size());
        frame.resize(frame_header_size);
        const auto header = std::span<std::byte>(frame.data(), frame_header_size);
        encode_len24(static_cast<std::uint32_t>(payload.size()), header.first<3>());
        header[3] = static_cast<std::byte>(type);
        header[4] = static_cast<std::byte>(flags);
        encode_u31(stream_id, header.last<4>());
        frame.insert(frame.end(), payload.begin(), payload.end());
        return frame;
    }

    /**
     * @brief 解析帧头
     * @param data 输入（至少 9 字节）
     * @return 解析后的帧头；不足返回 std::nullopt
     */
    [[nodiscard]] inline auto parse_frame_header(std::span<const std::byte> data)
        -> std::optional<frame_header>
    {
        if (data.size() < frame_header_size)
        {
            return std::nullopt;
        }
        frame_header h;
        const auto head = data.first<9>();
        h.length = decode_len24(head.first<3>());
        h.type = static_cast<frame_type>(std::to_integer<std::uint8_t>(head[3]));
        h.flags = std::to_integer<std::uint8_t>(head[4]);
        h.stream_id = decode_u31(head.last<4>());
        return h;
    }

    /**
     * @brief 编码 SETTINGS 参数
     * @param entries 参数列表
     * @return 载荷字节
     */
    [[nodiscard]] inline auto encode_settings(std::span<const settings_entry> entries)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        out.reserve(entries.size() * 6);
        for (const auto &e : entries)
        {
            out.push_back(static_cast<std::byte>((e.id >> 8) & 0xFF));
            out.push_back(static_cast<std::byte>(e.id & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 24) & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 16) & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 8) & 0xFF));
            out.push_back(static_cast<std::byte>(e.value & 0xFF));
        }
        return out;
    }

    /**
     * @brief 解码 SETTINGS 载荷
     * @param data 载荷字节
     * @return 参数列表；长度非法返回 std::nullopt
     */
    [[nodiscard]] inline auto decode_settings(std::span<const std::byte> data)
        -> std::optional<std::vector<settings_entry>>
    {
        if (data.size() % 6 != 0)
        {
            return std::nullopt;
        }
        std::vector<settings_entry> entries;
        entries.reserve(data.size() / 6);
        for (std::size_t i = 0; i < data.size(); i += 6)
        {
            settings_entry e;
            e.id = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[i])) << 8) |
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[i + 1])));
            e.value = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i + 2])) << 24) |
                      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i + 3])) << 16) |
                      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i + 4])) << 8) |
                      static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i + 5]));
            entries.push_back(e);
        }
        return entries;
    }

    /**
     * @brief 编码 WINDOW_UPDATE 载荷
     * @param increment 窗口增量
     * @return 4 字节载荷
     */
    [[nodiscard]] inline auto encode_window_update(std::uint32_t increment) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> out{};
        encode_u31(increment, out);
        return out;
    }

    /**
     * @brief 编码 RST_STREAM 载荷
     * @param error_code 错误码
     * @return 4 字节载荷
     */
    [[nodiscard]] inline auto encode_rst_stream(std::uint32_t error_code) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> out{};
        encode_u31(error_code, out);
        return out;
    }

    /**
     * @brief 编码 GOAWAY 载荷
     * @param params GOAWAY 参数
     * @return 载荷字节
     */
    [[nodiscard]] inline auto encode_goaway(const goaway_params &params) -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        out.reserve(8 + params.debug.size());
        out.resize(8);
        const auto head = std::span<std::byte>(out.data(), 8);
        encode_u31(params.last_stream_id, head.first<4>());
        encode_u31(params.error_code, head.last<4>());
        out.insert(out.end(), params.debug.begin(), params.debug.end());
        return out;
    }

    /// 常见 SETTINGS 参数 ID（RFC 7540 §6.5.2）
    constexpr std::uint16_t settings_header_table_size = 0x1;
    constexpr std::uint16_t settings_enable_push = 0x2;
    constexpr std::uint16_t settings_max_concurrent_streams = 0x3;
    constexpr std::uint16_t settings_initial_window_size = 0x4;
    constexpr std::uint16_t settings_max_frame_size = 0x5;
    constexpr std::uint16_t settings_max_header_list_size = 0x6;

    /// 常见错误码（RFC 7540 §7）
    constexpr std::uint32_t error_no_error = 0x0;
    constexpr std::uint32_t error_protocol = 0x1;
    constexpr std::uint32_t error_internal = 0x2;
    constexpr std::uint32_t error_flow_control = 0x3;
    constexpr std::uint32_t error_stream_closed = 0x5;
    constexpr std::uint32_t error_frame_size = 0x6;
    constexpr std::uint32_t error_refused_stream = 0x7;
    constexpr std::uint32_t error_cancel = 0x8;
    constexpr std::uint32_t error_compression = 0x9;

} // namespace psmtest::http2
