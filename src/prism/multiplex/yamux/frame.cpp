/**
 * @file frame.cpp
 * @brief yamux 协议帧编解码实现
 * @details 实现 yamux 帧头的编码和解码函数。所有多字节字段使用大端序（网络字节序）。
 */

#include <prism/multiplex/yamux/frame.hpp>

#include <cstring>

namespace psm::multiplex::yamux
{
    // === 帧头编码 ===

    auto build_header(const frame_header &hdr) noexcept
        -> std::array<std::byte, frame_header_size>
    {
        return {
            // Version (1B)
            std::byte{hdr.version},
            // Type (1B)
            static_cast<std::byte>(hdr.type),
            // Flags (2B BE)
            static_cast<std::byte>(static_cast<std::uint16_t>(hdr.flag) >> 8 & 0xFF),
            static_cast<std::byte>(static_cast<std::uint16_t>(hdr.flag) & 0xFF),
            // StreamID (4B BE)
            static_cast<std::byte>(hdr.stream_id >> 24 & 0xFF),
            static_cast<std::byte>(hdr.stream_id >> 16 & 0xFF),
            static_cast<std::byte>(hdr.stream_id >> 8 & 0xFF),
            static_cast<std::byte>(hdr.stream_id & 0xFF),
            // Length (4B BE)
            static_cast<std::byte>(hdr.length >> 24 & 0xFF),
            static_cast<std::byte>(hdr.length >> 16 & 0xFF),
            static_cast<std::byte>(hdr.length >> 8 & 0xFF),
            static_cast<std::byte>(hdr.length & 0xFF),
        };
    }

    // === 帧头解码 ===

    auto parse_header(const std::span<const std::byte> buffer) noexcept
        -> std::optional<frame_header>
    {
        if (buffer.size() < frame_header_size)
        {
            return std::nullopt;
        }

        frame_header hdr{};

        // Version (1B)
        hdr.version = static_cast<std::uint8_t>(buffer[0]);
        if (hdr.version != protocol_version)
        {
            return std::nullopt;
        }

        // Type (1B)
        hdr.type = static_cast<message_type>(buffer[1]);
        switch (hdr.type)
        {
        case message_type::data:
        case message_type::window_update:
        case message_type::ping:
        case message_type::go_away:
            break;
        default:
            return std::nullopt;
        }

        // Flags (2B BE)
        hdr.flag = static_cast<flags>(
            static_cast<std::uint16_t>(buffer[2]) << 8 |
            static_cast<std::uint16_t>(buffer[3]));

        // StreamID (4B BE)
        hdr.stream_id =
            static_cast<std::uint32_t>(buffer[4]) << 24 |
            static_cast<std::uint32_t>(buffer[5]) << 16 |
            static_cast<std::uint32_t>(buffer[6]) << 8 |
            static_cast<std::uint32_t>(buffer[7]);

        // Length (4B BE)
        hdr.length =
            static_cast<std::uint32_t>(buffer[8]) << 24 |
            static_cast<std::uint32_t>(buffer[9]) << 16 |
            static_cast<std::uint32_t>(buffer[10]) << 8 |
            static_cast<std::uint32_t>(buffer[11]);

        return hdr;
    }

    // === 构建特定帧类型 ===

    auto build_window_update_frame(const flags f, const std::uint32_t stream_id, const std::uint32_t delta) noexcept
        -> std::array<std::byte, frame_header_size>
    {
        frame_header hdr{};
        hdr.type = message_type::window_update;
        hdr.flag = f;
        hdr.stream_id = stream_id;
        hdr.length = delta;
        return build_header(hdr);
    }

    auto build_ping_frame(const flags f, const std::uint32_t ping_id) noexcept
        -> std::array<std::byte, frame_header_size>
    {
        frame_header hdr{};
        hdr.type = message_type::ping;
        hdr.flag = f;
        hdr.stream_id = 0;
        hdr.length = ping_id;
        return build_header(hdr);
    }

    auto build_go_away_frame(const go_away_code code) noexcept
        -> std::array<std::byte, frame_header_size>
    {
        frame_header hdr{};
        hdr.type = message_type::go_away;
        hdr.flag = flags::none;
        hdr.stream_id = 0;
        hdr.length = static_cast<std::uint32_t>(code);
        return build_header(hdr);
    }

} // namespace psm::multiplex::yamux
