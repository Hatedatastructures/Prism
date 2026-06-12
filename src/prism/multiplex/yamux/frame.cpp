#include <prism/multiplex/yamux/frame.hpp>

#include <cstring>

namespace psm::multiplex::yamux
{

    auto build_header(const frame_header &hdr) noexcept
        -> std::array<std::byte, frame_hdrsize>
    {
        return {
            // 版本号（1 字节）
            std::byte{hdr.version},
            // 帧类型（1 字节）
            static_cast<std::byte>(hdr.type),
            // 标志位（2 字节大端序）
            static_cast<std::byte>(static_cast<std::uint16_t>(hdr.flag) >> 8 & 0xFF),
            static_cast<std::byte>(static_cast<std::uint16_t>(hdr.flag) & 0xFF),
            // 流 ID（4 字节大端序）
            static_cast<std::byte>(hdr.stream_id >> 24 & 0xFF),
            static_cast<std::byte>(hdr.stream_id >> 16 & 0xFF),
            static_cast<std::byte>(hdr.stream_id >> 8 & 0xFF),
            static_cast<std::byte>(hdr.stream_id & 0xFF),
            // 载荷长度（4 字节大端序）
            static_cast<std::byte>(hdr.length >> 24 & 0xFF),
            static_cast<std::byte>(hdr.length >> 16 & 0xFF),
            static_cast<std::byte>(hdr.length >> 8 & 0xFF),
            static_cast<std::byte>(hdr.length & 0xFF),
        };
    }

    auto parse_header(const std::span<const std::byte> buffer) noexcept
        -> std::optional<frame_header>
    {
        if (buffer.size() < frame_hdrsize)
        {
            return std::nullopt;
        }

        frame_header hdr{};

        // 版本号（1 字节）
        hdr.version = static_cast<std::uint8_t>(buffer[0]);
        if (hdr.version != protocol_version)
        {
            return std::nullopt;
        }

        // 帧类型（1 字节）
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

        // 标志位（2 字节大端序）
        hdr.flag = static_cast<flags>(
            static_cast<std::uint16_t>(buffer[2]) << 8 |
            static_cast<std::uint16_t>(buffer[3]));

        // 流 ID（4 字节大端序）
        hdr.stream_id =
            static_cast<std::uint32_t>(buffer[4]) << 24 |
            static_cast<std::uint32_t>(buffer[5]) << 16 |
            static_cast<std::uint32_t>(buffer[6]) << 8 |
            static_cast<std::uint32_t>(buffer[7]);

        // 载荷长度（4 字节大端序）
        hdr.length =
            static_cast<std::uint32_t>(buffer[8]) << 24 |
            static_cast<std::uint32_t>(buffer[9]) << 16 |
            static_cast<std::uint32_t>(buffer[10]) << 8 |
            static_cast<std::uint32_t>(buffer[11]);

        return hdr;
    }

    auto build_winupd(const flags f, const std::uint32_t stream_id, const std::uint32_t delta) noexcept
        -> std::array<std::byte, frame_hdrsize>
    {
        frame_header hdr{};
        hdr.type = message_type::window_update;
        hdr.flag = f;
        hdr.stream_id = stream_id;
        hdr.length = delta;
        return build_header(hdr);
    }

    auto build_ping(const flags f, const std::uint32_t ping_id) noexcept
        -> std::array<std::byte, frame_hdrsize>
    {
        frame_header hdr{};
        hdr.type = message_type::ping;
        hdr.flag = f;
        hdr.stream_id = 0;
        hdr.length = ping_id;
        return build_header(hdr);
    }

    auto build_goaway(const away_code code) noexcept
        -> std::array<std::byte, frame_hdrsize>
    {
        frame_header hdr{};
        hdr.type = message_type::go_away;
        hdr.flag = flags::none;
        hdr.stream_id = 0;
        hdr.length = static_cast<std::uint32_t>(code);
        return build_header(hdr);
    }

    auto build_data(const flags f, const std::uint32_t stream_id, const std::span<const std::byte> payload) noexcept
        -> data_frame
    {
        frame_header hdr{};
        hdr.type = message_type::data;
        hdr.flag = f;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint32_t>(payload.size());
        return {build_header(hdr), memory::vector<std::byte>(payload.begin(), payload.end())};
    }

    auto build_syn(const std::uint32_t stream_id, const std::span<const std::byte> payload) noexcept
        -> data_frame
    {
        return build_data(flags::syn, stream_id, payload);
    }

    auto build_fin(const std::uint32_t stream_id) noexcept
        -> std::array<std::byte, frame_hdrsize>
    {
        frame_header hdr{};
        hdr.type = message_type::data;
        hdr.flag = flags::fin;
        hdr.stream_id = stream_id;
        hdr.length = 0;
        return build_header(hdr);
    }

} // namespace psm::multiplex::yamux
