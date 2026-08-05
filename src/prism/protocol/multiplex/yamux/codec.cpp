#include <prism/protocol/multiplex/yamux/codec.hpp>

#include <prism/protocol/multiplex/yamux/frame.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace psm::multiplex::yamux
{

    auto yamux_codec::header_size() const noexcept
        -> std::size_t
    {
        return frame_hdrsize;
    }


    auto yamux_codec::decode_header(const std::span<const std::byte> header)
        -> frame_meta
    {
        frame_meta meta;
        meta.raw_type = 0;

        const auto hdr_opt = parse_header(header);
        if (!hdr_opt)
        {
            return meta;
        }

        const auto &hdr = *hdr_opt;
        meta.stream_id = hdr.stream_id;
        meta.length = hdr.length;
        meta.flags = static_cast<std::uint16_t>(hdr.flag);
        meta.raw_type = static_cast<std::uint8_t>(hdr.type);

        switch (hdr.type)
        {
        case message_type::data:
            // Data 帧的 SYN/FIN/RST 标志由 control 层检查 meta.flags 分发
            meta.kind = frame_kind::data;
            break;
        case message_type::window_update:
        case message_type::ping:
        case message_type::go_away:
        default:
            meta.kind = frame_kind::control;
            break;
        }

        return meta;
    }


    auto yamux_codec::encode_data(const std::uint32_t stream_id,
                                  const std::span<const std::byte> payload)
        -> memory::vector<std::byte>
    {
        const auto frame = build_data(flags::none, stream_id, payload);
        memory::vector<std::byte> bytes(memory::current_resource());
        bytes.insert(bytes.end(), frame.header.begin(), frame.header.end());
        bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());
        return bytes;
    }


    auto yamux_codec::encode_fin(const std::uint32_t stream_id)
        -> memory::vector<std::byte>
    {
        const auto fin = build_fin(stream_id);
        memory::vector<std::byte> bytes(memory::current_resource());
        bytes.insert(bytes.end(), fin.begin(), fin.end());
        return bytes;
    }


    auto yamux_codec::type_name() const noexcept
        -> std::string_view
    {
        return "yamux";
    }

} // namespace psm::multiplex::yamux
