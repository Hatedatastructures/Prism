#include <prism/protocol/multiplex/smux/codec.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace psm::multiplex::smux
{

    auto smux_codec::header_size() const noexcept -> std::size_t
    {
        return frame_hdrsize;
    }

    auto smux_codec::decode_header(const std::span<const std::byte> header) -> frame_meta
    {
        frame_meta meta;
        meta.raw_type = 0;

        const auto hdr_opt = deserialization(header);
        if (!hdr_opt)
        {
            return meta;
        }

        const auto &hdr = *hdr_opt;
        meta.stream_id = hdr.stream_id;
        meta.length = hdr.length;
        meta.raw_type = static_cast<std::uint8_t>(hdr.cmd);

        switch (hdr.cmd)
        {
        case command::syn: meta.kind = frame_kind::syn; break;
        case command::fin: meta.kind = frame_kind::fin; break;
        case command::push: meta.kind = frame_kind::data; break;
        case command::nop:
        default: meta.kind = frame_kind::control; break;
        }

        return meta;
    }

    auto smux_codec::encode_data(const std::uint32_t stream_id, const std::span<const std::byte> payload)
        -> memory::vector<std::byte>
    {
        return make_data_frame(stream_id, payload);
    }

    auto smux_codec::encode_fin(const std::uint32_t stream_id) -> memory::vector<std::byte>
    {
        const auto fin = make_fin(stream_id);
        memory::vector<std::byte> bytes(memory::current_resource());
        bytes.insert(bytes.end(), fin.begin(), fin.end());
        return bytes;
    }

    auto smux_codec::type_name() const noexcept -> std::string_view
    {
        return "smux";
    }

} // namespace psm::multiplex::smux
