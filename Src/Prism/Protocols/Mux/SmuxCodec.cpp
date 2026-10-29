/** @file SmuxCodec.cpp @brief Smux wire 帧编解码实现。 */
#include <Prism/Protocols/Mux/Smux/Wire/Codec.hpp>

#include <cstring>

namespace Prism::Mux::Smux::Detail
{

    auto Build(
        const FrameHeader &Header,
        const std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        Output.reserve(FrameHdrsize + Payload.size());
        Output.push_back(Header.version);
        Output.push_back(static_cast<std::uint8_t>(Header.cmd));
        Output.push_back(static_cast<std::uint8_t>(Header.length & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Header.length >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Header.StreamId & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Header.StreamId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Header.StreamId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Header.StreamId >> 24) & 0xFF));
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    auto BuildSyn(const std::uint32_t StreamId)
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{.cmd = Command::Syn, .StreamId = StreamId};
        const auto Frame = Build(Header);
        std::array<std::uint8_t, FrameHdrsize> Output{};
        std::memcpy(Output.data(), Frame.data(), FrameHdrsize);
        return Output;
    }

    auto BuildFin(const std::uint32_t StreamId)
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{.cmd = Command::Fin, .StreamId = StreamId};
        const auto Frame = Build(Header);
        std::array<std::uint8_t, FrameHdrsize> Output{};
        std::memcpy(Output.data(), Frame.data(), FrameHdrsize);
        return Output;
    }

    auto BuildPush(
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        if (Payload.size() > MaxFrameLength)
        {
            return {};
        }
        const FrameHeader Header{
            .cmd = Command::Push,
            .length = static_cast<std::uint16_t>(Payload.size()),
            .StreamId = StreamId,
        };
        return Build(Header, Payload);
    }

    auto ParseHeader(
        const std::span<const std::uint8_t> Data,
        FrameHeader &Output) -> Error
    {
        if (Data.size() < FrameHdrsize)
        {
            return Error::NeedMore;
        }
        Output.version = Data[0];
        if (Output.version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        Output.cmd = static_cast<Command>(Data[1]);
        switch (Output.cmd)
        {
        case Command::Syn:
        case Command::Fin:
        case Command::Push:
        case Command::Nop:
            break;
        default:
            return Error::BadMessage;
        }
        Output.length = static_cast<std::uint16_t>(Data[2]) |
                        static_cast<std::uint16_t>(Data[3]) << 8;
        if (Output.length > MaxFrameLength)
        {
            return Error::BadLength;
        }
        Output.StreamId = static_cast<std::uint32_t>(Data[4]) |
                          static_cast<std::uint32_t>(Data[5]) << 8 |
                          static_cast<std::uint32_t>(Data[6]) << 16 |
                          static_cast<std::uint32_t>(Data[7]) << 24;
        return Error::None;
    }

    auto ParsePayload(
        FrameHeader &Frame,
        const std::span<const std::uint8_t> Data) -> Error
    {
        if (Data.size() < Frame.length)
        {
            return Error::NeedMore;
        }
        if (Data.size() > Frame.length)
        {
            return Error::BadLength;
        }
        return Error::None;
    }

} // namespace Prism::Mux::Smux::Detail
