/** @file YamuxCodec.cpp @brief Yamux wire 帧编解码实现。 */
#include <Prism/Protocols/Mux/Yamux/Detail/Wire/Codec.hpp>

#include <cstring>
#include <limits>

namespace Prism::Mux::Yamux::Detail
{

    auto BuildHeader(const FrameHeader &Header) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        std::array<std::uint8_t, FrameHdrsize> Output{};
        Output[0] = Header.version;
        Output[1] = static_cast<std::uint8_t>(Header.Type);
        Output[2] = static_cast<std::uint8_t>(
            (static_cast<std::uint16_t>(Header.flag) >> 8) & 0xFF);
        Output[3] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(Header.flag) & 0xFF);
        Output[4] = static_cast<std::uint8_t>((Header.StreamId >> 24) & 0xFF);
        Output[5] = static_cast<std::uint8_t>((Header.StreamId >> 16) & 0xFF);
        Output[6] = static_cast<std::uint8_t>((Header.StreamId >> 8) & 0xFF);
        Output[7] = static_cast<std::uint8_t>(Header.StreamId & 0xFF);
        Output[8] = static_cast<std::uint8_t>((Header.length >> 24) & 0xFF);
        Output[9] = static_cast<std::uint8_t>((Header.length >> 16) & 0xFF);
        Output[10] = static_cast<std::uint8_t>((Header.length >> 8) & 0xFF);
        Output[11] = static_cast<std::uint8_t>(Header.length & 0xFF);
        return Output;
    }

    auto Build(
        const FrameHeader &Header,
        const std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        constexpr auto MaxUint32 = (std::numeric_limits<std::uint32_t>::max)();
        if (Payload.size() > MaxUint32)
        {
            return {};
        }
        auto HeaderCopy = Header;
        if (HeaderCopy.Type == MessageType::Data)
        {
            HeaderCopy.length = static_cast<std::uint32_t>(Payload.size());
        }
        const auto EncodedHeader = BuildHeader(HeaderCopy);
        std::vector<std::uint8_t> Output;
        Output.reserve(FrameHdrsize + Payload.size());
        Output.insert(Output.end(), EncodedHeader.begin(), EncodedHeader.end());
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    auto BuildWinupd(
        const Flags FlagsValue,
        const std::uint32_t StreamId,
        const std::uint32_t Delta) noexcept -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{
            .Type = MessageType::WindowUpdate,
            .flag = FlagsValue,
            .StreamId = StreamId,
            .length = Delta,
        };
        return BuildHeader(Header);
    }

    auto BuildWindowUpdate(const std::uint32_t StreamId, const std::uint32_t Delta)
        -> std::vector<std::uint8_t>
    {
        const auto Frame = BuildWinupd(Flags::None, StreamId, Delta);
        return {Frame.begin(), Frame.end()};
    }

    auto BuildPing(const Flags FlagsValue, const std::uint32_t PingId) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{
            .Type = MessageType::Ping,
            .flag = FlagsValue,
            .StreamId = 0,
            .length = PingId,
        };
        return BuildHeader(Header);
    }

    auto BuildGoaway(const AwayCode Code) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{
            .Type = MessageType::GoAway,
            .flag = Flags::None,
            .StreamId = 0,
            .length = static_cast<std::uint32_t>(Code),
        };
        return BuildHeader(Header);
    }

    auto BuildData(
        const Flags FlagsValue,
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Payload) noexcept
        -> std::vector<std::uint8_t>
    {
        const FrameHeader Header{
            .Type = MessageType::Data,
            .flag = FlagsValue,
            .StreamId = StreamId,
        };
        return Build(Header, Payload);
    }

    auto BuildSyn(
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Payload) noexcept
        -> std::vector<std::uint8_t>
    {
        return BuildData(Flags::Syn, StreamId, Payload);
    }

    auto BuildFin(const std::uint32_t StreamId) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader Header{
            .Type = MessageType::Data,
            .flag = Flags::Fin,
            .StreamId = StreamId,
        };
        return BuildHeader(Header);
    }

    auto ParseHeader(
        const std::span<const std::uint8_t> Data,
        FrameHeader &Output) noexcept -> Error
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
        Output.Type = static_cast<MessageType>(Data[1]);
        switch (Output.Type)
        {
        case MessageType::Data:
        case MessageType::WindowUpdate:
        case MessageType::Ping:
        case MessageType::GoAway:
            break;
        default:
            return Error::BadMessage;
        }
        Output.flag = static_cast<Flags>(static_cast<std::uint16_t>(Data[2]) << 8 |
                                         static_cast<std::uint16_t>(Data[3]));
        constexpr auto KnownFlags = static_cast<std::uint16_t>(Flags::Syn) |
                                    static_cast<std::uint16_t>(Flags::Ack) |
                                    static_cast<std::uint16_t>(Flags::Fin) |
                                    static_cast<std::uint16_t>(Flags::Rst);
        const auto RawFlags = static_cast<std::uint16_t>(Output.flag);
        if ((RawFlags & static_cast<std::uint16_t>(~KnownFlags)) != 0)
        {
            return Error::BadMessage;
        }
        const auto HasFin = HasFlag(Output.flag, Flags::Fin);
        const auto HasRst = HasFlag(Output.flag, Flags::Rst);
        const auto HasSyn = HasFlag(Output.flag, Flags::Syn);
        const auto HasAck = HasFlag(Output.flag, Flags::Ack);
        if (Output.Type == MessageType::Data &&
            ((HasFin && HasRst) || (HasSyn && (HasFin || HasRst)) ||
             (HasAck && (HasFin || HasRst))))
        {
            return Error::BadMessage;
        }
        Output.StreamId = static_cast<std::uint32_t>(Data[4]) << 24 |
                          static_cast<std::uint32_t>(Data[5]) << 16 |
                          static_cast<std::uint32_t>(Data[6]) << 8 |
                          static_cast<std::uint32_t>(Data[7]);
        Output.length = static_cast<std::uint32_t>(Data[8]) << 24 |
                        static_cast<std::uint32_t>(Data[9]) << 16 |
                        static_cast<std::uint32_t>(Data[10]) << 8 |
                        static_cast<std::uint32_t>(Data[11]);
        return Error::None;
    }

    auto ParsePayload(FrameHeader &, std::span<const std::uint8_t>) -> Error
    {
        return Error::None;
    }

} // namespace Prism::Mux::Yamux::Detail
