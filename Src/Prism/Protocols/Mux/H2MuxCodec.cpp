/** @file H2MuxCodec.cpp @brief H2Mux wire 帧编解码实现。 */
#include <Prism/Protocols/Mux/H2Mux/Codec.hpp>

#include <cstring>

namespace Prism::Mux::H2Mux
{

    auto Build(
        const FrameType Type,
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        if (Payload.size() > MaxFrameLength)
        {
            return {};
        }
        std::vector<std::uint8_t> Output;
        Output.reserve(FrameHdrsize + Payload.size());
        Output.push_back(static_cast<std::uint8_t>(Type));
        Output.push_back(static_cast<std::uint8_t>((Payload.size() >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Payload.size() >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Payload.size() >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((StreamId >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((StreamId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((StreamId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(StreamId & 0xFF));
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    auto BuildData(
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        return Build(FrameType::Data, StreamId, Payload);
    }

    auto BuildWinupd(const std::uint32_t StreamId, const std::uint32_t Delta)
        -> std::array<std::uint8_t, FrameHdrsize + sizeof(std::uint32_t)>
    {
        std::array<std::uint8_t, FrameHdrsize + sizeof(std::uint32_t)> Output{};
        Output[0] = static_cast<std::uint8_t>(FrameType::WindowUpdate);
        Output[1] = 0;
        Output[2] = 0;
        Output[3] = 0;
        Output[4] = static_cast<std::uint8_t>(sizeof(std::uint32_t));
        Output[5] = static_cast<std::uint8_t>((StreamId >> 24) & 0xFF);
        Output[6] = static_cast<std::uint8_t>((StreamId >> 16) & 0xFF);
        Output[7] = static_cast<std::uint8_t>((StreamId >> 8) & 0xFF);
        Output[8] = static_cast<std::uint8_t>(StreamId & 0xFF);
        Output[9] = static_cast<std::uint8_t>((Delta >> 24) & 0xFF);
        Output[10] = static_cast<std::uint8_t>((Delta >> 16) & 0xFF);
        Output[11] = static_cast<std::uint8_t>((Delta >> 8) & 0xFF);
        Output[12] = static_cast<std::uint8_t>(Delta & 0xFF);
        return Output;
    }

    auto BuildPing(const std::uint32_t PingId) -> std::vector<std::uint8_t>
    {
        const auto Payload = std::array<std::uint8_t, 4>{
            static_cast<std::uint8_t>((PingId >> 24) & 0xFF),
            static_cast<std::uint8_t>((PingId >> 16) & 0xFF),
            static_cast<std::uint8_t>((PingId >> 8) & 0xFF),
            static_cast<std::uint8_t>(PingId & 0xFF),
        };
        return Build(FrameType::Ping, 0, Payload);
    }

    auto BuildClose(const std::uint32_t StreamId)
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const auto Frame = Build(FrameType::Close, StreamId);
        std::array<std::uint8_t, FrameHdrsize> Output{};
        std::memcpy(Output.data(), Frame.data(), FrameHdrsize);
        return Output;
    }

    auto ParseHeader(
        const std::span<const std::uint8_t> Data,
        FrameHeader &Output) -> Error
    {
        if (Data.size() < FrameHdrsize)
        {
            return Error::NeedMore;
        }
        const auto RawType = Data[0];
        if (RawType > static_cast<std::uint8_t>(FrameType::Close))
        {
            return Error::BadMessage;
        }
        Output.Type = static_cast<FrameType>(RawType);
        Output.length = static_cast<std::uint32_t>(Data[1]) << 24 |
                        static_cast<std::uint32_t>(Data[2]) << 16 |
                        static_cast<std::uint32_t>(Data[3]) << 8 |
                        static_cast<std::uint32_t>(Data[4]);
        if (Output.length > MaxFrameLength)
        {
            return Error::BadLength;
        }
        Output.StreamId = static_cast<std::uint32_t>(Data[5]) << 24 |
                          static_cast<std::uint32_t>(Data[6]) << 16 |
                          static_cast<std::uint32_t>(Data[7]) << 8 |
                          static_cast<std::uint32_t>(Data[8]);
        switch (Output.Type)
        {
        case FrameType::Data:
            break;
        case FrameType::WindowUpdate:
        case FrameType::Ping:
            if (Output.length != sizeof(std::uint32_t))
            {
                return Error::BadLength;
            }
            break;
        case FrameType::Close:
            if (Output.length != 0)
            {
                return Error::BadLength;
            }
            break;
        default:
            return Error::BadMessage;
        }
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

} // namespace Prism::Mux::H2Mux
