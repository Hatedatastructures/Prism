/**
 * @file Frame.cpp
 * @brief HTTP/2 帧载荷编解码实现
 */

#include <Prism/Protocols/Http2/Detail/Frame.hpp>

namespace Prism::Http2::Detail
{
    auto EncodeLen24(const std::uint32_t Length, const std::span<std::byte, 3> Output) noexcept -> void
    {
        Output[0] = static_cast<std::byte>((Length >> 16) & 0xFF);
        Output[1] = static_cast<std::byte>((Length >> 8) & 0xFF);
        Output[2] = static_cast<std::byte>(Length & 0xFF);
    }

    auto DecodeLen24(const std::span<const std::byte, 3> Input) noexcept -> std::uint32_t
    {
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[0])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[1])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[2]));
    }

    auto EncodeU31(const std::uint32_t Value, const std::span<std::byte, 4> Output) noexcept -> void
    {
        Output[0] = static_cast<std::byte>((Value >> 24) & 0x7F);
        Output[1] = static_cast<std::byte>((Value >> 16) & 0xFF);
        Output[2] = static_cast<std::byte>((Value >> 8) & 0xFF);
        Output[3] = static_cast<std::byte>(Value & 0xFF);
    }

    auto EncodeU32(const std::uint32_t ErrorCode, const std::span<std::byte, 4> Output) noexcept -> void
    {
        Output[0] = static_cast<std::byte>((ErrorCode >> 24) & 0xFF);
        Output[1] = static_cast<std::byte>((ErrorCode >> 16) & 0xFF);
        Output[2] = static_cast<std::byte>((ErrorCode >> 8) & 0xFF);
        Output[3] = static_cast<std::byte>(ErrorCode & 0xFF);
    }

    auto DecodeU31(const std::span<const std::byte> Input) noexcept -> std::uint32_t
    {
        if (Input.size() < 4)
        {
            return 0;
        }
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[0]) & 0x7F) << 24) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[1])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[2])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[3]));
    }

    auto DecodeU32(const std::span<const std::byte> Input) noexcept -> std::uint32_t
    {
        if (Input.size() < 4)
        {
            return 0;
        }
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[0])) << 24) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[1])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[2])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Input[3]));
    }

    auto BuildFrame(const FrameParameters &Params) -> std::vector<std::byte>
    {
        if (Params.Payload.size() > 0xFFFFFFU)
        {
            return {};
        }
        std::vector<std::byte> Frame;
        Frame.reserve(FrameHeaderSize + Params.Payload.size());
        Frame.resize(FrameHeaderSize);
        const auto Header = std::span<std::byte>(Frame.data(), FrameHeaderSize);
        EncodeLen24(static_cast<std::uint32_t>(Params.Payload.size()), Header.first<3>());
        Header[3] = static_cast<std::byte>(Params.Type);
        Header[4] = static_cast<std::byte>(Params.Flags);
        EncodeU31(Params.StreamId, Header.last<4>());
        Frame.insert(Frame.end(), Params.Payload.begin(), Params.Payload.end());
        return Frame;
    }

    auto ParseFrameHeader(const std::span<const std::byte> Data) -> std::optional<FrameHeader>
    {
        if (Data.size() < FrameHeaderSize)
        {
            return std::nullopt;
        }
        FrameHeader Header;
        const auto Head = Data.first<9>();
        Header.Length = DecodeLen24(Head.first<3>());
        Header.Type = static_cast<FrameType>(std::to_integer<std::uint8_t>(Head[3]));
        Header.Flags = std::to_integer<std::uint8_t>(Head[4]);
        Header.StreamId = DecodeU31(Head.last<4>());
        return Header;
    }

    auto EncodeSettings(const std::span<const SettingsEntry> Entries) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(Entries.size() * 6);
        for (const auto &Entry : Entries)
        {
            Output.push_back(static_cast<std::byte>((Entry.Id >> 8) & 0xFF));
            Output.push_back(static_cast<std::byte>(Entry.Id & 0xFF));
            Output.push_back(static_cast<std::byte>((Entry.Value >> 24) & 0xFF));
            Output.push_back(static_cast<std::byte>((Entry.Value >> 16) & 0xFF));
            Output.push_back(static_cast<std::byte>((Entry.Value >> 8) & 0xFF));
            Output.push_back(static_cast<std::byte>(Entry.Value & 0xFF));
        }
        return Output;
    }

    auto DecodeSettings(const std::span<const std::byte> Data)
        -> std::optional<std::vector<SettingsEntry>>
    {
        if (Data.size() % 6 != 0)
        {
            return std::nullopt;
        }
        std::vector<SettingsEntry> Entries;
        Entries.reserve(Data.size() / 6);
        for (std::size_t I = 0; I < Data.size(); I += 6)
        {
            SettingsEntry Entry;
            Entry.Id = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[I])) << 8) |
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[I + 1])));
            Entry.Value = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 2])) << 24) |
                          (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 3])) << 16) |
                          (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 4])) << 8) |
                          static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 5]));
            Entries.push_back(Entry);
        }
        return Entries;
    }

    auto EncodeWindowUpdate(const std::uint32_t Increment) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> Output{};
        EncodeU31(Increment, Output);
        return Output;
    }

    auto EncodeRstStream(const std::uint32_t ErrorCode) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> Output{};
        EncodeU32(ErrorCode, Output);
        return Output;
    }

    auto EncodeGoaway(const GoawayParams &Params) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(8 + Params.Debug.size());
        Output.resize(8);
        const auto Head = std::span<std::byte>(Output.data(), 8);
        EncodeU31(Params.LastStreamId, Head.first<4>());
        EncodeU31(Params.ErrorCode, Head.last<4>());
        Output.insert(Output.end(), Params.Debug.begin(), Params.Debug.end());
        return Output;
    }
} // namespace Prism::Http2::Detail
