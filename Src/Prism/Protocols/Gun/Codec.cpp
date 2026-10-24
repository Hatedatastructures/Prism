/**
 * @file Codec.cpp
 * @brief gRPC tunnel frame varint 编解码实现。
 */
#include <Prism/Protocols/Gun/Codec.hpp>

#include <array>
#include <limits>
#include <vector>

namespace Prism::Gun
{

    auto EncodeVarint(
        const std::uint32_t Value,
        const std::span<std::uint8_t> Output) -> std::size_t
    {
        std::uint32_t Probe = Value;
        std::size_t Required = 1;
        while (Probe >= 0x80)
        {
            ++Required;
            Probe >>= 7;
        }
        if (Required > Output.size())
        {
            return 0;
        }

        std::uint32_t Remaining = Value;
        std::size_t Written = 0;
        while (Remaining >= 0x80)
        {
            Output[Written++] = static_cast<std::uint8_t>((Remaining & 0x7F) | 0x80);
            Remaining >>= 7;
        }
        Output[Written++] = static_cast<std::uint8_t>(Remaining);
        return Written;
    }

    auto DecodeVarint(
        const std::span<const std::uint8_t> Input,
        std::uint32_t &Value) -> std::size_t
    {
        Value = 0;
        std::uint32_t V = 0;
        for (std::size_t I = 0; I < Input.size() && I < MaxVarintLen; ++I)
        {
            const auto Byte = Input[I];
            const auto Chunk = static_cast<std::uint32_t>(Byte & 0x7F);
            if (I == MaxVarintLen - 1 &&
                (Chunk > 0x0F || (Byte & 0x80) != 0))
            {
                return 0;
            }
            V |= Chunk << (7 * I);
            if ((Byte & 0x80) == 0)
            {
                Value = V;
                return I + 1;
            }
        }
        return 0;
    }

    auto EncodeFrame(const std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        if (Payload.size() > MaxPayloadLen ||
            Payload.size() > (std::numeric_limits<std::uint32_t>::max)())
        {
            return {};
        }
        std::array<std::uint8_t, MaxVarintLen> VarintBuf{};
        const auto VarintLen = EncodeVarint(static_cast<std::uint32_t>(Payload.size()), VarintBuf);
        if (VarintLen == 0)
        {
            return {};
        }
        const auto TotalSize = std::size_t{1} + VarintLen + Payload.size();
        if (TotalSize > (std::numeric_limits<std::uint32_t>::max)())
        {
            return {};
        }
        const auto Total = static_cast<std::uint32_t>(TotalSize);
        std::vector<std::uint8_t> Output;
        Output.reserve(HeaderFixedLen + VarintLen + Payload.size());
        Output.push_back(0x00);
        Output.push_back(static_cast<std::uint8_t>((Total >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Total >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Total >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Total & 0xFF));
        Output.push_back(0x0A);
        Output.insert(Output.end(), VarintBuf.begin(), VarintBuf.begin() + VarintLen);
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    auto ParseFrameHeader(
        const std::span<const std::uint8_t> Input,
        FrameHeader &Header) -> bool
    {
        Header = {};
        if (Input.size() < HeaderFixedLen + 1)
        {
            return false;
        }
        if (Input[0] != 0x00 || Input[5] != 0x0A)
        {
            return false;
        }
        const auto Total = static_cast<std::uint32_t>(Input[1]) << 24 |
                           static_cast<std::uint32_t>(Input[2]) << 16 |
                           static_cast<std::uint32_t>(Input[3]) << 8 |
                           static_cast<std::uint32_t>(Input[4]);
        std::uint32_t PayloadLength = 0;
        const auto VarintLength = DecodeVarint(
            Input.subspan(HeaderFixedLen), PayloadLength);
        if (VarintLength == 0 || PayloadLength > MaxPayloadLen)
        {
            return false;
        }
        const auto ExpectedTotal = std::size_t{1} + VarintLength + PayloadLength;
        if (ExpectedTotal > (std::numeric_limits<std::uint32_t>::max)() ||
            Total != ExpectedTotal)
        {
            return false;
        }
        Header.PayloadLen = PayloadLength;
        Header.HeaderLen = HeaderFixedLen + VarintLength;
        return true;
    }

} // namespace Prism::Gun
