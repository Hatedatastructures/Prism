/**
 * @file GrpcFraming.hpp
 * @brief gRPC message envelope、gun tunnel envelope 和增量解码器。
 */
#pragma once

#include <Prism/Protocols/Gun/Codec.hpp>
#include <Prism/Protocols/Gun/GrpcTypes.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Gun::Grpc
{

    [[nodiscard]] inline auto EncodeMessage(std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        if (Payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()))
        {
            return {};
        }
        std::vector<std::byte> Output(5U + Payload.size());
        Output[0] = std::byte{0};
        const auto Length = static_cast<std::uint32_t>(Payload.size());
        Output[1] = static_cast<std::byte>((Length >> 24U) & 0xFFU);
        Output[2] = static_cast<std::byte>((Length >> 16U) & 0xFFU);
        Output[3] = static_cast<std::byte>((Length >> 8U) & 0xFFU);
        Output[4] = static_cast<std::byte>(Length & 0xFFU);
        std::copy(Payload.begin(), Payload.end(), Output.begin() + 5);
        return Output;
    }

    [[nodiscard]] inline auto EncodeTunMessage(std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        if (Payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()))
        {
            return {};
        }
        std::array<std::uint8_t, Prism::Gun::MaxVarintLen> Varint{};
        const auto Length = Prism::Gun::EncodeVarint(static_cast<std::uint32_t>(Payload.size()), Varint);
        if (Length == 0U)
        {
            return {};
        }
        std::vector<std::byte> Output;
        Output.reserve(1U + Length + Payload.size());
        Output.push_back(std::byte{0x0A});
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            Output.push_back(static_cast<std::byte>(Varint[Index]));
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    [[nodiscard]] inline auto DecodeTunMessage(std::span<const std::byte> Message)
        -> std::optional<std::vector<std::byte>>
    {
        if (Message.size() < 2U || Message.front() != std::byte{0x0A})
        {
            return std::nullopt;
        }
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(Message.data() + 1), Message.size() - 1U);
        std::uint32_t Length = 0;
        const auto VarintLength = Prism::Gun::DecodeVarint(Bytes, Length);
        if (VarintLength == 0U || static_cast<std::size_t>(Length) != Message.size() - 1U - VarintLength)
        {
            return std::nullopt;
        }
        return std::vector<std::byte>(Message.begin() + static_cast<std::ptrdiff_t>(1U + VarintLength),
            Message.end());
    }

    class MessageDecoder final
    {
    public:
        explicit MessageDecoder(const std::size_t MaxMessageBytes = DefaultMaxMessageBytes)
            : MaxMessageBytes_(MaxMessageBytes)
        {
        }

        [[nodiscard]] auto Feed(std::span<const std::byte> Data,
            std::vector<std::vector<std::byte>>& Messages) -> bool
        {
            Buffer_.insert(Buffer_.end(), Data.begin(), Data.end());
            while (Buffer_.size() >= 5U)
            {
                if (Buffer_[0] != std::byte{0})
                {
                    return false;
                }
                const auto Length =
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[1])) << 24U) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[2])) << 16U) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[3])) << 8U) |
                    static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[4]));
                if (Length > MaxMessageBytes_)
                {
                    return false;
                }
                const auto Total = 5U + static_cast<std::size_t>(Length);
                if (Buffer_.size() < Total)
                {
                    break;
                }
                Messages.emplace_back(Buffer_.begin() + 5,
                    Buffer_.begin() + static_cast<std::ptrdiff_t>(Total));
                Buffer_.erase(Buffer_.begin(), Buffer_.begin() + static_cast<std::ptrdiff_t>(Total));
            }
            return true;
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Buffer_.empty();
        }

    private:
        std::size_t MaxMessageBytes_;
        std::vector<std::byte> Buffer_;
    };

} // namespace Prism::Gun::Grpc
