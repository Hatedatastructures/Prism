/**
 * @file GrpcFraming.hpp
 * @brief gRPC message envelope、gun tunnel envelope 和增量解码器。
 */
#pragma once

#include <Prism/Protocols/Gun/Codec.hpp>
#include <Prism/Protocols/Gun/GrpcEndpoint.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Gun::Grpc
{

    [[nodiscard]] auto EncodeMessage(std::span<const std::byte> Payload)
        -> std::vector<std::byte>;

    [[nodiscard]] auto EncodeTunMessage(std::span<const std::byte> Payload)
        -> std::vector<std::byte>;

    [[nodiscard]] auto DecodeTunMessage(std::span<const std::byte> Message)
        -> std::optional<std::vector<std::byte>>;

    class MessageDecoder final
    {
    public:
        explicit MessageDecoder(const std::size_t MaxMessageBytes = DefaultMaxMessageBytes)
            : MaxMessageBytes_(MaxMessageBytes)
        {
        }

        [[nodiscard]] auto Feed(std::span<const std::byte> Data,
            std::vector<std::vector<std::byte>>& Messages) -> bool;

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Buffer_.empty();
        }

    private:
        std::size_t MaxMessageBytes_;
        std::vector<std::byte> Buffer_;
    };

} // namespace Prism::Gun::Grpc
