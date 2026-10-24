/**
 * @file Codec.hpp
 * @brief AnyTLS sing-mux 的 bootstrap 与 StreamRequest wire 解析辅助。
 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Net/Target.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace Prism::Mux::Detail::SingMux
{

    struct Bootstrap final
    {
        std::uint8_t Version{0};
        std::uint8_t Protocol{0};
        std::size_t Consumed{0};
    };

    struct StreamRequest final
    {
        Prism::Network::Target Target;
        std::uint16_t Flags{0};
        bool Udp{false};
        bool PacketAddress{false};
        std::size_t Consumed{0};
    };

    [[nodiscard]] auto ParseBootstrap(std::span<const std::byte> Data)
        -> std::expected<Bootstrap, Prism::Error>;

    [[nodiscard]] auto ParseStreamRequest(std::span<const std::byte> Data)
        -> std::expected<StreamRequest, Prism::Error>;

} // namespace Prism::Mux::Detail::SingMux
