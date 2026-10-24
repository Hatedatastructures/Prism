/**
 * @file CarrierPreparation.hpp
 * @brief Reality 服务端 carrier secret 的协议内准备接口。
 */
#pragma once

#include <Prism/Protocols/Reality/CarrierTypes.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Reality
{
    enum class CarrierPreparationError : std::uint8_t
    {
        MissingPrivateKey,
        InvalidPrivateKey,
        MissingShortIds,
        InvalidShortId,
    };

    struct CarrierPreparationRequest final
    {
        std::string_view PrivateKey;
        std::span<const std::string> ShortIds;
        std::span<const std::string> ServerNames;
    };

    [[nodiscard]] auto PrepareCarrier(CarrierPreparationRequest Request)
        -> std::expected<PreparedConfig, CarrierPreparationError>;
}
