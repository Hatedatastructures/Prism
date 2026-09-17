/**
 * @file AnytlsWire.hpp
 * @brief AnyTLS sing-mux bootstrap and StreamRequest wire helpers.
 */
#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Net/Target.hpp>

#include <boost/asio/ip/address.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace Preview::Composition::AnytlsWire
{

    struct Bootstrap final
    {
        std::uint8_t Version{0};
        std::uint8_t Protocol{0};
        std::size_t Consumed{0};
    };

    struct StreamRequest final
    {
        Preview::Network::Target Target;
        std::uint16_t Flags{0};
        bool Udp{false};
        bool PacketAddress{false};
        std::size_t Consumed{0};
    };

    [[nodiscard]] inline auto ParseBootstrap(std::span<const std::byte> Data)
        -> std::expected<Bootstrap, Preview::Error>
    {
        if (Data.size() < 2U)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        Bootstrap Result;
        Result.Version = std::to_integer<std::uint8_t>(Data[0]);
        Result.Protocol = std::to_integer<std::uint8_t>(Data[1]);
        Result.Consumed = 2U;
        if (Result.Version == 0U)
        {
            return Result;
        }
        if (Data.size() < 3U)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        const auto PaddingEnabled = std::to_integer<std::uint8_t>(Data[2]);
        Result.Consumed = 3U;
        if (PaddingEnabled == 0U)
        {
            return Result;
        }
        if (Data.size() < 5U)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        const auto PaddingLength = static_cast<std::size_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[3])) << 8U) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[4])));
        if (Data.size() < 5U + PaddingLength)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        Result.Consumed = 5U + PaddingLength;
        return Result;
    }

    [[nodiscard]] inline auto ParseStreamRequest(std::span<const std::byte> Data)
        -> std::expected<StreamRequest, Preview::Error>
    {
        if (Data.size() < 3U)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        StreamRequest Result;
        Result.Flags = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[0])) << 8U) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[1])));
        Result.Udp = (Result.Flags & 0x0001U) != 0U;
        Result.PacketAddress = (Result.Flags & 0x0002U) != 0U;
        const auto Type = std::to_integer<std::uint8_t>(Data[2]);
        std::size_t Offset = 3U;
        std::string Host;
        if (Type == 1U)
        {
            if (Data.size() < Offset + 4U + 2U)
            {
                return std::unexpected(Preview::Error::NeedMore);
            }
            boost::asio::ip::address_v4::bytes_type Bytes{};
            for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
            {
                Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
            }
            Host = boost::asio::ip::address_v4(Bytes).to_string();
            Offset += 4U;
        }
        else if (Type == 4U)
        {
            if (Data.size() < Offset + 16U + 2U)
            {
                return std::unexpected(Preview::Error::NeedMore);
            }
            boost::asio::ip::address_v6::bytes_type Bytes{};
            for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
            {
                Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
            }
            Host = boost::asio::ip::address_v6(Bytes).to_string();
            Offset += 16U;
        }
        else if (Type == 3U)
        {
            if (Data.size() < Offset + 1U)
            {
                return std::unexpected(Preview::Error::NeedMore);
            }
            const auto Length = std::to_integer<std::uint8_t>(Data[Offset++]);
            if (Length == 0U)
            {
                return std::unexpected(Preview::Error::BadMessage);
            }
            if (Data.size() < Offset + Length + 2U)
            {
                return std::unexpected(Preview::Error::NeedMore);
            }
            Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
            Offset += Length;
        }
        else
        {
            return std::unexpected(Preview::Error::BadMessage);
        }
        if (Data.size() < Offset + 2U)
        {
            return std::unexpected(Preview::Error::NeedMore);
        }
        const auto Port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset])) << 8U) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset + 1U])));
        if (Port == 0U)
        {
            return std::unexpected(Preview::Error::BadAddress);
        }
        Offset += 2U;
        Result.Target.Host.assign(Host);
        Result.Target.Port.assign(std::to_string(Port));
        Result.Target.Positive = true;
        Result.Consumed = Offset;
        return Result;
    }

} // namespace Preview::Composition::AnytlsWire
