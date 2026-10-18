/** @file Target.hpp @brief AnyTLS PSH 目标解析，Consumed 保留同帧尾 payload。 */
#pragma once
#include <Prism/Foundation/Error.hpp>
#include <Prism/Net/Target.hpp>
#include <boost/asio/ip/address.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>

namespace Prism::Anytls::Detail
{
    struct TargetRequest final
    {
        Prism::Network::Target Target;
        std::size_t Consumed{0};
        bool NestedMux{false}, UnsupportedUdp{false};
    };

    [[nodiscard]] inline auto ParseTarget(std::span<const std::byte> Data)
        -> std::expected<TargetRequest, Error>
    {
        if (Data.empty()) return std::unexpected(Error::NeedMore);
        const auto Type = std::to_integer<std::uint8_t>(Data.front());
        std::size_t Offset = 1U;
        Prism::Network::Host Host;
        if (Type == 1U)
        {
            if (Data.size() < Offset + 4U + 2U)
                return std::unexpected(Error::NeedMore);
            boost::asio::ip::address_v4::bytes_type Bytes{};
            for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
                Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
            Host = Prism::Network::Host(Prism::Network::Ipv4Bytes{Bytes});
            Offset += 4U;
        }
        else if (Type == 4U)
        {
            if (Data.size() < Offset + 16U + 2U)
                return std::unexpected(Error::NeedMore);
            boost::asio::ip::address_v6::bytes_type Bytes{};
            for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
                Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
            Host = Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes});
            Offset += 16U;
        }
        else if (Type == 3U)
        {
            if (Data.size() < Offset + 1U)
                return std::unexpected(Error::NeedMore);
            const auto Length = std::to_integer<std::uint8_t>(Data[Offset++]);
            if (Length == 0U) return std::unexpected(Error::BadMessage);
            if (Data.size() < Offset + Length + 2U)
                return std::unexpected(Error::NeedMore);
            auto Domain = Prism::Network::DecodeHost(
                Prism::Network::HostEncoding::Domain,
                {reinterpret_cast<const char *>(Data.data() + Offset), Length});
            if (!Domain) return std::unexpected(Error::BadAddress);
            Host = Prism::Network::Host(std::move(*Domain));
            Offset += Length;
        }
        else
        {
            return std::unexpected(Error::BadMessage);
        }

        if (Data.size() < Offset + 2U)
            return std::unexpected(Error::NeedMore);
        const auto Port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset])) << 8U) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset + 1U])));
        if (Port == 0U) return std::unexpected(Error::BadAddress);
        Offset += 2U;
        Prism::Network::Target Target{
            std::move(Host), Port, Prism::Network::RouteKind::Forward};
        const auto *Domain = std::get_if<Prism::Network::DomainName>(&Target.Host.Get());
        const bool Nested = Domain && Domain->View() == "sp.mux.sing-box.arpa";
        const bool Udp = Domain && Domain->View() == "sp.v2.udp-over-tcp.arpa";
        return TargetRequest{std::move(Target), Offset, Nested, Udp};
    }
}
