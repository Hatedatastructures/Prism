/**
 * @file Framing.cpp
 * @brief Common 地址与端口帧载荷解析实现。
 */

#include <Prism/Protocols/Common/Framing.hpp>

#include <cstring>

namespace Prism::Protocol::Common::Framing
{
    [[nodiscard]] auto ParseIpv4(const std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv4Address>
    {
        if (Buffer.size() < 4)
        {
            return {Fault::Code::BadMessage, {}};
        }
        Ipv4Address AddressValue{};
        std::memcpy(AddressValue.Bytes.data(), Buffer.data(), 4);
        return {Fault::Code::Success, AddressValue};
    }

    [[nodiscard]] auto ParseIpv6(const std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv6Address>
    {
        if (Buffer.size() < 16)
        {
            return {Fault::Code::BadMessage, {}};
        }
        Ipv6Address AddressValue{};
        std::memcpy(AddressValue.Bytes.data(), Buffer.data(), 16);
        return {Fault::Code::Success, AddressValue};
    }

    [[nodiscard]] auto ParseDomain(const std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, DomainAddress>
    {
        if (Buffer.empty())
        {
            return {Fault::Code::BadMessage, {}};
        }
        const std::uint8_t Len = Buffer[0];
        if (Buffer.size() < static_cast<std::size_t>(1 + Len))
        {
            return {Fault::Code::BadMessage, {}};
        }
        DomainAddress AddressValue{};
        if (Len > AddressValue.value.size())
        {
            return {Fault::Code::BadMessage, {}};
        }
        AddressValue.length = Len;
        std::memcpy(AddressValue.value.data(), Buffer.data() + 1, Len);
        return {Fault::Code::Success, AddressValue};
    }

    [[nodiscard]] auto ParsePort(const std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, std::uint16_t>
    {
        if (Buffer.size() < 2)
        {
            return {Fault::Code::BadMessage, 0};
        }
        const auto Port = static_cast<std::uint16_t>(Buffer[0]) << 8 |
                          static_cast<std::uint16_t>(Buffer[1]);
        return {Fault::Code::Success, Port};
    }
} // namespace Prism::Protocol::Common::Framing
