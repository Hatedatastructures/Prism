/** @file Wire.hpp @brief DNS 传输 wire frame 的私有界限与构造声明。 */
#pragma once

#include <Prism/Net/Dns/Transport.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Prism::Network::Dns::Detail
{
    inline constexpr std::size_t MaxFrameBytes = 65535;
    inline constexpr std::size_t MaxUdpResponseBytes = 4096;

    /** @brief 将 DNS wire 封装为两字节大端长度帧；超长输入返回 message_size。 */
    [[nodiscard]] auto MakeTcpFrame(std::span<const std::uint8_t> Wire)
        -> EcResult<std::vector<std::uint8_t>>;
}
