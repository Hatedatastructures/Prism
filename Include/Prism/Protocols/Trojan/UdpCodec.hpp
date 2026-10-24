/**
 * @file UdpCodec.hpp
 * @brief Trojan UDP datagram framing
 * @details 只拥有目标地址、长度字段和 CRLF 分隔符组成的 UDP 帧。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

namespace Prism::Trojan
{

    /**
     * @brief 构造 Trojan UDP 帧并写入复用缓冲
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @param Output 输出缓冲
     * @details 帧格式为 [ATYP][ADDR][PORT 2B][LEN 2B BE][CRLF][payload]。
     */
    template <typename Alloc>
    inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (Payload.size() > 0xFFFF)
        {
            return;
        }
        Output.reserve(Target.Host.size() + 12 + Payload.size());
        if (!EncodeAddress(Target, Output))
        {
            Output.clear();
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((Payload.size() >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFF));
        Output.push_back('\r');
        Output.push_back('\n');
        Output.insert(Output.end(), Payload.begin(), Payload.end());
    }

    /**
     * @brief 构造 Trojan UDP 帧
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @return UDP 帧字节；非法地址或过长载荷返回空缓冲
     */
    [[nodiscard]] auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析 Trojan UDP 帧
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param Payload 输出载荷视图（指向 Data）
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] auto ParseUdpPkt(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error;

} // namespace Prism::Trojan
