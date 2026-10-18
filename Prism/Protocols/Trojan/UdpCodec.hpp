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
    [[nodiscard]] inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpPkt(Target, Payload, Output);
        return Output;
    }

    /**
     * @brief 解析 Trojan UDP 帧
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param Payload 输出载荷视图（指向 Data）
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] inline auto ParseUdpPkt(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        std::size_t AddressConsumed = 0;
        const auto AddressError = ParseAddress(Data, Target, AddressConsumed);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        if (Data.size() - AddressConsumed < 4)
        {
            return Error::NeedMore;
        }
        const auto Length = static_cast<std::size_t>(Data[AddressConsumed]) << 8 |
                            Data[AddressConsumed + 1];
        if (Data[AddressConsumed + 2] != '\r' || Data[AddressConsumed + 3] != '\n')
        {
            return Error::BadMagic;
        }
        const auto PayloadStart = AddressConsumed + 4;
        if (Data.size() - PayloadStart < Length)
        {
            return Error::NeedMore;
        }
        Payload = Data.subspan(PayloadStart, Length);
        return Error::None;
    }

} // namespace Prism::Trojan
