/**
 * @file UdpCodec.hpp
 * @brief VLESS 普通 UDP 唯一长度分帧。
 * @details 唯一 wire 为 [uint16BE payload length][payload]；目标只来自 UDP 握手。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <vector>

namespace Prism::Vless
{
    /** @brief 保留 typed/native 首因及当前 frame 中真实传输进度。 */
    struct UdpFailure final
    {
        Prism::Fault::Failure Cause;
        std::size_t Transferred{0};
    };

    using UdpResult = std::expected<void, UdpFailure>;

    /** @brief 编码一条普通 VLESS UDP 数据报；空载荷是合法数据报。 */
    template <typename Alloc>
    [[nodiscard]] inline auto BuildUdpPkt(
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> UdpResult
    {
        if (Payload.size() > std::numeric_limits<std::uint16_t>::max())
        {
            return std::unexpected(UdpFailure{
                {Prism::Fault::Code::OversizedMsg}, 0});
        }

        Output.clear();
        Output.reserve(Payload.size() + 2U);
        const auto Length = static_cast<std::uint16_t>(Payload.size());
        Output.push_back(static_cast<std::uint8_t>(Length >> 8U));
        Output.push_back(static_cast<std::uint8_t>(Length & 0xFFU));
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return {};
    }

    /** @brief 校验完整长度帧并返回其 payload 视图。 */
    [[nodiscard]] auto ParseUdpPkt(
        const std::span<const std::uint8_t> Frame,
        std::span<const std::uint8_t> &Payload) -> UdpResult;
} // namespace Prism::Vless
