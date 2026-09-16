/**
 * @file Carrier.hpp
 * @brief Reality 的 Preview carrier 边界。
 * @details Reality carrier 的配置与 Facade 入口。无参数入口继续保留为
 *          unavailable；显式配置入口用于承载真实 wire 握手实现。
 */
#pragma once

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Reality/Types.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Reality
{

    /// Reality server carrier 的最小运行时配置。
    struct CarrierOptions final
    {
        std::array<std::uint8_t, KeyLen> ServerPrivateKey{};
        std::vector<std::array<std::uint8_t, MaxShortIdLen>> ShortIds;
        std::vector<std::string> SniAllowlist;
    };

    inline constexpr std::string_view WireBlocker =
        "Reality carrier requires a complete TLS 1.3 wire engine and ClientHello mutation";

    [[nodiscard]] inline auto MakeFacadeCarrier()
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Composition::Carrier::FacadeCarrier::Unavailable(
            Preview::Composition::Carrier::CarrierKind::Reality, std::string(WireBlocker));
    }

    /**
     * @brief 创建显式配置的 Reality carrier。
     * @param Options 服务端静态密钥、ShortId 和 SNI 白名单
     * @return 已注册 Reality handler 的 Facade
     * @note wire 状态机在后续实现中由该入口承载；配置入口本身必须可见。
     */
    [[nodiscard]] inline auto MakeFacadeCarrier(CarrierOptions Options)
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        (void)Options;
        return Preview::Composition::Carrier::FacadeCarrier::Ready(
            Preview::Composition::Carrier::CarrierKind::Reality,
            [](Preview::Composition::Carrier::CarrierAcceptRequest Request)
                -> Preview::Composition::Carrier::Net::awaitable<
                    Preview::Composition::Carrier::CarrierAcceptResult>
            {
                auto Failure = Preview::Composition::Carrier::MapError(
                    Preview::Error::NotSupported,
                    Preview::Composition::Carrier::HandshakeStage::Preparing,
                    std::string(WireBlocker));
                co_return Preview::Composition::Carrier::CarrierAcceptResult::Rejected(
                    std::move(Failure), std::move(Request.Transport), Request.Replay,
                    std::move(Request.State));
            });
    }

} // namespace Preview::Reality
