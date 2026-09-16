/**
 * @file Carrier.hpp
 * @brief ShadowTLS 的 Preview carrier 边界。
 * @details 无配置入口显式拒绝 carrier；配置了目标拨号器后，入口委托
 *          ServerSession 完成真实的 ClientHello 转发、ServerHello 识别、首帧认证
 *          与 record 状态接管。
 */
#pragma once

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Shadowtls/Server.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace Preview::Shadowtls
{

    inline constexpr std::string_view WireBlocker =
        "ShadowTLS carrier requires ServerOptions::DialTarget for a complete TLS relay";

    [[nodiscard]] inline auto MakeFacadeCarrier()
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Composition::Carrier::FacadeCarrier::Unavailable(
            Preview::Composition::Carrier::CarrierKind::Shadowtls, std::string(WireBlocker));
    }

    /**
     * @brief 创建配置完成的 ShadowTLS 服务端 carrier。
     * @param Options 目标 TLS 服务拨号配置
     * @param Config ShadowTLS 服务端认证配置
     * @return 已绑定 relay session 的 carrier facade
     * @details 只有真实 relay 配置存在时才报告 WireReady；成功结果要求
     *          ServerSession 已完成首个客户端 application-data 的认证和 record 接管。
     */
    [[nodiscard]] inline auto MakeFacadeCarrier(ServerOptions Options, ServerConfig Config)
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        namespace Carrier = Preview::Composition::Carrier;
        if (!Options.DialTarget)
        {
            return Carrier::FacadeCarrier::Unavailable(Carrier::CarrierKind::Shadowtls,
                                                        std::string(WireBlocker));
        }

        auto Session = std::make_shared<ServerSession>(std::move(Options));
        return Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Shadowtls,
            [Session, Config = std::move(Config)](Carrier::CarrierAcceptRequest Request)
                -> Net::awaitable<Carrier::CarrierAcceptResult>
            {
                auto ServerResult = co_await Session->Run(std::move(Request.Transport), Config);
                if (ServerResult.Status != Preview::Error::None || !ServerResult.Connection)
                {
                    const auto Detail = ServerResult.Status == Preview::Error::None
                                            ? std::string{"ShadowTLS relay returned no connection"}
                                            : std::string{"ShadowTLS relay failed: "} +
                                                  Preview::make_error_code(ServerResult.Status).message();
                    auto Failure = Carrier::MapError(ServerResult.Status,
                                                      Carrier::HandshakeStage::Preparing,
                                                      Detail);
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        std::move(Failure), {}, std::move(Request.Replay), std::move(Request.State));
                }

                Preview::SharedTransmission Transport = std::move(ServerResult.Connection);
                auto Metadata = Carrier::CarrierMetadata{
                    .Kind = Carrier::CarrierKind::Shadowtls,
                    .WireComplete = true,
                    .ReplayBytes = Request.Replay.Size(),
                    .Detail = "ShadowTLS v3 server relay completed authenticated wire handoff"};
                co_return Carrier::CarrierAcceptResult::Accepted(
                    std::move(Transport), std::move(Request.Replay), std::move(Metadata),
                    std::move(Request.State));
            });
    }

} // namespace Preview::Shadowtls
