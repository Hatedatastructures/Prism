/**
 * @file ShadowtlsCarrier.hpp
 * @brief Composition 使用的 ShadowTLS 服务端 carrier 工厂。
 * @details 该头文件只提供稳定的 Composition 命名入口，协议细节由
 *          Preview::Shadowtls::ServerSession 负责。
 */
#pragma once

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Shadowtls/Carrier.hpp>

#include <utility>

namespace Preview::Composition::Recognition
{

    /**
     * @brief 构造 ShadowTLS 服务端 carrier facade。
     * @param Options 目标 TLS 服务拨号配置
     * @param Config ShadowTLS 服务端认证配置
     * @return 配置有效时可执行 wire relay 的 facade，否则返回 unavailable facade
     */
    [[nodiscard]] inline auto MakeShadowtlsCarrier(Preview::Shadowtls::ServerOptions Options,
                                                    Preview::Shadowtls::ServerConfig Config)
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Shadowtls::MakeFacadeCarrier(std::move(Options), std::move(Config));
    }

} // namespace Preview::Composition::Recognition
