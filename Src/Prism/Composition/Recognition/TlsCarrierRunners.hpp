/** @file TlsCarrierRunners.hpp @brief TLS carrier owner 的私有执行入口声明。 */
#pragma once

#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>

#include <memory>

namespace Prism::Composition::Recognition
{

    [[nodiscard]] auto RunShadowtlsServerAccept(
        std::shared_ptr<Prism::Shadowtls::ServerSession> Session,
        Prism::Shadowtls::ServerConfig Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto RunWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto RunXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto RunGunServerAccept(
        GunServerAcceptOptions Options,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto RejectRealityAccept(
        Prism::SharedTransmission Inbound,
        Prism::Fault::Failure Cause)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto RunRealityServerAccept(
        Prism::Reality::PreparedConfig Config,
        Core::CarrierAcceptPreparedInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    /**
     * @brief 执行 strict Native TLS 服务端 carrier 接入。
     * @param TlsContext 按值持有的服务端 SSL context。
     * @param Input 按值接管的入站传输与 worker BytePool。
     * @return typed carrier 结果，保留 NativeError 和握手 fault。
     * @details Native 入口必须完成 TLS 握手；executor 与取消随传输传播，失败
     *          关闭由 admission ticket 排空，成功后的最终关闭由 session owner 负责。
     */
    [[nodiscard]] auto RunNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>;

} // namespace Prism::Composition::Recognition
