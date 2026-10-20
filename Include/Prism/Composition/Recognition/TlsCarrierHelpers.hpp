/**
 * @file TlsCarrierHelpers.hpp
 * @brief 具体 TLS carrier 的服务端接入回调构造辅助函数。
 * @details 每个回调按值捕获长期依赖，并在成功时转移已完成 carrier
 *          握手的传输；失败通过 typed fault 返回给 Recognition commit。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <cstdint>
#include <memory>
#include <utility>

#include <Prism/Composition/Recognition/TlsCandidateModel.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Prism/Protocols/Reality/Prepared.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Protocols/Xhttp/Xhttp.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /** @brief 已通过 Application 配置校验的 Gun 服务模式。 */
    enum class GunServerMode : std::uint8_t
    {
        GunLite,
        Grpc,
    };

    /**
     * @struct GunServerAcceptOptions
     * @brief Gun carrier 的 owning 冷装配材料。
     * @details Mode 已由 Application 从配置字符串解析；运行期 callback 不再
     *          借用配置或按未知字符串隐式选择 GunLite。
     */
    struct GunServerAcceptOptions final
    {
        GunServerAcceptOptions(
            std::shared_ptr<Net::ssl::context> TlsContextValue,
            Prism::Gun::Config ConfigValue,
            const GunServerMode ModeValue)
            : TlsContext(std::move(TlsContextValue)), Config(std::move(ConfigValue)), Mode(ModeValue)
        {
        }

        std::shared_ptr<Net::ssl::context> TlsContext;
        Prism::Gun::Config Config;
        GunServerMode Mode;
    };

    /**
     * @brief 创建 ShadowTLS v3 服务端 carrier 接入回调。
     * @param Options relay 目标拨号选项。
     * @param Config ShadowTLS 认证配置。
     * @return 可长期捕获的服务端接入回调。
     * @details factory 只提交 named runner；runner 按值拥有 session、配置和
     *          typed carrier input，并在 inbound executor 上调用 ShadowTLS protocol owner。
     *          失败返回 typed fault，取消、半关闭和最终关闭由 protocol owner 承担。
     */
    [[nodiscard]] auto MakeShadowtlsServerAccept(Prism::Shadowtls::ServerOptions Options,
                                                        Prism::Shadowtls::ServerConfig Config)
        -> CarrierAcceptFn;

    /**
     * @brief 创建 WebSocket 服务端 carrier 接入回调。
     * @param TlsContext 按值复制的 TLS context shared owner；可为空表示明文 WS。
     * @param Config WebSocket path/Host 约束，按值进入 callback frame。
     * @return 在 carrier commit 阶段执行真实 HTTP Upgrade 的回调。
     * @details callback 在入站 transport executor 上运行；同一 Bytes shared owner
     *          分别交给 TLS 与 WS Conn。取消只取消在途操作；半关闭由 ConnClose 转交，
     *          最终关闭由 ConnClose 交付，活动排空后 ConnSession 释放 BytePool owner。
     */
    [[nodiscard]] auto MakeWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config) -> CarrierAcceptFn;

    /**
     * @brief 创建 XHTTP 服务端 carrier 接入回调。
     * @param TlsContext 按值复制的服务端 TLS context shared owner。
     * @param Config XHTTP path/authority/mode 约束，按值进入 callback frame。
     * @return 在 carrier commit 阶段执行真实 TLS + HTTP/2 握手的回调。
     * @details callback 不借用 Application configuration；取消、半关闭和最终
     *          transport 关闭由 XHTTP protocol owner 执行。
     */
    [[nodiscard]] auto MakeXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config) -> CarrierAcceptFn;

    /**
     * @brief 创建 Gun 服务端 carrier 接入回调。
     * @param Options 已完成校验并按值拥有的 TLS/Gun/mode 材料。
     * @return 在 carrier commit 阶段执行真实 TLS + Gun CONNECT 握手的回调。
     */
    [[nodiscard]] auto MakeGunServerAccept(GunServerAcceptOptions Options)
        -> CarrierAcceptFn;

    [[nodiscard]] auto MakeRealityServerAccept(
        Prism::Reality::PreparedConfig Config)
        -> CarrierAcceptPreparedFn;

    /**
     * @brief 构造唯一 Native TLS 服务端 carrier callback。
     * @param TlsContext 按值接管的 shared SSL context；空值仍返回 typed callback，
     *        由 strict Native owner 产生明确失败结果。
     * @return 运行期只捕获 owning context 的 carrier callback。
     * @details callback 在入站 transport executor 上执行；必须完成 TLS handshake，
     *          不接受明文前缀直通。通用可选 TLS 前缀探测仍由 Transport owner 使用。
     */
    [[nodiscard]] auto MakeNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext) -> CarrierAcceptFn;

} // namespace Prism::Composition::Recognition
