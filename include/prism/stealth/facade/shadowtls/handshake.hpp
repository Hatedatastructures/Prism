/**
 * @file handshake.hpp
 * @brief ShadowTLS v3 服务端握手
 * @details ShadowTLS v3 服务端处理流程：
 * 1. 接收已读取的 ClientHello（由 Recognition 层预读）
 * 2. 验证 SessionID 中的 HMAC 标签
 * 3. 认证成功后，与后端服务器完成 TLS 握手
 * 4. 握手完成后，处理数据帧的 HMAC 验证和 XOR 解密
 *
 * 与 Reality 不同，ShadowTLS 使用标准 TLS 外层，认证发生在
 * ClientHello 阶段，不需要伪造证书。
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/stealth/facade/shadowtls/config.hpp>

#include <boost/asio.hpp>
#include <openssl/hmac.h>

#include <cstddef>
#include <memory>
#include <vector>


namespace psm::outbound
{

    class proxy;

}

namespace psm::stealth::shadowtls
{

    namespace net = boost::asio;

    /// HMAC 上下文删除器
    struct hmac_ctx_deleter
    {
        void operator()(HMAC_CTX *ctx) const { HMAC_CTX_free(ctx); }
    };

    /**
     * @struct handshake_detail
     * @brief ShadowTLS 握手输出的额外数据
     * @details 握手成功后，scheme.cpp 需要这些数据来创建 shadowtls_transport。
     * 参照 sing-shadowtls service.go case 3：
     * - hmac_write_ctx: 写入方向累积 HMAC，初始状态 = password + serverRandom + "S"
     * - hmac_read_ctx: 读取方向累积 HMAC，初始状态 = password + serverRandom + "C" + first_frame_payload + HMAC[:4]
     */
    struct handshake_detail
    {
        memory::vector<std::byte> client_firstframe; ///< 客户端首帧数据（认证后，TLS header + payload）
        std::string matched_user;                     ///< 匹配的用户名
        std::string matched_password;                 ///< 匹配的密码（用于后续 HMAC 计算）
        std::array<std::byte, 32> server_random{};    ///< ServerHello 的 ServerRandom（用于后续 HMAC 和 XOR）
        std::shared_ptr<HMAC_CTX> hmac_write_ctx;     ///< 写入方向累积 HMAC（初始：password + SR + "S"）
        std::shared_ptr<HMAC_CTX> hmac_read_ctx;      ///< 读取方向累积 HMAC（初始：password + SR + "C" + payload + HMAC[:4]）
    };

    /**
     * @struct handshake_opts
     * @brief handshake 参数收敛
     * @details 将参数收敛为单一结构体，遵守 Rule 1。
     * 使用 shared_transmission 替代裸 tcp::socket（RFC-033 装饰器化）。
     */
    struct handshake_opts
    {
        transport::shared_transmission inbound;
        const config &cfg;
        outbound::proxy *outbound{nullptr};
        memory::vector<std::byte> client_hello;
        handshake_detail &detail;
        std::shared_ptr<trace::trace_context> prefix;
        // 便捷访问：trace 等价于 prefix（P9 显式传参过渡）
        std::shared_ptr<trace::trace_context> trace;
    };

    /**
     * @brief ShadowTLS v3 服务端握手
     * @details 执行完整的 ShadowTLS v3 握手流程：
     * 1. 使用已读取的 ClientHello 验证 HMAC
     * 2. 转发到后端服务器（通过 connect::dial）
     * 3. 处理握手阶段数据帧
     * @param opts 握手参数（inbound, cfg, router, client_hello, detail）
     * @return 握手结果（使用 stealth 基类的 handshake_result）
     */
    [[nodiscard]] auto handshake(handshake_opts opts)
        -> net::awaitable<stealth::handshake_result>;
} // namespace psm::stealth::shadowtls
