/**
 * @file handshake.hpp
 * @brief ShadowTLS v3 服务端握手
 * @details ShadowTLS v3 服务端处理流程：
 * 1. 读取客户端 TLS ClientHello 帧
 * 2. 验证 SessionID 中的 HMAC 标签
 * 3. 认证成功后，与后端服务器完成 TLS 握手
 * 4. 握手完成后，处理数据帧的 HMAC 验证和 XOR 解密
 *
 * 与 Reality 不同，ShadowTLS 使用标准 TLS 外层，认证发生在
 * ClientHello 阶段，不需要伪造证书。
 */
#pragma once

#include <boost/asio.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/agent/context.hpp>
#include <span>
#include <cstdint>
#include <vector>
#include <error.h>

namespace psm::stealth::shadowtls
{
    namespace net = boost::asio;
    /**
     * @struct handshake_result
     * @brief ShadowTLS 握手结果
     */
    struct handshake_result
    {
        bool authenticated{false};              // 是否认证成功
        std::error_code error;                  // 错误码
        std::vector<std::byte> client_first_frame; // 客户端首帧数据（认证后）
        std::string_view matched_user;          // 匹配的用户名
    };

    /**
     * @brief ShadowTLS v3 服务端握手
     * @details 执行完整的 ShadowTLS v3 握手流程：
     * 1. 读取 ClientHello
     * 2. 验证 HMAC
     * 3. 转发到后端服务器
     * 4. 处理握手阶段数据帧
     * @param ctx 会话上下文
     * @param cfg ShadowTLS 配置
     * @param pre_read_data 预读数据（如果有）
     * @return 握手结果
     */
    auto handshake(agent::session_context &ctx,
                   const config &cfg,
                   std::span<const std::byte> pre_read_data = {})
        -> net::awaitable<handshake_result>;
} // namespace psm::stealth::shadowtls
