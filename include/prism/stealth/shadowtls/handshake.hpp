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

#include <boost/asio.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/memory/container.hpp>
#include <vector>
#include <cstddef>

namespace psm::stealth::shadowtls
{
    namespace net = boost::asio;
    /**
     * @struct handshake_result
     * @brief ShadowTLS 握手结果
     */
    struct handshake_result
    {
        bool authenticated{false};                 // 是否认证成功
        std::error_code error;                     // 错误码
        std::vector<std::byte> client_first_frame; // 客户端首帧数据（认证后）
        std::string_view matched_user;             // 匹配的用户名
    };

    /**
     * @brief ShadowTLS v3 服务端握手
     * @details 执行完整的 ShadowTLS v3 握手流程：
     * 1. 使用已读取的 ClientHello 验证 HMAC
     * 2. 转发到后端服务器
     * 3. 处理握手阶段数据帧
     * @param client_sock 客户端 TCP socket
     * @param cfg ShadowTLS 配置
     * @param client_hello 已读取的完整 ClientHello 帧（含 TLS header）
     * @return 握手结果
     */
    auto handshake(net::ip::tcp::socket &client_sock, const config &cfg, memory::vector<std::byte> client_hello)
        -> net::awaitable<handshake_result>;
} // namespace psm::stealth::shadowtls
