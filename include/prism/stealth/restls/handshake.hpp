/**
 * @file handshake.hpp
 * @brief Restls 服务端握手
 * @details Restls 握手流程（Path C 代理，复用 ShadowTLS 双工转发架构）：
 * 1. 从客户端接收 ClientHello，转发到后端 TLS 服务器
 * 2. 读取 ServerHello，提取 server_random
 * 3. 双工转发握手数据：
 *    - 后端→客户端：XOR 第一个加密记录（server_mask）
 *    - 客户端→后端：捕获 clientFinished（完整加密 TLS record）
 * 4. 认证成功后关闭后端连接，返回握手结果
 *
 * 认证基于 BLAKE3 keyed mode，非传统 HMAC。
 */
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/stealth/restls/config.hpp>
#include <prism/stealth/restls/script.hpp>

namespace psm::stealth::restls
{
    namespace net = boost::asio;

    /**
     * @struct handshake_detail
     * @brief Restls 握手输出的额外数据
     * @details 握手成功后，scheme.cpp 需要这些数据来创建 restls_transport。
     */
    struct handshake_detail
    {
        std::array<std::uint8_t, 32> restls_secret{};     // RestlsSecret（BLAKE3 derive_key 派生）
        std::array<std::uint8_t, 32> server_random{};     // ServerHello 的 server_random
        memory::vector<std::uint8_t> client_finished;     // 客户端 Finished（完整加密 TLS record 含 header）
        memory::vector<std::byte> first_frame;            // 认证后的首帧数据
        bool tls13{true};                                 // 后端是否为 TLS 1.3
        script_engine script;                             // Restls script 引擎
    };

    /**
     * @brief Restls 服务端握手
     * @param client_sock 客户端 TCP socket
     * @param cfg Restls 配置
     * @param client_hello 已读取的完整 ClientHello（含 TLS header）
     * @param detail 输出参数，握手成功时填充
     * @return 握手结果
     */
    [[nodiscard]] auto handshake(net::ip::tcp::socket &client_sock,
                   const config &cfg,
                   memory::vector<std::byte> client_hello,
                   handshake_detail &detail)
        -> net::awaitable<stealth::handshake_result>;
} // namespace psm::stealth::restls
