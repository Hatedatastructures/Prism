/**
 * @file handshake.hpp
 * @brief Restls 服务端握手（中间人代理模式）
 * @details Restls 握手流程（中间人代理）：
 * 1. 转发客户端 ClientHello 到真实 TLS 后端（如 nvidia.com:443）
 * 2. 读取后端 ServerHello，提取 server_random
 * 3. 双工转发握手数据：
 *    - 后端→客户端：XOR 第一个加密记录（serverRandomMac auth 验证）
 *    - 客户端→后端：捕获 clientFinished（完整加密 TLS record）
 * 4. 认证成功后关闭后端连接，把 raw socket 交给 restls_transport
 */
#pragma once

#include <prism/core/memory/container.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/stealth/facade/restls/config.hpp>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/stealth/facade/restls/transport.hpp>
#include <prism/stealth/scheme.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <span>


namespace psm::stealth::restls
{

    namespace net = boost::asio;

    /**
     * @struct handshake_detail
     * @brief Restls 握手输出的额外数据
     */
    struct handshake_detail
    {
        std::array<std::uint8_t, 32> restls_secret{};  ///< RestlsSecret
        std::array<std::uint8_t, 32> server_random{};  ///< ServerHello 的 server_random
        memory::vector<std::byte> client_finished;     ///< 客户端 Finished（完整加密 TLS record，含 5B header）
        memory::vector<std::byte> first_encrypted;     ///< 后端第一个加密帧（XOR 后的内容，含 5B header）
        tls_version version{tls_version::v13};         ///< TLS 版本
        script_engine script;                          ///< Restls script 引擎
    };

    /**
     * @struct handshake_opts
     * @brief handshake 参数收敛
     */
    struct handshake_opts
    {
        std::shared_ptr<transport::reliable> raw_trans;  ///< 客户端 raw TCP transport（所有权转移）
        const config &cfg;                                ///< Restls 配置
        memory::vector<std::byte> client_hello;           ///< 预读的 ClientHello
        handshake_detail &detail;                         ///< 握手输出
    };

    /**
     * @brief Restls 服务端握手
     */
    [[nodiscard]] auto handshake(handshake_opts opts)
        -> net::awaitable<stealth::handshake_result>;

} // namespace psm::stealth::restls
