/**
 * @file shadowsocks2022.hpp
 * @brief Shadowsocks 2022 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，chunk 加解密数据面）、
 *   dgram（包，dgram.hpp，逐包 AEAD）
 * - 编解码/密码学：codec.hpp（头部编解码 + KDF + chunk + 握手 + UDP 数据报）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/udp_transmission.hpp>
#include <common/proxy/shadowsocks2022/conn.hpp>
#include <common/proxy/shadowsocks2022/dgram.hpp>
#include <common/proxy/shadowsocks2022/types.hpp>

#include <openssl/evp.h>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace psmtest::shadowsocks2022
{

    namespace ss = psmtest::ss2022;

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief SS2022 客户端配置
     * @details 控制客户端的行为：密码（PSK 派生）。构造后只读。
     */
    struct client_config
    {
        /// 客户端密码（连接构造时派生 16 字节 PSK）
        std::string password;
    };

    /**
     * @struct server_config
     * @brief SS2022 服务端配置
     * @details 控制服务端的行为：密码（PSK 派生）与时间戳窗口。
     * 构造后只读。
     */
    struct server_config
    {
        /// 服务端密码（连接构造时派生 16 字节 PSK）
        std::string password;
        /// 时间戳容忍窗口（秒）
        std::uint64_t time_window{90};
    };

    // =========================================================================
    // 工具
    // =========================================================================

    /// 密码派生 16 字节 PSK（测试库约定：SHA256 前 16 字节）
    [[nodiscard]] inline auto derive_psk(std::string_view password)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 32> hash{};
        unsigned int len = 0;
        EVP_Digest(password.data(), password.size(), hash.data(), &len, EVP_sha256(), nullptr);
        std::array<std::uint8_t, 16> psk{};
        std::memcpy(psk.data(), hash.data(), 16);
        return psk;
    }

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 salt 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      const ss::address &target)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(cfg.password);
        const auto err = co_await c->write_handshake(std::move(upstream), target);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

    /**
     * @brief 创建客户端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param ex 执行器
     * @param remote 代理服务器 UDP 端点（host:port）
     * @param cfg 客户端配置
     * @return 包连接（连接失败时为空）
     * @details 直接创建 UDP socket 连接服务器，逐包 AEAD 加密；
     * 无 TCP 握手（对齐 SIP022 独立数据报通道）。
     */
    [[nodiscard]] inline auto connect_packet(net::any_io_executor ex, const std::string &remote,
                                             const client_config &cfg) -> shared_dgram
    {
        auto udp = std::make_shared<udp_transmission>(ex);
        if (!udp->connect(remote))
            return nullptr;
        return std::make_shared<dgram>(std::move(udp), derive_psk(cfg.password));
    }

    /**
     * @brief 接收服务端流连接并完成首包握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, ss::message, shared_conn>>
    {
        auto c = std::make_shared<conn>(cfg.password);
        auto [err, req] = co_await c->read_handshake(std::move(upstream));
        co_return std::tuple{err, std::move(req),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 创建服务端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param ex 执行器
     * @param port 监听端口
     * @param cfg 服务端配置
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，逐包 AEAD 解密；无 TCP 握手。
     */
    [[nodiscard]] inline auto accept_packet(net::any_io_executor ex, unsigned short port,
                                            const server_config &cfg) -> shared_dgram
    {
        auto udp = std::make_shared<udp_transmission>(ex);
        if (!udp->bind(port))
            return nullptr;
        return std::make_shared<dgram>(std::move(udp), derive_psk(cfg.password));
    }

    // 编解码类型 re-export（ss2022 命名空间 → shadowsocks2022）
    using psmtest::ss2022::address;
    using psmtest::ss2022::address_type;
    using psmtest::ss2022::message;
    using psmtest::ss2022::parser;
    using psmtest::ss2022::serializer;

} // namespace psmtest::shadowsocks2022
