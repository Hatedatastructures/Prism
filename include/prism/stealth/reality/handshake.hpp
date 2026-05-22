/**
 * @file handshake.hpp
 * @brief Reality 握手状态机
 * @details Reality 协议的核心入口，协调 ClientHello 解析、认证、
 * TLS 1.3 握手和回退逻辑。由 session 层调用。
 */

#pragma once

#include <cstdint>
#include <span>
#include <prism/context/context.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/stealth/scheme.hpp>
#include <boost/asio.hpp>

namespace psm::connect
{
    class router;
} // namespace psm::connect

namespace psm::stealth::reality
{
    namespace net = boost::asio;

    /**
     * @brief 执行 Reality 握手
     * @details 读取 ClientHello，尝试 Reality 认证，成功则建立加密传输层，
     * 失败则回退到 dest 服务器的标准 TLS 或直接透传
     * @param inbound 入站传输层（不转移所有权，仅使用）
     * @param cfg 服务器配置
     * @param session 会话上下文（用于 fallback 等需要 router 的场景）
     * @return net::awaitable<stealth::handshake_result> 异步操作，返回握手结果
     */
    auto handshake(transport::shared_transmission inbound,
                   const psm::config &cfg,
                   psm::context::session &session)
        -> net::awaitable<stealth::handshake_result>;

    /**
     * @brief 执行回退：连接 dest 服务器并透明代理
     * @details 连接配置的 dest 目标服务器，将原始 TLS 记录转发过去，
     * 完成透明代理后由上层继续处理内层协议
     * @param session 会话上下文（用于 router 和 tunnel）
     * @param inbound 入站传输层
     * @param raw_record 原始 ClientHello TLS 记录字节
     * @return net::awaitable<fault::code> 异步操作，返回错误码
     */
    auto fallback_to_dest(psm::context::session &session,
                          transport::shared_transmission inbound,
                          std::span<const std::uint8_t> raw_record)
        -> net::awaitable<fault::code>;

    /**
     * @brief 从 dest 配置中解析 host 和 port
     * @details 解析 "host:port" 格式的 dest 配置字符串
     * @param dest 目标地址字符串（host:port 格式）
     * @param host 输出参数，解析出的主机名
     * @param port 输出参数，解析出的端口号
     * @return bool 解析成功返回 true，格式错误返回 false
     */
    auto parse_dest(std::string_view dest, std::string &host, std::uint16_t &port) -> bool;

    /**
     * @brief 从 dest 服务器获取证书
     * @details 通过 router 解析目标地址并建立 TLS 连接，
     * 获取目标网站的 DER 格式证书用于 Reality 伪造
     * @param host 目标主机名
     * @param port 目标端口
     * @param router 路由器引用，用于 DNS 解析
     * @return net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
     * 异步操作，返回错误码和 DER 格式证书
     */
    auto fetch_dest_certificate(std::string_view host, std::uint16_t port, connect::router &router)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;
} // namespace psm::stealth::reality
