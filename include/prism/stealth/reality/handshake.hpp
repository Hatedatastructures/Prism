/**
 * @file handshake.hpp
 * @brief Reality 握手状态机
 * @details Reality 协议的核心入口，协调 ClientHello 解析、认证、
 * TLS 1.3 握手和回退逻辑。由 session 层调用。
 */

#pragma once

#include <cstdint>
#include <span>
#include <prism/agent/context.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <boost/asio.hpp>

namespace psm::resolve
{
    class router;
} // namespace psm::resolve

namespace psm::stealth::reality
{
    namespace net = boost::asio;

    /**
     * @enum handshake_result_type
     * @brief 握手结果类型
     */
    enum class handshake_result_type
    {
        /** @brief Reality 认证成功，返回加密传输层 */
        authenticated,
        /** @brief 非 Reality 客户端（SNI 不匹配），应走标准 TLS */
        not_reality,
        /** @brief 回退到 dest 服务器，透明代理已完成 */
        fallback,
        /** @brief 错误 */
        failed
    };

    /**
     * @struct handshake_result
     * @brief 握手结果
     * @details 包含握手结果类型、加密传输层（认证成功时）、
     * 内层预读数据、原始 TLS 记录（非 Reality 时）和错误码
     */
    struct handshake_result
    {
        handshake_result_type type = handshake_result_type::failed;  // 握手结果类型
        channel::transport::shared_transmission encrypted_transport; // type==authenticated 时为加密传输层
        memory::vector<std::byte> inner_preread;                     // type==authenticated 时为内层预读数据
        memory::vector<std::byte> raw_tls_record;                    // type==not_reality 时为原始 ClientHello TLS record
        fault::code error = fault::code::success;                    // 错误码
    };

    /**
     * @brief 执行 Reality 握手
     * @details 读取 ClientHello，尝试 Reality 认证，成功则建立加密传输层，
     * 失败则回退到 dest 服务器的标准 TLS 或直接透传
     * @param ctx 会话上下文
     * @param preread 预读的初始数据
     * @return net::awaitable<handshake_result> 异步操作，返回握手结果
     */
    auto handshake(psm::agent::session_context &ctx, std::span<const std::byte> preread)
        -> net::awaitable<handshake_result>;

    /**
     * @brief 执行回退：连接 dest 服务器并透明代理
     * @details 连接配置的 dest 目标服务器，将原始 TLS 记录转发过去，
     * 完成透明代理后由上层继续处理内层协议
     * @param ctx 会话上下文
     * @param raw_record 原始 ClientHello TLS 记录字节
     * @return net::awaitable<fault::code> 异步操作，返回错误码
     */
    auto fallback_to_dest(psm::agent::session_context &ctx, std::span<const std::uint8_t> raw_record)
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
    auto fetch_dest_certificate(std::string_view host, std::uint16_t port, resolve::router &router)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;
} // namespace psm::stealth::reality
