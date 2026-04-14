/**
 * @file handshake.hpp
 * @brief Reality 握手状态机
 * @details Reality 协议的核心入口，协调 ClientHello 解析、认证、
 * TLS 1.3 握手和回退逻辑。由 session::diversion() 调用。
 */

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>
#include <prism/agent/context.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/reality/constants.hpp>
#include <boost/asio.hpp>

namespace psm::protocol::reality
{
    namespace net = boost::asio;

    /**
     * @enum handshake_result_type
     * @brief 握手结果类型
     */
    enum class handshake_result_type
    {
        authenticated, ///< Reality 认证成功，返回加密传输层
        not_reality,   ///< 非 Reality 客户端（SNI 不匹配），应走标准 TLS
        fallback,      ///< 回退到 dest 服务器，透明代理已完成
        failed         ///< 错误
    };

    /**
     * @struct handshake_result
     * @brief 握手结果
     */
    struct handshake_result
    {
        handshake_result_type type = handshake_result_type::failed;

        /// type == authenticated: 加密传输层
        channel::transport::shared_transmission encrypted_transport;

        /// type == authenticated: 内层预读数据
        memory::vector<std::byte> inner_preread;

        /// type == not_reality: 原始 ClientHello TLS record，供标准 TLS 路径使用
        memory::vector<std::byte> raw_tls_record;

        /// 错误码
        fault::code error = fault::code::success;
    };

    /**
     * @brief 执行 Reality 握手
     * @param ctx 会话上下文（ctx.inbound 是原始 TCP 传输层）
     * @param preread probe 阶段读取的前 24 字节（TLS ClientHello 开头）
     * @return 握手结果
     * @details 完整流程：
     * 1. 读取完整 ClientHello
     * 2. Reality 认证（SNI + X25519 + short_id）
     * 3a. 认证失败 → 连接 dest → 透明代理 → 返回 fallback
     * 3b. 认证成功 → 自定义 TLS 1.3 握手 → 返回加密传输层
     */
    auto handshake(psm::agent::session_context &ctx, std::span<const std::byte> preread)
        -> net::awaitable<handshake_result>;

    /**
     * @brief 执行回退：连接 dest 服务器并透明代理
     * @param ctx 会话上下文
     * @param raw_record 完整的 ClientHello TLS 记录
     * @return 错误码
     */
    auto fallback_to_dest(psm::agent::session_context &ctx, std::span<const std::uint8_t> raw_record)
        -> net::awaitable<fault::code>;

    /**
     * @brief 从 dest 配置中解析 host 和 port
     * @param dest "host:port" 格式字符串
     * @param host 输出主机名
     * @param port 输出端口号
     * @return 解析成功返回 true
     */
    auto parse_dest(std::string_view dest, std::string &host, std::uint16_t &port) -> bool;

    /**
     * @brief 从 dest 服务器获取证书
     * @param host dest 服务器主机名
     * @param port dest 服务器端口
     * @return DER 编码的证书链，失败返回空
     * @details 临时连接到 dest:443，执行 TLS 握手到 Certificate 阶段，
     * 提取证书链后断开连接。此操作是阻塞的，但仅在握手期间执行一次。
     * @note 使用协程异步连接。
     */
    auto fetch_dest_certificate(std::string_view host, std::uint16_t port, net::any_io_executor executor)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;
} // namespace psm::protocol::reality
