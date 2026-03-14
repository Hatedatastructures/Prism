/**
 * @file protocols.hpp
 * @brief 协议处理管道入口
 * @details 定义 HTTP、SOCKS5 和 TLS 流量的具体会话处理函数。
 * 会话层检测协议后直接分发到这些函数，不再使用单独的注册表
 * 包装或兼容层。每个函数负责完整的协议处理流程，包括请求解析、
 * 上游连接建立以及双向隧道转发。
 */

#pragma once
#include <cstddef>
#include <cctype>
#include <algorithm>

#include <memory>
#include <string>
#include <utility>
#include <string_view>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/context.hpp>
#include <forward-engine/agent/distribution/router.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/protocol/socks5.hpp>
#include <forward-engine/transport/adaptation.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/agent/pipeline/primitives.hpp>

/**
 * @namespace ngx::agent::pipeline
 * @brief 协议处理管道命名空间
 * @details 定义协议处理的核心逻辑，包括转发辅助函数和具体协议
 * 处理函数。该命名空间实现了基于 transmission 抽象层的协议处理
 * 管道，包含资源管理函数 shut_close()、连接建立函数 dial()、
 * 原始转发函数 original_tunnel() 以及协议处理函数 http()、
 * socks5()、tls()。
 * @note 该命名空间的内容主要用于协议处理逻辑，请勿在协议检测
 * 阶段调用。
 * @warning 预读数据注入必须在协议接管之前完成，否则可能导致
 * 协议解析失败。
 */
namespace ngx::agent::pipeline
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;

    /**
     * @brief HTTP 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的初始数据
     * @return 异步操作对象，处理完成后返回
     * @details 解析 HTTP 请求，连接上游，并建立隧道。支持 CONNECT
     * 方法和普通 HTTP 请求。处理流程包括请求解析、目标地址提取、
     * 上游连接建立、CONNECT 响应或请求转发、双向隧道建立。
     * 对于 CONNECT 方法，向客户端发送 200 Connection Established
     * 响应后建立原始隧道进行透明转发。对于普通请求，将请求序列化
     * 后转发到上游，同时转发预读缓冲区中的剩余数据，最后建立
     * 双向隧道转发后续响应。
     * @note 支持 HTTP/1.1，自动处理 chunked 编码和连接复用。
     * @warning 如果请求解析失败或连接建立失败，会静默关闭连接
     * 而不返回错误。
     */
    auto http(ngx::agent::session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

    /**
     * @brief SOCKS5 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的初始数据
     * @return 异步操作对象，处理完成后返回
     * @details 处理 SOCKS5 握手、请求和转发。支持 SOCKS5 协议标准
     * 定义的所有命令和地址类型。处理流程包括握手协商获取认证方法
     * 和协议版本、请求解析获取目标地址和端口、命令分发根据命令
     * 类型分发到 TCP 隧道或 UDP 中继、响应发送向客户端发送成功或
     * 错误响应、隧道建立建立双向数据隧道。
     * @note 支持 CONNECT 和 UDP_ASSOCIATE 命令，不支持 BIND 命令。
     * @warning SOCKS5 协议要求预读数据为空，否则握手可能失败。
     */
    auto socks5(ngx::agent::session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>;

    /**
     * @brief TLS 协议处理函数
     * @param ctx 会话上下文，包含入站传输和 SSL 配置
     * @param data 预读数据，协议检测时读取的初始数据（TLS 协议应为空）
     * @return 异步操作对象，处理完成后返回
     * @details 执行 TLS 握手，解密后作为 HTTPS 处理。处理流程包括
     * TLS 握手执行服务器端 TLS 握手，支持 SNI 和 ALPN、HTTP 解析
     * 将解密的流量作为 HTTP 请求解析、目标解析从 HTTP 请求中提取
     * 目标主机和端口、连接建立调用 dial() 连接到上游服务器、
     * CONNECT 处理如果是 CONNECT 方法，建立原始隧道、请求转发
     * 否则序列化请求并转发、隧道建立建立双向数据隧道。
     * @note 假设 TLS 内部是 HTTP/HTTPS 协议，不支持其他应用层协议。
     * @warning TLS 协议要求预读数据为空，否则握手会失败。
     */
    auto tls(ngx::agent::session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace ngx::agent::pipeline
