/**
 * @file tls.hpp
 * @brief TLS 上下文初始化模块。
 * @details 本文件提供 TLS/SSL 上下文的创建和配置功能。根据服务
 * 配置加载证书链和私钥，设置 GREASE 扩展和 ALPN 协议协商参数。
 * 如果未提供证书或私钥，则返回空指针表示运行明文模式。
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <boost/asio/ssl.hpp>

#include <prism/exception.hpp>
#include <prism/agent/config.hpp>
#include <prism/trace.hpp>

/**
 * @namespace psm::agent::worker::tls
 * @brief TLS 上下文管理功能。
 * @details 该命名空间封装了 TLS 上下文的创建和配置逻辑。提供
 * 从配置文件加载证书和私钥的能力，支持 HTTP/2 和 HTTP/1.1 的
 * ALPN 协议协商。如果服务未配置 TLS 证书，则自动降级为明文模式。
 */
namespace psm::agent::worker::tls
{
    namespace ssl = boost::asio::ssl;

    // TLS 上下文共享指针类型别名。
    using shared_context = std::shared_ptr<ssl::context>;

    /**
     * @brief 配置 TLS 上下文参数。
     * @details 对给定的 TLS 上下文进行初始化配置，主要包括四项工作：
     * 加载证书链文件用于服务端身份验证，加载私钥文件用于密钥交换，
     * 启用 GREASE 扩展增加 TLS 指纹随机性以提升安全性，设置 ALPN
     * 协议列表支持 HTTP/2 和 HTTP/1.1 协议协商。证书和私钥加载失败
     * 时会记录错误日志并抛出协议异常。
     * @param ctx 待配置的 TLS 上下文引用。
     * @param cert 证书链文件路径。
     * @param key 私钥文件路径。
     * @throws exception::protocol 证书或私钥文件加载失败时抛出。
     */
    void configure(ssl::context &ctx, std::string_view cert, std::string_view key);

    /**
     * @brief 根据服务配置创建 TLS 上下文。
     * @details 检查配置中的证书和私钥路径，如果任一为空则返回空指针，
     * 表示当前 worker 仅处理明文 HTTP 流量。如果两者都存在，则创建
     * TLS 上下文并调用 configure 进行初始化配置。配置失败时会抛出
     * 异常，调用方需要处理初始化失败的情况。
     * @param cfg 代理服务配置，包含证书和私钥路径。
     * @return TLS 上下文共享指针；如果未配置证书则返回空指针。
     * @throws exception::protocol 证书或私钥加载失败时抛出。
     * @throws std::exception 其他初始化异常。
     */
    [[nodiscard]] auto make(const agent::config &cfg)
        -> shared_context;
}
