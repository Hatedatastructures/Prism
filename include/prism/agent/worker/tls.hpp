/**
 * @file tls.hpp
 * @brief TLS 上下文初始化模块
 * @details 提供 TLS/SSL 上下文的创建和配置功能。根据服务配置
 * 加载证书链和私钥，设置 GREASE 扩展和 ALPN 协议协商参数。
 * 如果未提供证书或私钥，则返回空指针表示运行明文模式。
 * @note 该模块在 Worker 初始化阶段调用，每个 Worker 创建一次
 * TLS 上下文。
 * @warning 证书或私钥文件加载失败将抛出 exception::protocol。
 */

#pragma once

#include <memory>
#include <string_view>

#include <boost/asio/ssl.hpp>

#include <prism/agent/config.hpp>

namespace psm::agent::worker::tls
{
    namespace ssl = boost::asio::ssl;

    using shared_context = std::shared_ptr<ssl::context>; // TLS 上下文共享指针类型别名

    /**
     * @brief 配置 TLS 上下文参数
     * @details 对给定的 TLS 上下文进行初始化配置，主要包括四项
     * 工作：加载证书链文件用于服务端身份验证，加载私钥文件用于
     * 密钥交换，启用 GREASE 扩展增加 TLS 指纹随机性以提升安全
     * 性，设置 ALPN 协议列表支持 HTTP/2 和 HTTP/1.1 协议协商。
     * 证书和私钥加载失败时会记录错误日志并抛出协议异常。
     * @param ctx 待配置的 TLS 上下文引用
     * @param cert 证书链文件路径
     * @param key 私钥文件路径
     * @throws exception::protocol 证书或私钥文件加载失败时抛出
     */
    void configure(ssl::context &ctx, std::string_view cert, std::string_view key);

    /**
     * @brief 根据服务配置创建 TLS 上下文
     * @details 检查配置中的证书和私钥路径，如果任一为空则返回
     * 空指针，表示当前 worker 仅处理明文 HTTP 流量。如果两者
     * 都存在，则创建 TLS 上下文并调用 configure 进行初始化配置。
     * 配置失败时会抛出异常，调用方需要处理初始化失败的情况。
     * @param cfg 代理服务配置，包含证书和私钥路径
     * @return TLS 上下文共享指针，如果未配置证书则返回空指针
     * @throws exception::protocol 证书或私钥加载失败时抛出
     * @throws std::exception 其他初始化异常
     */
    [[nodiscard]] auto make(const agent::config &cfg)
        -> shared_context;
}
