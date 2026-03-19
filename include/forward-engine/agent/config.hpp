/**
 * @file config.hpp
 * @brief Agent 运行时配置类型定义
 * @details 声明代理服务的配置模型，涵盖工作线程启动、账户状态管理、
 * 路由策略、监听端点、TLS 证书以及协议管道行为等核心配置项。
 * 所有配置结构均采用 PMR 内存分配器，支持高性能内存管理。
 */
#pragma once

#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/socks5/config.hpp>
#include <forward-engine/protocol/trojan/config.hpp>

/**
 * @namespace ngx::agent
 * @brief Agent 运行时域
 * @details 包含代理运行时的配置、会话、路由、前端监听器以及
 * 协议管道构建模块。该命名空间是正向代理引擎的核心组件集合，
 * 负责连接管理、流量转发和协议适配。
 */
namespace ngx::agent
{
    /**
     * @struct endpoint
     * @brief 网络端点配置
     * @details 表示一个网络端点，包含主机名和端口号。用于定义
     * 监听地址、正向代理目标、反向代理后端等场景。主机名支持
     * 域名和 IP 地址两种格式，端口号范围为 1 至 65535。
     * @note 主机名使用 memory::string 存储，支持 PMR 内存分配。
     * @warning 端口号 0 表示未设置，配置验证时应检查端口有效性。
     */
    struct endpoint
    {
        // 主机名，可以是域名或 IP 地址
        memory::string host;

        // 端口号，范围 1-65535，0 表示未设置
        std::uint16_t port = 0;
    };

    /**
     * @struct limit
     * @brief 连接限制配置
     * @details 控制代理服务的并发连接数和黑名单策略，用于防止
     * 资源耗尽和恶意请求攻击。并发限制作用于全局所有工作线程，
     * 黑名单功能可根据内部规则拦截可疑 IP 地址。
     * @note 并发连接数限制是全局性的，作用于所有工作线程。
     * @warning 设置过小的并发数可能导致服务拒绝合法连接，
     * 应根据服务器资源合理调整。
     */
    struct limit
    {
        // 最大并发连接数，默认 20，0 表示无限制
        std::uint32_t concurrences = 20U;

        // 是否启用黑名单，默认启用
        bool blacklist = true;
    };

    /**
     * @struct certificate
     * @brief SSL/TLS 证书配置
     * @details 包含 TLS 加密所需的私钥和证书文件路径，用于配置
     * SSL 上下文以支持 HTTPS 和 TLS 协议。文件格式要求为 PEM，
     * 私钥用于 TLS 握手签名，证书包含公钥和证书链信息。
     * @note 文件路径使用 memory::string 存储，支持 PMR 内存分配。
     * @warning 文件路径必须可读，否则 SSL 上下文初始化会失败。
     */
    struct certificate
    {
        // 私钥文件路径，PEM 格式
        memory::string key;

        // 证书文件路径，PEM 格式
        memory::string cert;
    };

    /**
     * @struct authentication
     * @brief 身份认证配置
     * @details 管理客户端身份验证的凭据和用户限制。支持两种模式：
     * 简单凭据列表模式仅校验凭据是否存在，无独立限制；用户列表
     * 模式可为每个用户配置独立的最大并发连接数。凭据通常为密码
     * 的 SHA224 哈希值，由客户端在握手阶段提供。
     * @note 凭据通常是密码的 SHA224 哈希，由客户端在握手时提供。
     * @warning 如果同时配置 credentials 和 users，account::directory
     * 会优先检查 users 列表。
     */
    struct authentication
    {
        /**
         * @struct user
         * @brief 用户配置
         * @details 表示一个独立用户，包含凭据和可选的连接数限制。
         * 用于精细化的连接控制和配额管理。用户凭据在 account::directory
         * 中用于查找和配额控制。
         * @note 用户凭据在 account::directory 中用于查找和配额控制。
         * @warning 如果 max_connections 设为 0，该用户不受并发数限制。
         */
        struct user
        {
            // 用户凭据，SHA224 哈希字符串
            memory::string credential;

            // 最大并发连接数，0 表示无限制
            std::uint32_t max_connections = 0;
        };

        // 凭据列表，存储允许通过验证的 SHA224 密码哈希
        memory::vector<memory::string> credentials;

        // 用户列表，支持为单个用户配置独立限制
        memory::vector<user> users;
    };

    /**
     * @struct pool_config
     * @brief 连接池配置
     * @details 控制连接池的行为参数，包括缓存大小和空闲超时。
     * 连接池缓存 TCP 连接以避免频繁的三次握手，提升性能。
     * 合理配置可平衡内存占用和连接复用效率。
     * @note 连接池缓存 TCP 连接，避免频繁的三次握手，提升性能。
     * @warning 设置过大的缓存数可能导致内存压力，应根据实际
     * 并发连接数调整。
     */
    struct pool_config
    {
        // 单个目标端点最大缓存连接数，默认 32
        std::uint32_t max_cache_per_endpoint = 32U;

        // 空闲连接最大存活时间（秒），默认 60 秒
        std::uint64_t max_idle_seconds = 60ULL;
    };

    /**
     * @struct buffer
     * @brief 缓冲区配置
     * @details 控制数据传输时的缓冲区大小。合理的缓冲区大小可以
     * 平衡内存占用和吞吐量。对于高延迟高带宽环境建议增大此值，
     * 对于内存受限环境可适当减小。默认值 256KB 用于抵消高延迟
     * 网络的影响。
     * @note 对于高延迟高带宽环境建议增大此值，对于内存受限
     * 环境可减小此值。
     */
    struct buffer
    {
        // 传输缓冲区大小（字节），默认 256KB
        std::uint32_t size = 262144U;
    };

    /**
     * @struct config
     * @brief 代理服务全局配置
     * @details 聚合所有子模块配置，作为代理服务的完整配置入口。
     * 该结构用于初始化 worker、account::directory 和 resolve::router。
     * 涵盖连接限制、正向代理、监听端点、TLS 证书、身份认证、
     * 伪装路径、反向代理路由、连接池、缓冲区以及协议配置等。
     * @note 所有配置字段均使用 PMR 容器，支持自定义内存分配器。
     * @warning 配置对象应在服务启动前完成初始化，运行时修改
     * 可能不会立即生效。
     */
    struct config
    {
        // 连接限制配置，控制并发数和黑名单
        struct limit limit;

        // 正向代理端点，定义上游代理服务器
        endpoint positive;

        // 监听端点，定义服务监听的地址和端口
        endpoint addressable;

        // SSL/TLS 证书配置
        struct certificate certificate;

        // 身份认证配置，管理用户凭据和连接限制
        struct authentication authentication;

        // 伪装路径，用于抗探测
        memory::string camouflage;

        // 反向代理路由表，键为主机名，值为后端端点
        memory::map<memory::string, endpoint> reverse_map;

        // 连接池配置，控制连接缓存和空闲超时
        struct pool_config pool;

        // 缓冲区配置，控制数据转发缓冲区大小
        struct buffer buffer;

        // Clash 兼容模式，启用后支持 Clash 客户端特性
        bool clash = false;

        // SOCKS5 协议配置，控制能力开关和 UDP relay 参数
        protocol::socks5::config socks5;

        // Trojan 协议配置，控制能力开关和 UDP 参数
        protocol::trojan::config trojan;
    };
}
