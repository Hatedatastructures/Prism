/**
 * @file config.hpp
 * @brief Agent 运行时配置类型定义
 * @details 声明代理服务的配置模型，涵盖工作线程启动、
 * 账户状态管理、路由策略、监听端点、TLS 证书以及协议
 * 管道行为等核心配置项。所有配置结构均采用 PMR 内存
 * 分配器，支持高性能内存管理。
 */
#pragma once

#include <prism/memory/container.hpp>
#include <prism/protocol/socks5/config.hpp>
#include <prism/protocol/trojan/config.hpp>
#include <prism/protocol/vless/config.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/stealth/restls/config.hpp>

namespace psm::agent
{
    /**
     * @struct endpoint
     * @brief 网络端点配置
     * @details 表示一个网络端点，包含主机名和端口号。
     * 用于定义监听地址、正向代理目标、反向代理后端等
     * 场景。主机名支持域名和 IP 地址两种格式，端口号
     * 范围为 1 至 65535。
     * @note 主机名使用 memory::string 存储，支持 PMR
     * 内存分配。
     * @warning 端口号 0 表示未设置，配置验证时应检查
     * 端口有效性。
     */
    struct endpoint
    {
        memory::string host;    // 主机名，可以是域名或 IP 地址
        std::uint16_t port = 0; // 端口号，范围 1-65535，0 表示未设置
    }; // struct endpoint

    /**
     * @struct limit
     * @brief 连接限制配置
     * @details 控制代理服务的并发连接数和黑名单策略，
     * 用于防止资源耗尽和恶意请求攻击。并发限制作用于
     * 全局所有工作线程，黑名单功能可根据内部规则拦截
     * 可疑 IP 地址。
     * @note 并发连接数限制是全局性的，作用于所有工作
     * 线程。
     * @warning 设置过小的并发数可能导致服务拒绝合法
     * 连接，应根据服务器资源合理调整。
     */
    struct limit
    {
        bool blacklist = true; // 是否启用黑名单，默认启用
    }; // struct limit

    /**
     * @struct certificate
     * @brief SSL/TLS 证书配置
     * @details 包含 TLS 加密所需的私钥和证书文件路径，
     * 用于配置 SSL 上下文以支持 HTTPS 和 TLS 协议。
     * 文件格式要求为 PEM，私钥用于 TLS 握手签名，
     * 证书包含公钥和证书链信息。
     * @note 文件路径使用 memory::string 存储，支持 PMR
     * 内存分配。
     * @warning 文件路径必须可读，否则 SSL 上下文初始化
     * 会失败。
     */
    struct certificate
    {
        memory::string key;  // 私钥文件路径，PEM 格式
        memory::string cert; // 证书文件路径，PEM 格式
    }; // struct certificate

    /**
     * @struct authentication
     * @brief 身份认证配置
     * @details 管理客户端身份验证的凭据和用户限制。
     * 用户列表模式可为每个用户配置独立的最大并发连接数。
     * 凭据通常为密码的 SHA224 哈希值，由客户端在握手
     * 阶段提供。
     * @note 凭据通常是密码的 SHA224 哈希，由客户端在
     * 握手时提供。
     * @warning 如果同时配置 credentials 和 users，
     * account::directory 会优先检查 users 列表。
     */
    struct authentication
    {
        /**
         * @struct user
         * @brief 统一用户配置
         * @details 表示一个独立用户，可同时配置密码和 UUID
         * 两种认证方式。password 用于 Trojan/HTTP/SOCKS5
         * 协议，启动时自动转换为 SHA224 哈希注册到
         * account::directory。uuid 用于 VLESS 协议，直接
         * 注册到 account::directory。两种凭证共享同一个
         * entry，从而共享连接数配额。两个字段均为可选，
         * 但至少一个非空才有效。
         * @warning 如果 max_connections 设为 0，该用户
         * 不受并发数限制。
         */
        struct user
        {
            memory::string password;           // 密码认证，用于 Trojan/HTTP/SOCKS5
            memory::string uuid;               // VLESS UUID 字符串
            std::uint32_t max_connections = 0; // 最大并发连接数，0 表示无限制
        }; // struct user

        memory::vector<user> users; // 统一用户列表
    }; // struct authentication

    /**
     * @struct buffer
     * @brief 缓冲区配置
     * @details 控制数据传输时的缓冲区大小。合理的缓冲区
     * 大小可以平衡内存占用和吞吐量。对于高延迟高带宽
     * 环境建议增大此值，对于内存受限环境可适当减小。
     * 默认值 256KB 用于抵消高延迟网络的影响。
     */
    struct buffer
    {
        std::uint32_t size = 262144U; // 传输缓冲区大小（字节），默认 256KB
    }; // struct buffer

    /**
     * @namespace protocol
     * @brief 协议配置聚合
     * @details 聚合所有代理协议的配置项，包括 SOCKS5、
     * Trojan、VLESS 和 Shadowsocks。每个协议配置
     * 独立定义能力开关和运行时参数。
     */
    namespace protocol
    {
        struct config
        {
            psm::protocol::socks5::config socks5;
            psm::protocol::trojan::config trojan;
            psm::protocol::vless::config vless;
            psm::protocol::shadowsocks::config shadowsocks;
        };
    }

    /**
     * @namespace stealth
     * @brief 伪装配置聚合
     * @details 聚合 Reality TLS 伪装和 ShadowTLS 伪装的
     * 配置项。每个伪装方案独立定义其参数和行为。
     */
    namespace stealth
    {
        struct config
        {
            psm::stealth::reality::config reality;
            psm::stealth::shadowtls::config shadowtls;
            psm::stealth::restls::config restls;
        };
    }

    /**
     * @struct config
     * @brief 代理服务核心配置
     * @details 仅包含 agent 模块专属的配置项：连接限制、
     * 正向代理、监听端点、TLS 证书、身份认证、伪装路径、
     * 反向代理路由。其他模块配置（pool、buffer、protocol、
     * mux、dns、stealth）已移至顶层 psm::config。
     * @warning 配置对象应在服务启动前完成初始化，运行时
     * 修改可能不会立即生效。
     */
    struct config
    {
        limit limit;                                       // 连接限制配置
        endpoint positive;                                 // 正向代理端点
        endpoint addressable;                              // 监听端点
        certificate certificate;                           // SSL/TLS 证书配置
        authentication authentication;                     // 身份认证配置
        memory::string camouflage;                         // 伪装路径，用于抗探测
        memory::map<memory::string, endpoint> reverse_map; // 反向代理路由表
    }; // struct config
} // namespace psm::agent

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::agent::endpoint>
{
    using T = psm::agent::endpoint;
    static constexpr auto value = glz::object("host", &T::host, "port", &T::port);
};

template <>
struct glz::meta<psm::agent::limit>
{
    using T = psm::agent::limit;
    static constexpr auto value = glz::object("blacklist", &T::blacklist);
};

template <>
struct glz::meta<psm::agent::certificate>
{
    using T = psm::agent::certificate;
    static constexpr auto value = glz::object("key", &T::key, "cert", &T::cert);
};

template <>
struct glz::meta<psm::agent::authentication::user>
{
    using T = psm::agent::authentication::user;
    static constexpr auto value = glz::object(
        "password", &T::password, "uuid", &T::uuid, "max_connections", &T::max_connections);
};

template <>
struct glz::meta<psm::agent::authentication>
{
    using T = psm::agent::authentication;
    static constexpr auto value = glz::object("users", &T::users);
};

template <>
struct glz::meta<psm::agent::buffer>
{
    using T = psm::agent::buffer;
    static constexpr auto value = glz::object("size", &T::size);
};

template <>
struct glz::meta<psm::agent::protocol::config>
{
    using T = psm::agent::protocol::config;
    static constexpr auto value = glz::object(
        "socks5",       &T::socks5,
        "trojan",       &T::trojan,
        "vless",        &T::vless,
        "shadowsocks",  &T::shadowsocks);
};

template <>
struct glz::meta<psm::agent::stealth::config>
{
    using T = psm::agent::stealth::config;
    static constexpr auto value = glz::object(
        "reality",      &T::reality,
        "shadowtls",    &T::shadowtls,
        "restls",       &T::restls);
};

template <>
struct glz::meta<psm::agent::config>
{
    using T = psm::agent::config;
    static constexpr auto value = glz::object(
        "limit",           &T::limit,
        "positive",        &T::positive,
        "addressable",     &T::addressable,
        "certificate",     &T::certificate,
        "authentication",  &T::authentication,
        "camouflage",      &T::camouflage,
        "reverse_map",     &T::reverse_map);
};
