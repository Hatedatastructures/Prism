/**
 * @file config.hpp
 * @brief 代理服务配置定义
 * @details 定义了代理服务所需的各种配置结构，包括端点、限制、证书和认证信息。
 */
#pragma once

#include <forward-engine/memory/container.hpp>

namespace ngx::agent
{
    /**
     * @brief 端点配置
     * @details 包含网络连接的主机名和端口号信息。
     */
    struct endpoint
    {
        /**
         * @brief 主机名
         * @details 可以是域名或 IP 地址。
         */
        memory::string host;    

        /**
         * @brief 端口号
         * @details 监听或连接的目标端口。
         */
        std::uint16_t port = 0;
    };

    /**
     * @brief 连接限制配置
     * @details 控制并发连接数和黑名单策略。
     */
    struct limit
    {
        /**
         * @brief 最大并发连接数
         * @details 默认值为 20。超过限制的连接可能会被拒绝或排队。
         */
        std::uint32_t concurrences = 20U;

        /**
         * @brief 是否启用黑名单
         * @details 默认启用。启用后将根据黑名单规则拦截请求。
         */
        bool blacklist = true;
    };

    /**
     * @brief SSL/TLS 证书配置
     * @details 包含证书文件和私钥文件的路径信息。
     */
    struct certificate
    {
        /**
         * @brief 私钥文件路径
         * @details 支持 PEM 格式。
         */
        memory::string key;

        /**
         * @brief 证书文件路径
         * @details 支持 PEM 格式。
         */
        memory::string cert;
    };

    /**
     * @brief 身份认证配置
     * @details 包含用于验证客户端身份的凭据信息。
     */
    struct authentication
    {
        /**
         * @brief 用户配置
         * @details 以 `credential` 为用户唯一标识，携带可选的连接数限制。
         */
        struct user
        {
            /**
             * @brief 用户凭据
             * @details 用于身份校验的凭据（如密码哈希、令牌等）。
             */
            memory::string credential;

            /**
             * @brief 最大并发连接数
             * @details 0 表示不限制。
             */
            std::uint32_t max_connections = 0;
        };

        /**
         * @brief 凭据列表
         * @details 存储允许通过验证的凭据（通常为 SHA224 密码哈希）。
         */
        memory::vector<memory::string> credentials;

        /**
         * @brief 用户列表
         * @details 与 `credentials` 等价但更可扩展，支持为单个用户配置独立限制。
         */
        memory::vector<user> users;
    };

    /**
     * @brief 代理服务全局配置
     * @details 聚合了所有子模块的配置项，用于初始化 `worker`。
     */
    struct config
    {
        /**
         * @brief 连接限制配置
         */
        struct limit limit;

        /**
         * @brief 正向代理端点配置
         * @details 定义正向代理的目标服务器（如果有）。
         */
        endpoint positive;

        /**
         * @brief 监听端点配置
         * @details 定义代理服务监听的地址和端口。
         */
        endpoint addressable;

        /**
         * @brief SSL/TLS 证书配置
         */
        struct certificate certificate;

        /**
         * @brief 身份认证配置
         */
        struct authentication authentication;

        /**
         * @brief 伪装路径
         * @details 用于抗探测，非标准路径的请求可能被伪装成普通网页访问。
         */
        memory::string camouflage;

        /**
         * @brief 反向代理路由表
         * @details 键为主机名 (Host)，值为后端端点。
         */
        memory::map<memory::string, endpoint> reverse_map;

        /**
         * @brief Clash 兼容模式
         * @details 是否启用 Clash 客户端兼容特性。
         */
        bool clash = false;
    };
}
