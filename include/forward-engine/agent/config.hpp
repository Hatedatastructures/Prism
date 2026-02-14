/**
 * @file config.hpp
 * @brief 代理服务配置定义
 * @details 定义了代理服务所需的各种配置结构，包括端点、限制、证书、认证、连接池等核心配置项。
 * 这些配置结构用于初始化 `worker` 和 `validator`，控制代理服务的运行时行为。
 *
 * 配置层次：
 * - 1. 网络端点 (`endpoint`)：定义主机名和端口；
 * - 2. 连接限制 (`limit`)：控制并发连接和黑名单；
 * - 3. 证书配置 (`certificate`)：`TLS` 证书和私钥路径；
 * - 4. 身份认证 (`authentication`)：用户凭据和连接数限制；
 * - 5. 连接池 (`pool_config`)：连接缓存和空闲超时；
 * - 6. 全局配置 (`config`)：聚合所有子配置，作为服务入口点。
 *
 * @note 所有配置结构使用 `memory::string` 和 `memory::vector` 等 `PMR` 容器，支持自定义内存分配。
 * @warning 配置对象应在服务启动前完成初始化，运行时修改可能不会立即生效。
 *
 * ```
 * // 初始化 worker
 * ngx::agent::worker wkr(cfg);
 * ```
 */
#pragma once

#include <forward-engine/memory/container.hpp>

namespace ngx::agent
{
    /**
     * @struct endpoint
     * @brief 端点配置
     * @details 表示一个网络端点，包含主机名和端口号。用于定义监听地址、正向代理目标、反向代理后端等。
     *
     * 字段说明：
     * @details - `host`：主机名，可以是域名（如 "example.com"）或 `IP` 地址（如 "192.168.1.1"）；
     * @details - `port`：端口号，范围 1–65535，0 表示未设置。
     *
     * @note 主机名使用 `memory::string` 存储，支持 `PMR` 内存分配。
     * @warning 端口号 0 是无效的，在验证配置时应检查端口是否已设置。
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
     * @struct limit
     * @brief 连接限制配置
     * @details 控制代理服务的并发连接数和黑名单策略。用于防止资源耗尽和恶意请求。
     *
     * 字段说明：
     * @details - `concurrences`：最大并发连接数，默认 20，0 表示无限制；
     * @details - `blacklist`：是否启用黑名单，默认启用，启用后根据内部规则拦截可疑 `IP`。
     *
     * @note 并发连接数限制是全局性的，作用于所有工作线程。
     * @warning 设置过小的并发数可能导致服务拒绝合法连接，应根据服务器资源调整。
     *
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
     * @struct certificate
     * @brief SSL/TLS 证书配置
     * @details 包含 `TLS` 加密所需的私钥和证书文件路径。用于配置 `SSL` 上下文，支持 `HTTPS` 和 `TLS` 协议。
     *
     * 字段说明：
     * @details - `key`：私钥文件路径（`PEM` 格式），用于 `TLS` 握手签名；
     * @details - `cert`：证书文件路径（`PEM` 格式），包含公钥和证书链。
     *
     * @note 文件路径使用 `memory::string` 存储，支持 `PMR` 内存分配。
     * @warning 文件路径必须可读，否则 `SSL` 上下文初始化会失败。
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
     * @struct authentication
     * @brief 身份认证配置
     * @details 管理客户端身份验证的凭据和用户限制。支持两种模式：
     * 1. **简单凭据列表** (`credentials`)：仅校验凭据是否存在，无独立限制；
     * 2. **用户列表** (`users`)：为每个用户配置独立的最大并发连接数。
     *
     * 字段说明：
     * @details - `credentials`：凭据列表，每个元素是一个 `SHA224` 哈希字符串；
     * @details - `users`：用户列表，每个用户包含凭据和连接数限制。
     *
     * @note 凭据通常是密码的 `SHA224` 哈希，由客户端在握手时提供。
     * @warning 如果同时使用 `credentials` 和 `users`，`validator` 会优先检查 `users`。
     */
    struct authentication
    {
        /**
         * @struct user
         * @brief 用户配置
         * @details 表示一个独立用户，包含凭据和可选的连接数限制。用于精细化的连接控制。
         *
         * 字段说明：
         * @details - `credential`：用户凭据，`SHA224` 哈希字符串；
         * @details - `max_connections`：最大并发连接数，0 表示无限制。
         *
         * @note 用户凭据在 `validator` 中用于查找和配额控制。
         * @warning 如果 `max_connections` 设为 0，该用户将不受并发数限制。
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
     * @struct pool_config
     * @brief 连接池配置
     * @details 控制连接池的行为参数，包括缓存大小和空闲超时。用于优化连接复用和资源管理。
     *
     * 字段说明：
     * @details - `max_cache_per_endpoint`：单个目标端点最大缓存连接数，默认 32，防止内存爆炸；
     * @details - `max_idle_seconds`：空闲连接最大存活时间（秒），默认 60 秒，超时后连接被销毁。
     *
     * @note 连接池缓存 `TCP` 连接，避免频繁的三次握手，提升性能。
     * @warning 设置过大的缓存数可能导致内存压力，应根据实际并发连接数调整。

     */
    struct pool_config
    {
        /**
         * @brief 单个目标端点最大缓存连接数
         * @details 默认值为 32。防止内存爆炸。
         */
        std::uint32_t max_cache_per_endpoint = 32U;

        /**
         * @brief 空闲连接最大存活时间（秒）
         * @details 默认值为 60 秒。超过此时间的空闲连接将被销毁。
         */
        std::uint64_t max_idle_seconds = 60ULL;
    };

    /**
     * @struct config
     * @brief 代理服务全局配置
     * @details 聚合所有子模块配置，作为代理服务的完整配置入口。该结构用于初始化 `worker`、`validator` 和 `distributor`。
     *
     * 配置项说明：
     * @details - `limit`：连接限制配置，控制并发数和黑名单；
     * @details - `positive`：正向代理端点，定义上游代理服务器（可选）；
     * @details - `addressable`：监听端点，定义服务监听的地址和端口；
     * @details - `certificate`：`TLS` 证书配置，用于 `HTTPS` 和 `TLS` 协议；
     * @details - `authentication`：身份认证配置，管理用户凭据和连接限制；
     * @details - `camouflage`：伪装路径，用于抗探测，将代理流量伪装成普通 `HTTP` 请求；
     * @details - `reverse_map`：反向代理路由表，映射主机名到后端端点；
     * @details - `pool`：连接池配置，控制连接缓存和空闲超时；
     * @details - `clash`：`Clash` 兼容模式，启用后支持 `Clash` 客户端特性。
     *
     * @note 所有配置字段均使用 `PMR` 容器，支持自定义内存分配器。
     * @warning 配置对象应在服务启动前完成初始化，运行时修改可能不会立即生效。
     *
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
         * @brief 连接池配置
         * @details 控制连接池的行为参数。
         */
        struct pool_config pool;

        /**
         * @brief Clash 兼容模式
         * @details 是否启用 Clash 客户端兼容特性。
         */
        bool clash = false;
    };
}
