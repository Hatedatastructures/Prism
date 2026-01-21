#pragma once

#include <cstdint>
#include <memory/container.hpp>

namespace ngx::agent
{
    /**
     * @brief 端点配置
     * @details 包含主机名和端口号
     */
    struct endpoint
    {
        ngx::memory::string host;
        std::uint16_t port = 0;
    };

    struct limit
    {
        std::uint32_t concurrences = 20U;
        bool blacklist = true;
    };

    /**
     * @brief 证书配置
     * @details 包含证书文件路径和密钥文件路径
     */
    struct certificate
    {
        ngx::memory::string key;
        ngx::memory::string cert;
    };

    /**
     * @brief 认证配置
     * @details 包含用于验证客户端身份的密码哈希列表 (SHA224)
     */
    struct authentication
    {
        ngx::memory::vector<ngx::memory::string> passwords;
    };

    /**
     * @brief 代理配置
     * @details 包含限制配置、正面端点配置、可寻址端点配置、证书配置、伪装路径和是否启用Clash模式
     */
    struct config
    {
        limit limit;
        endpoint positive;
        endpoint addressable;
        certificate certificate;
        authentication authentication;
        ngx::memory::string camouflage;
        bool clash = false;
    };
}
