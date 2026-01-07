#pragma once

#include <string>
#include <cstdint>

namespace ngx::agent
{
    /**
     * @brief  agent 模块配置信息
     */
    struct config
    {
        std::uint16_t port = 8080;
        std::string cert_path;
        std::string key_path;
        bool clash = false;
    };
}