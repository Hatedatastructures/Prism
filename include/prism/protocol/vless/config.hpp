/**
 * @file config.hpp
 * @brief VLESS 协议配置结构
 * @details 定义 VLESS 协议的配置参数，包括允许连接的用户 UUID 列表。
 * 配置结构由 agent::config 持有，随服务启动时初始化。
 */

#pragma once

#include <vector>
#include <string>
#include <array>
#include <cstdint>

namespace psm::protocol::vless
{
    /**
     * @struct config
     * @brief VLESS 协议配置
     * @details 控制 VLESS 协议的用户认证。users 列表包含允许连接的
     * UUID 字符串（标准格式 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"）。
     */
    struct config
    {
        // 允许连接的用户 UUID 列表
        std::vector<std::string> users;
    };
}
