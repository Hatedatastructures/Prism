#pragma once
#include <string>
#include <forward-engine/agent/config.hpp>

namespace ngx::adapter
{
    /**
     * @brief 加载外部配置
     * @details 解析外部配置文件（如 YAML/JSON），并转换为内部的 config 结构。
     * @param path 配置文件路径
     * @return agent::config 转换后的配置对象
     */
    inline agent::config load(const std::string& path)
    {
        // TODO: 实现具体的解析逻辑 (例如适配 Clash 配置文件)
        agent::config cfg;
        return cfg;
    }
}
