#pragma once
#include <string>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/transformer.hpp>

/**
 * @namespace ngx::adapter
 * @brief 配置适配层
 * @details 负责将外部配置格式 (如 YAML, JSON, Clash 配置) 转换为内部的 `agent::config` 结构。
 * 充当外部世界与核心配置之间的防腐层。
 */
namespace ngx::adapter
{
    /**
     * @brief 加载外部配置
     * @details 解析外部配置文件，并转换为内部的 config 结构。
     * @param path 配置文件路径
     * @return core::configuration 转换后的配置对象
     */
    inline auto load(const std::string_view path)
        -> core::configuration
    {
        std::ifstream file(path.data(), std::ios::binary);
        if (!file.is_open())
        {
            throw ngx::abnormal::security("system error : {}", "file open failed");
        }
        file.seekg(0, std::ios::end);
        const auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        memory::string content(size, '\0');
        file.read(content.data(), size);


        core::configuration config;
        try
        {
            if (transformer::json::deserialize({content.data(), content.size()}, config))
            {
                return config;
            }
        }
        catch (...)
        {
        }
        return {};
    }
}
