/**
 * @file load.hpp
 * @brief 配置加载适配器
 * @details 负责将外部配置格式（如 JSON）转换为内部的 psm::config 结构。
 * 该模块充当外部世界与核心配置之间的防腐层，确保核心配置结构不受
 * 外部格式变化的影响。当前支持通过 glaze 库解析 JSON 格式配置文件，
 * 未来可扩展支持 YAML、TOML 等格式。
 * @note 配置文件必须是有效的 JSON 格式
 * @warning 配置文件加载失败将返回空配置对象
 */
#pragma once
#include <string>
#include <fstream>
#include <prism/config.hpp>
#include <prism/exception.hpp>
#include <prism/transformer.hpp>

/**
 * @namespace psm::loader
 * @brief 配置适配层
 * @details 负责将外部配置格式（如 YAML、JSON、Clash 配置）转换为
 * 内部的 psm::config 结构。充当外部世界与核心配置之间的防腐层，
 * 确保核心配置结构不受外部格式变化的影响。
 */
namespace psm::loader
{
    /**
     * @brief 加载外部配置
     * @param path 配置文件路径，支持相对路径和绝对路径
     * @return psm::config 转换后的配置对象，加载失败时返回空对象
     * @throws exception::security 如果文件打开失败
     * @details 从文件系统加载配置文件，解析 JSON 格式并转换为
     * 内部的 psm::config 结构。
     * @note 配置文件必须是有效的 JSON 格式，且符合 psm::config 的结构定义
     */
    inline auto load(const std::string_view path)
        -> config
    {
        std::ifstream file(path.data(), std::ios::binary);
        if (!file.is_open())
        {
            throw exception::security("system error : {}", "file open failed");
        }
        file.seekg(0, std::ios::end);
        const auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        memory::string content(size, '\0');
        file.read(content.data(), size);


        config cfg;
        try
        {
            if (transformer::json::deserialize({content.data(), content.size()}, cfg))
            {
                return cfg;
            }
        }
        catch (...)
        {
        }
        return {};
    }
}
