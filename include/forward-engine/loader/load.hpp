/**
 * @file load.hpp
 * @brief 配置加载适配器
 * @details 负责将外部配置格式（如 JSON）转换为内部的
 * core::configuration 结构。该模块充当外部世界与核心配置之间的
 * 防腐层，确保核心配置结构不受外部格式变化的影响。设计原理
 * 采用防腐层模式隔离外部配置格式与内部配置结构，遵循单一职责
 * 原则仅负责配置加载和格式转换，并通过错误隔离机制确保外部格式
 * 错误不会影响核心配置结构。内存管理方面使用 PMR 内存管理减少
 * 堆分配开销。当前支持通过 glaze 库解析 JSON 格式配置文件，未来
 * 可扩展支持 YAML、TOML 等格式。典型使用场景包括系统启动时加载
 * 服务器配置文件、运行时配置热重载以及配置文件有效性验证。
 * @note 配置文件必须是有效的 JSON 格式
 * @warning 配置文件加载失败将返回空配置对象
 */
#pragma once
#include <string>
#include <fstream>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/exception.hpp>
#include <forward-engine/transformer.hpp>

/**
 * @namespace ngx::loader
 * @brief 配置适配层
 * @details 负责将外部配置格式（如 YAML、JSON、Clash 配置）转换为
 * 内部的 agent::config 结构。充当外部世界与核心配置之间的防腐层，
 * 确保核心配置结构不受外部格式变化的影响。核心职责包括从文件系统
 * 加载配置文件、将外部格式转换为内部配置结构、处理配置加载和解析
 * 过程中的错误，以及使用 PMR 内存管理减少堆分配开销。
 * @note 该命名空间是配置系统的入口点，所有配置加载都应通过此命名空间进行
 * @warning 配置加载失败将返回空配置对象，调用者应检查配置有效性
 */
namespace ngx::loader
{
    /**
     * @brief 加载外部配置
     * @param path 配置文件路径，支持相对路径和绝对路径
     * @return core::configuration 转换后的配置对象，加载失败时返回空对象
     * @throws exception::security 如果文件打开失败
     * @details 从文件系统加载配置文件，解析 JSON 格式并转换为内部的
     * core::configuration 结构。该函数是配置加载的主入口点。加载流程
     * 首先以二进制模式打开配置文件，然后读取文件全部内容到内存，接着
     * 使用 glaze 库解析 JSON 内容，最后将解析结果转换为 core::configuration
     * 结构。错误处理方面，文件打开失败时抛出 exception::security 异常，
     * JSON 解析失败或格式不匹配时返回空配置对象。
     * @note 配置文件必须是有效的 JSON 格式，且符合 core::configuration 的结构定义
     * @warning 返回空配置对象可能表示加载失败，调用者应检查配置有效性
     */
    inline auto load(const std::string_view path)
        -> core::configuration
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
