/**
 * @file load.hpp
 * @brief 配置加载适配器
 * @details 负责将外部配置格式（如 JSON）转换为内部的 `core::configuration` 结构。该模块充当外部世界与核心配置之间的防腐层，确保核心配置结构不受外部格式变化的影响。
 *
 * 设计原理：
 * @details - 防腐层模式：隔离外部配置格式与内部配置结构；
 * @details - 单一职责：仅负责配置加载和格式转换；
 * @details - 错误隔离：外部格式错误不会影响核心配置结构；
 * @details - 内存高效：使用 PMR 内存管理减少堆分配。
 *
 * 支持的配置格式：
 * @details - JSON：通过 glaze 库解析 JSON 格式配置文件；
 * @details - 未来扩展：可扩展支持 YAML、TOML 等格式。
 *
 * 使用场景：
 * @details - 系统启动：加载服务器配置文件；
 * @details - 配置热重载：运行时重新加载配置；
 * @details - 配置验证：验证配置文件的正确性。
 *
 * @note 配置文件必须是有效的 JSON 格式。
 * @warning 配置文件加载失败将返回空配置对象。
 */
#pragma once
#include <string>
#include <fstream>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/transformer.hpp>

/**
 * @namespace ngx::adapter
 * @brief 配置适配层
 * @details 负责将外部配置格式（如 YAML, JSON, Clash 配置）转换为内部的 `agent::config` 结构。充当外部世界与核心配置之间的防腐层，确保核心配置结构不受外部格式变化的影响。
 *
 * 核心职责：
 * @details - 配置加载：从文件系统加载配置文件；
 * @details - 格式转换：将外部格式转换为内部配置结构；
 * @details - 错误处理：处理配置加载和解析过程中的错误；
 * @details - 内存管理：使用 PMR 内存管理减少堆分配。
 *
 * @note 该命名空间是配置系统的入口点，所有配置加载都应通过此命名空间进行。
 * @warning 配置加载失败将返回空配置对象，调用者应检查配置有效性。
 */
namespace ngx::adapter
{
    /**
     * @brief 加载外部配置
     * @details 从文件系统加载配置文件，解析 JSON 格式并转换为内部的 `core::configuration` 结构。该函数是配置加载的主入口点。
     *
     * 加载流程：
     * @details - 文件打开：以二进制模式打开配置文件；
     * @details - 内容读取：读取文件全部内容到内存；
     * @details - JSON 解析：使用 glaze 库解析 JSON 内容；
     * @details - 配置转换：将解析结果转换为 `core::configuration` 结构。
     *
     * 错误处理：
     * @details - 文件打开失败：抛出 `abnormal::security` 异常；
     * @details - JSON 解析失败：返回空配置对象；
     * @details - 格式不匹配：返回空配置对象。
     *
     * @param path 配置文件路径（支持相对路径和绝对路径）
     * @return `core::configuration` 转换后的配置对象，加载失败时返回空对象
     * @throws `abnormal::security` 如果文件打开失败
     * @note 配置文件必须是有效的 JSON 格式，且符合 `core::configuration` 的结构定义。
     * @warning 返回空配置对象可能表示加载失败，调用者应检查配置有效性。
     */
    inline auto load(const std::string_view path)
        -> core::configuration
    {
        std::ifstream file(path.data(), std::ios::binary);
        if (!file.is_open())
        {
            throw abnormal::security("system error : {}", "file open failed");
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
