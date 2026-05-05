/**
 * @file registry.hpp
 * @brief 伪装方案注册表
 * @details 单例模式，管理所有 stealth_scheme 的注册和查询。
 * 启动阶段通过 register_all_schemes() 手动注册所有方案，
 * 运行时只读，无需同步。
 */

#pragma once

#include <vector>
#include <string_view>
#include <prism/stealth/scheme.hpp>

namespace psm::stealth
{
    /**
     * @class scheme_registry
     * @brief 伪装方案注册表（单例）
     * @details 管理所有 stealth_scheme 的注册和查询。
     * 启动时通过 register_all_schemes() 注册所有方案，
     * 运行时由 recognition 模块查询和使用。
     *
     * **使用流程**：
     * 1. 启动阶段调用 register_all_schemes()
     * 2. recognition 调用 scheme_registry::instance().all() 获取所有方案
     * 3. 对每个方案调用 detect() 获取候选列表
     * 4. 通过 scheme_executor 执行候选方案
     */
    class scheme_registry
    {
    public:
        /**
         * @brief 获取全局单例
         * @return scheme_registry 引用
         */
        static auto instance() -> scheme_registry &;

        /**
         * @brief 注册方案
         * @param scheme 方案实例
         * @details 启动阶段调用，运行时不再修改。
         */
        auto add(shared_scheme scheme) -> void;

        /**
         * @brief 获取所有已注册的方案
         * @return 方案列表（按注册顺序 = 默认优先级）
         */
        [[nodiscard]] auto all() const -> const std::vector<shared_scheme> &;

        /**
         * @brief 按名称查找方案
         * @param name 方案名称
         * @return 方案实例，未找到返回 nullptr
         */
        [[nodiscard]] auto find(std::string_view name) const -> shared_scheme;

    private:
        std::vector<shared_scheme> schemes_;
    };

    /**
     * @brief 注册所有伪装方案
     * @details 在 main() 或启动阶段调用，注册 reality/shadowtls/restls/native。
     * 新增方案只需在此函数中添加一行。
     */
    auto register_all_schemes() -> void;

} // namespace psm::stealth
