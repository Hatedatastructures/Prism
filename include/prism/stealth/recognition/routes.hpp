/**
 * @file routes.hpp
 * @brief SNI 路由表
 * @details 根据 ClientHello SNI 快速路由到对应伪装方案。
 * 从配置构建，启动时初始化，支持多方案共享同一 SNI（返回多个候选）。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <string_view>


namespace psm
{

    struct config;
}

namespace psm::recognition
{

    /**
     * @class route_table
     * @brief SNI 路由表
     * @details 从各伪装方案的 server_names 配置构建路由表，
     * 实现 SNI → 方案名称的快速映射。
     *
     * 路由规则：
     * Reality server_names → "reality"
     * ShadowTLS server_names → "shadowtls"
     * Restls server_names → "restls"
     * 未匹配任何 SNI → 返回空列表（后续 fallback 到 native）
     *
     * 多方案共享 SNI：
     * 同一 SNI 可配置在多个方案中，返回多个候选
     * 例如："example.com" 同时配置在 reality 和 shadowtls
     * 执行时按优先级顺序尝试
     */
    class route_table
    {
    public:
        /**
         * @brief 从配置构建路由表
         * @param cfg 全局配置
         * @return 构建完成的路由表
         * @details 遍历所有 stealth 方案的 server_names，
         * 构建 SNI → 方案名称的映射。
         */
        [[nodiscard]] static auto build(const psm::config &cfg)
            -> route_table;

        /**
         * @brief 根据 SNI 查找匹配方案
         * @param sni ClientHello 中的 SNI
         * @return 匹配的方案名称列表（通常只有一个）
         * @details 空字符串 sni 返回空列表。
         */
        [[nodiscard]] auto lookup(std::string_view sni) const
            -> memory::vector<memory::string>;

        /**
         * @brief 检查 SNI 是否匹配任意方案
         * @param sni ClientHello 中的 SNI
         * @return 是否匹配至少一个方案
         */
        [[nodiscard]] auto matches_any(std::string_view sni) const
            -> bool;

        /**
         * @brief 获取所有已注册的 SNI 列表
         * @return SNI 列表（用于调试）
         */
        [[nodiscard]] auto registered_snis() const
            -> memory::vector<memory::string>;

        /**
         * @brief 检查路由表是否为空
         * @return 无任何 SNI 注册时返回 true
         */
        [[nodiscard]] auto empty() const noexcept
            -> bool;

    private:
        /// SNI → 方案名称列表映射
        memory::map<memory::string, memory::vector<memory::string>> route_map_;

        /**
         * @brief 添加单个 SNI → 方案映射
         * @param sni SNI 值
         * @param scheme_name 方案名称
         */
        void add_route(std::string_view sni, std::string_view scheme_name);
    };
} // namespace psm::recognition
