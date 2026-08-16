/**
 * @file api_manager.hpp
 * @brief 管理 API 接口与骨架（T5-8 O7）
 * @details 资源树契约 + api_manager 接口：
 *          - 会话列表（快照式，无 L3 引用）
 *          - 流量摘要
 *          - 配置快照（JSON 文本）
 * @note 接口可 mock；独立 ioc 的执行骨架由调用方持有
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <common/core/runtime/per_worker_traffic.hpp>
#include <common/core/runtime/session_registry.hpp>

namespace psmtest::api
{

    /**
     * @struct resource_node
     * @brief 资源树节点（契约）
     */
    struct resource_node
    {
        std::string name{};    ///< 资源名（如 "session"）
        std::uint64_t id{0};   ///< 资源 id（会话 id 等）
        std::string detail{};  ///< 详情（地址/目标等）
        std::uint64_t value{0}; ///< 数值（流量字节等）
    };

    /**
     * @class api_manager
     * @brief 管理 API 接口
     * @details 会话列表 / 流量摘要 / 配置快照。
     *          所有返回均为值拷贝（快照），严禁外部引用内部状态。
     */
    class api_manager
    {
    public:
        virtual ~api_manager() = default;

        /**
         * @brief 会话列表快照
         */
        [[nodiscard]] virtual auto list_sessions() const -> std::vector<resource_node> = 0;

        /**
         * @brief 流量摘要（up/down 聚合）
         */
        [[nodiscard]] virtual auto traffic_summary() const -> psmtest::runtime::traffic_pod = 0;

        /**
         * @brief 配置快照（JSON 文本）
         */
        [[nodiscard]] virtual auto config_snapshot() const -> std::string = 0;
    };

    /**
     * @class registry_api_manager
     * @brief 基于注册表 + 统计的实现
     * @details 组合 session_registry 与流量聚合器，提供值快照 API。
     */
    class registry_api_manager final : public api_manager
    {
    public:
        /**
         * @brief 构造
         * @param registry 会话注册表（非拥有）
         * @param traffic 流量聚合器（非拥有）
         */
        registry_api_manager(const psmtest::runtime::session_registry *registry,
                             const psmtest::runtime::per_worker_traffic *traffic,
                             const psmtest::runtime::identity_traffic *identity = nullptr)
            : registry_(registry), traffic_(traffic), identity_(identity)
        {
        }

        /**
         * @brief 会话列表快照（值拷贝）
         */
        [[nodiscard]] auto list_sessions() const -> std::vector<resource_node> override
        {
            std::vector<resource_node> out;
            if (!registry_)
            {
                return out;
            }
            const auto snap = registry_->snapshot();
            for (const auto &[id, info] : *snap)
            {
                resource_node node;
                node.name = "session";
                node.id = id;
                node.detail = info.peer + " -> " + info.target + " [" + info.identity + "]";
                out.push_back(std::move(node));
            }
            return out;
        }

        /**
         * @brief 流量摘要
         */
        [[nodiscard]] auto traffic_summary() const -> psmtest::runtime::traffic_pod override
        {
            if (!traffic_)
            {
                return {};
            }
            return traffic_->total();
        }

        /**
         * @brief 配置快照（JSON 文本）
         */
        [[nodiscard]] auto config_snapshot() const -> std::string override
        {
            std::string out = "{";
            out += "\"sessions\":";
            out += std::to_string(registry_ ? registry_->size() : 0);
            if (identity_)
            {
                out += ",\"identities\":";
                out += std::to_string(identity_->identity_count());
            }
            out += "}";
            return out;
        }

    private:
        const psmtest::runtime::session_registry *registry_;         ///< 会话注册表
        const psmtest::runtime::per_worker_traffic *traffic_;        ///< 流量聚合
        const psmtest::runtime::identity_traffic *identity_;         ///< 身份聚合（可选）
    };

} // namespace psmtest::api
