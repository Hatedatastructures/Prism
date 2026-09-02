/**
 * @file ApiManager.hpp
 * @brief 管理 API 接口与骨架（T5-8 O7）
 * @details 资源树契约 + ApiManager 接口：
 *          - 会话列表（快照式，无 L3 引用）
 *          - 流量摘要
 *          - 配置快照（JSON 文本）
 * @note 接口可 mock；独立 ioc 的执行骨架由调用方持有
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <preview/Runtime/Statistics.hpp>
#include <preview/Runtime/SessionRegistry.hpp>

namespace Preview::Api
{

    /**
     * @struct ResourceNode
     * @brief 资源树节点（契约）
     */
    struct ResourceNode
    {
        std::string Name{};    ///< 资源名（如 "Session"）
        std::uint64_t Id{0};   ///< 资源 Id（会话 Id 等）
        std::string detail{};  ///< 详情（地址/目标等）
        std::uint64_t value{0}; ///< 数值（流量字节等）
    };

    /**
     * @class ApiManager
     * @brief 管理 API 接口
     * @details 会话列表 / 流量摘要 / 配置快照。
     *          所有返回均为值拷贝（快照），严禁外部引用内部状态。
     */
    class ApiManager
    {
    public:
        virtual ~ApiManager() = default;

        /**
         * @brief 会话列表快照
         */
        [[nodiscard]] virtual auto ListSessions() const -> std::vector<ResourceNode> = 0;

        /**
         * @brief 流量摘要（up/down 聚合）
         */
        [[nodiscard]] virtual auto TrafficSummary() const -> Preview::Runtime::TrafficPod = 0;

        /**
         * @brief 配置快照（JSON 文本）
         */
        [[nodiscard]] virtual auto ConfigSnapshot() const -> std::string = 0;
    };

    /**
     * @class RegistryApiManager
     * @brief 基于注册表 + 统计的实现
     * @details 组合 SessionRegistry 与流量聚合器，提供值快照 API。
     */
    class RegistryApiManager final : public ApiManager
    {
    public:
        /**
         * @brief 构造
         * @param registry 会话注册表（非拥有）
         * @param traffic 流量聚合器（非拥有）
         */
        RegistryApiManager(const Preview::Runtime::SessionRegistry *registry,
                             const Preview::Runtime::PerWorkerTraffic *traffic,
                             const Preview::Runtime::IdentityTraffic *identity = nullptr)
            : Registry_(registry), Traffic_(traffic), Identity_(identity)
        {
        }

        /**
         * @brief 会话列表快照（值拷贝）
         */
        [[nodiscard]] auto ListSessions() const -> std::vector<ResourceNode> override
        {
            std::vector<ResourceNode> out;
            if (!Registry_)
            {
                return out;
            }
            const auto Snap = Registry_->Snapshot();
            for (const auto &[Id, Info] : *Snap)
            {
                ResourceNode node;
                node.Name = "Session";
                node.Id = Id;
                node.detail = Info.peer + " -> " + Info.Target + " [" + Info.identity + "]";
                out.push_back(std::move(node));
            }
            return out;
        }

        /**
         * @brief 流量摘要
         */
        [[nodiscard]] auto TrafficSummary() const -> Preview::Runtime::TrafficPod override
        {
            if (!Traffic_)
            {
                return {};
            }
            return Traffic_->Total();
        }

        /**
         * @brief 配置快照（JSON 文本）
         */
        [[nodiscard]] auto ConfigSnapshot() const -> std::string override
        {
            std::string out = "{";
            out += "\"sessions\":";
            std::size_t RegSize = 0;
            if (Registry_)
            {
                RegSize = Registry_->Size();
            }
            out += std::to_string(RegSize);
            if (Identity_)
            {
                out += ",\"identities\":";
                out += std::to_string(Identity_->IdentityCount());
            }
            out += "}";
            return out;
        }

    private:
        const Preview::Runtime::SessionRegistry *Registry_;         ///< 会话注册表
        const Preview::Runtime::PerWorkerTraffic *Traffic_;        ///< 流量聚合
        const Preview::Runtime::IdentityTraffic *Identity_;         ///< 身份聚合（可选）
    };

} // namespace Preview::Api
