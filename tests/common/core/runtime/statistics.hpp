/**
 * @file statistics.hpp
 * @brief 流量统计聚合器（T4-4）
 * @details 实现 traffic_sink 接口，按 identity 聚合 up/down 流量：
 *          - 多会话累计（同一 identity 汇总）
 *          - 未知 identity 查询返回 0
 *          - 接 relay 结束点（ctx.traffic）自动统计
 * @note 单线程 io_context 测试环境用 map 即可；并发多 worker
 *       版本（alignas(64) 原子 + COW 聚合）见 T5-2 O2
 */

#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <string_view>

#include <common/core/middleware/context.hpp>

namespace psmtest::runtime
{

    /**
     * @class traffic_counter
     * @brief 按 identity 聚合的流量计数器
     * @details 会话结束时 relay 中间件调用 report()，
     *          本聚合器按 identity 累计 up/down。
     */
    class traffic_counter final : public psmtest::middleware::context::traffic_sink
    {
    public:
        /**
         * @struct entry
         * @brief 单 identity 的流量
         */
        struct entry
        {
            std::size_t up{0};   ///< 上行字节
            std::size_t down{0}; ///< 下行字节
        };

        /**
         * @brief 上报流量（relay 结束点调用）
         * @param identity 用户标识
         * @param up 上行字节
         * @param down 下行字节
         */
        void report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            auto &e = by_identity_[std::string(identity)];
            e.up += up;
            e.down += down;
        }

        /**
         * @brief 查询 identity 累计流量
         * @param identity 用户标识
         * @return 累计（未知 identity 返回 0）
         */
        [[nodiscard]] auto total(const std::string_view identity) const -> entry
        {
            const auto it = by_identity_.find(std::string(identity));
            if (it == by_identity_.end())
            {
                return {};
            }
            return it->second;
        }

        /**
         * @brief 有流量的 identity 数
         */
        [[nodiscard]] auto identity_count() const -> std::size_t
        {
            return by_identity_.size();
        }

        /**
         * @brief 全部 identity 累计流量
         */
        [[nodiscard]] auto grand_total() const -> entry
        {
            entry g;
            for (const auto &[id, e] : by_identity_)
            {
                (void)id;
                g.up += e.up;
                g.down += e.down;
            }
            return g;
        }

    private:
        std::map<std::string, entry> by_identity_; ///< identity → 流量
    };

} // namespace psmtest::runtime
