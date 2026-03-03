#include <forward-engine/agent/distribute.hpp>

#include <algorithm>
#include <limits>

namespace ngx::agent
{
    /**
     * @brief 构造接入分流器
     * @details 初始化 `worker` 绑定和过载状态位集合。
     */
    distribute::distribute(memory::vector<worker_binding> bindings, const distribute_config config,
                           memory::resource_pointer mr)
        : bindings_(std::move(bindings), mr), overload_state_(mr), config_(config), mr_(mr)
    {
        overload_state_.resize(bindings_.size(), 0U);
    }

    /**
     * @brief 64 位混洗函数
     * @details 基于 `splitmix64` 思路，降低亲和键碰撞导致的倾斜风险。
     */
    auto distribute::mix_hash(std::uint64_t value) noexcept -> std::uint64_t
    {
        value += 0x9e3779b97f4a7c15ULL;
        value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
        value = value ^ (value >> 31U);
        return value;
    }

    /**
     * @brief 计算综合负载得分
     * @details 将会话数、投递队列和事件循环延迟归一化并线性加权。
     */
    auto distribute::score(const worker_load_snapshot &snapshot) const noexcept
        -> double
    {
        const double session_ratio = static_cast<double>(snapshot.active_sessions) /
                                     static_cast<double>(std::max<std::uint32_t>(1U, config_.session_capacity));
        const double pending_ratio = static_cast<double>(snapshot.pending_handoffs) /
                                     static_cast<double>(std::max<std::uint32_t>(1U, config_.pending_capacity));
        const double lag_ratio = static_cast<double>(snapshot.event_loop_lag_us) /
                                 static_cast<double>(std::max<std::uint64_t>(1ULL, config_.lag_capacity_us));
        return session_ratio * config_.weight_session + pending_ratio * config_.weight_pending + lag_ratio * config_.weight_lag;
    }

    /**
     * @brief 更新超载滞回状态
     * @details 使用双阈值避免状态在边界附近频繁抖动。
     */
    void distribute::refresh_state(const std::size_t worker_index, const double load_score) noexcept
    {
        const bool current = overload_state_[worker_index] != 0U;
        if (!current && load_score >= config_.enter_overload)
        {
            overload_state_[worker_index] = 1U;
            return;
        }
        if (current && load_score <= config_.exit_overload)
        {
            overload_state_[worker_index] = 0U;
        }
    }

    /**
     * @brief 选择目标工作线程
     * @details
     * - 主路径：亲和哈希得到 primary；
     * - 兜底：primary 超载时，在 secondary 与 primary 中择优；
     * - 背压：全体超载或最小分数过高时输出背压信号。
     */
    auto distribute::select(const std::uint64_t affinity_value) noexcept
        -> select_result
    {
        if (bindings_.empty())
        {
            return {};
        }

        const std::size_t workers_count = bindings_.size();
        const std::size_t primary = static_cast<std::size_t>(mix_hash(affinity_value) % workers_count);
        std::size_t secondary = primary;
        if (workers_count > 1U)
        {
            secondary = static_cast<std::size_t>(mix_hash(affinity_value ^ 0xa24baed4963ee407ULL) % workers_count);
            if (secondary == primary)
            {
                secondary = (secondary + 1U) % workers_count;
            }
        }

        double primary_score = 0.0; // 负载分数
        double secondary_score = 0.0; // 兜底负载分数
        double min_score = std::numeric_limits<double>::max();
        std::size_t overloaded_count = 0; // 超载计数

        for (std::size_t index = 0; index < workers_count; ++index)
        {
            const worker_load_snapshot snapshot = bindings_[index].snapshot();
            const double load_score = score(snapshot); // 计算负载分
            refresh_state(index, load_score);

            if (index == primary)
            {
                primary_score = load_score;
            }
            if (index == secondary)
            {
                secondary_score = load_score;
            }

            if (load_score < min_score)
            {
                min_score = load_score;
            }

            if (overload_state_[index] != 0U)
            {
                ++overloaded_count;
            }
        }
        // 当前是否发生预先计算的索引对应的 worker 达到超载
        const bool primary_overloaded = overload_state_[primary] != 0U;
        std::size_t selected = primary;

        if (primary_overloaded && workers_count > 1U)
        {   // 如果发生超载就用兜底方案计算的索引值
            selected = secondary_score < primary_score ? secondary : primary;
        }
        // 当前是否发生背压
        const bool backpressure = overloaded_count == workers_count || min_score >= config_.global_backpressure_threshold;

        return {selected, primary_overloaded, backpressure};
    }

    /**
     * @brief 投递 socket 到目标 `worker`
     * @details 若索引越界则回退到 0 号 `worker`。
     */
    void distribute::dispatch(std::size_t worker_index, tcp::socket socket) const
    {
        if (bindings_.empty())
        {
            return;
        }
        if (worker_index >= bindings_.size())
        {   // 兜底
            worker_index = 0U;
        }
        bindings_[worker_index].dispatch(std::move(socket));
    }

    /**
     * @brief 获取 `worker` 绑定数量
     */
    auto distribute::size() const noexcept -> std::size_t
    {
        return bindings_.size();
    }
}
