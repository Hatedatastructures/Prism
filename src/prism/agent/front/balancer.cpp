#include <prism/agent/front/balancer.hpp>

#include <algorithm>
#include <limits>

namespace psm::agent::front
{
    balancer::balancer(memory::vector<worker_binding> bindings, const distribute_config &config,
                       const memory::resource_pointer mr)
        : bindings_(std::move(bindings), mr), overload_state_(mr), config_(config), mr_(mr)
    {
        // 每个 worker 一个过载标记，0=正常，1=过载
        overload_state_.resize(bindings_.size(), 0U);
    }

    // splitmix64 哈希函数——将亲和性值（客户端 IP 哈希）均匀打散。
    // 目的：即使客户端 IP 集中在某个子网，分配到 worker 的分布也要尽量均匀。
    auto balancer::mix_hash(std::uint64_t value) noexcept -> std::uint64_t
    {
        value += 0x9e3779b97f4a7c15ULL;
        value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
        value = value ^ (value >> 31U);
        return value;
    }

    // 计算单个 worker 的负载评分（0.0 = 空闲，越高越忙）。
    // 三个维度加权求和：活跃会话数（权重最大）、待处理移交数、事件循环延迟。
    // 用比率而非绝对值，这样不同容量的 worker 可以公平比较。
    auto balancer::score(const worker_load_snapshot &snapshot) const noexcept -> double
    {
        const auto session_capacity = std::max(1U, config_.session_capacity);
        const auto pending_capacity = std::max(1U, config_.pending_capacity);
        const auto lag_capacity = std::max(1ULL, config_.lag_capacity_us);

        const double session_ratio = static_cast<double>(snapshot.active_sessions) / session_capacity;
        const double pending_ratio = static_cast<double>(snapshot.pending_handoffs) / pending_capacity;
        const double lag_ratio = static_cast<double>(snapshot.event_loop_lag_us) / lag_capacity;

        return session_ratio * config_.weight_session +
               pending_ratio * config_.weight_pending +
               lag_ratio * config_.weight_lag;
    }

    // 过载状态更新——采用迟滞（hysteresis）机制：
    // 进入过载阈值（如 90%）和退出过载阈值（如 80%）不同，
    // 防止负载在阈值附近波动时频繁切换状态。
    void balancer::refresh_state(const std::size_t worker_index, const double load_score) noexcept
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

    // 核心选择算法：为新连接选一个 worker。
    //
    // 步骤：
    // 1. 用客户端亲和性值（来自 IP 地址哈希）选出两个候选 worker
    //    - primary：亲和性首选，同一客户端尽量落到同一 worker
    //    - secondary：备选，primary 过载时的降级选择
    // 2. 遍历所有 worker，计算负载评分并更新过载状态
    // 3. 选择策略：
    //    - primary 未过载 → 选 primary（保持亲和性）
    //    - primary 过载 → 选负载更低的那个（primary 或 secondary 都可能）
    // 4. 判断是否触发全局背压：
    //    - 所有 worker 都过载，或最低评分超过全局阈值
    auto balancer::select(const std::uint64_t affinity_value) noexcept -> select_result
    {
        if (bindings_.empty())
        {
            return {};
        }

        const std::size_t workers_count = bindings_.size();

        // 用不同的哈希种子选出两个不同的候选 worker
        const auto primary = mix_hash(affinity_value) % workers_count;
        std::size_t secondary = primary;
        if (workers_count > 1U)
        {
            secondary = mix_hash(affinity_value ^ 0xa24baed4963ee407ULL) % workers_count;
            if (secondary == primary)
            {
                secondary = (secondary + 1U) % workers_count;
            }
        }

        double primary_score = 0.0;
        double secondary_score = 0.0;
        double min_score = std::numeric_limits<double>::max();
        std::size_t overloaded_count = 0;

        // 遍历所有 worker：采集负载、更新过载状态、记录候选分数
        for (std::size_t index = 0; index < workers_count; ++index)
        {
            const worker_load_snapshot snapshot = bindings_[index].snapshot();
            const double load_score = score(snapshot);
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

        // primary 过载时，看 secondary 是否更空闲
        const bool primary_overloaded = overload_state_[primary] != 0U;
        std::size_t selected = primary;
        if (primary_overloaded && workers_count > 1U)
        {
            selected = secondary_score < primary_score ? secondary : primary;
        }

        // 全局背压：所有 worker 都过载 或 全局最低评分已经很高
        const bool backpressure = overloaded_count == workers_count || min_score >= config_.global_backpressure_threshold;
        return {selected, primary_overloaded, backpressure};
    }

    // 将 socket 实际移交给选中的 worker。
    // 越界时回退到 worker 0 作为安全兜底。
    void balancer::dispatch(std::size_t worker_index, tcp::socket socket) const
    {
        if (bindings_.empty())
        {
            return;
        }
        if (worker_index >= bindings_.size())
        {
            worker_index = 0U;
        }
        bindings_[worker_index].dispatch(std::move(socket));
    }

    auto balancer::size() const noexcept -> std::size_t
    {
        return bindings_.size();
    }
} // namespace psm::agent::front
