#include <prism/agent/front/balancer.hpp>

#include <algorithm>
#include <limits>

namespace psm::agent::front
{
    balancer::balancer(memory::vector<worker_binding> bindings, const distribute_config &config,
                       const memory::resource_pointer mr)
        : bindings_(std::move(bindings), mr), overload_state_(mr), config_(config), mr_(mr)
    {
        overload_state_.resize(bindings_.size(), 0U);
    }

    auto balancer::mix_hash(std::uint64_t value) noexcept -> std::uint64_t
    {
        value += 0x9e3779b97f4a7c15ULL;
        value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
        value = value ^ (value >> 31U);
        return value;
    }

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

    auto balancer::select(const std::uint64_t affinity_value) noexcept -> select_result
    {
        if (bindings_.empty())
        {
            return {};
        }

        const std::size_t workers_count = bindings_.size();
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

        const bool primary_overloaded = overload_state_[primary] != 0U;
        std::size_t selected = primary;
        if (primary_overloaded && workers_count > 1U)
        {
            selected = secondary_score < primary_score ? secondary : primary;
        }

        const bool backpressure = overloaded_count == workers_count || min_score >= config_.global_backpressure_threshold;
        return {selected, primary_overloaded, backpressure};
    }

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