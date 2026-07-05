#include <prism/net/connect/route/table.hpp>

#include <utility>

namespace psm::connect
{
    auto route_table::add_route(std::string_view host, const tcp::endpoint &ep) -> void
    {
        memory::string key(host, reverse_.get_allocator());
        reverse_.insert_or_assign(std::move(key), ep);
    }

    auto route_table::remove_route(std::string_view host) -> std::size_t
    {
        const auto erased = reverse_.erase(host);
        return erased;
    }

    auto route_table::set_forward_endpoint(std::string_view host, std::uint16_t port) -> void
    {
        if (host.empty() || port == 0)
        {
            forward_host_.reset();
            forward_port_ = 0;
            return;
        }
        forward_host_ = memory::string(host, reverse_.get_allocator());
        forward_port_ = port;
    }

    auto route_table::clear_forward_endpoint() -> void
    {
        forward_host_.reset();
        forward_port_ = 0;
    }

    auto route_table::lookup(std::string_view host) -> std::optional<tcp::endpoint>
    {
        const auto it = reverse_.find(host);
        if (it == reverse_.end())
        {
            reverse_misses_.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        reverse_hits_.fetch_add(1, std::memory_order_relaxed);
        return it->second;
    }

    auto route_table::stats() const noexcept -> route_stats
    {
        return route_stats{
            reverse_hits_.load(std::memory_order_relaxed),
            reverse_misses_.load(std::memory_order_relaxed),
            forward_uses_.load(std::memory_order_relaxed)};
    }

} // namespace psm::connect
