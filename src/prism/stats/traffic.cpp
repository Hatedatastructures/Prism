#include <prism/stats/traffic.hpp>

namespace psm::stats::traffic
{
    // --- traffic_state ---

    void traffic_state::on_connect() noexcept
    {
        total_connections_.fetch_add(1, std::memory_order::relaxed);
        total_active_.fetch_add(1, std::memory_order::relaxed);
    }

    void traffic_state::on_protocol_detected(protocol::protocol_type type) noexcept
    {
        const auto i = static_cast<std::uint8_t>(type);
        protocols_[i].connections.fetch_add(1, std::memory_order::relaxed);
        protocols_[i].active.fetch_add(1, std::memory_order::relaxed);
    }

    void traffic_state::on_disconnect(protocol::protocol_type type) noexcept
    {
        total_active_.fetch_sub(1, std::memory_order::relaxed);
        const auto i = static_cast<std::uint8_t>(type);
        protocols_[i].active.fetch_sub(1, std::memory_order::relaxed);
    }

    void traffic_state::flush_traffic(protocol::protocol_type proto,
                                       std::uint64_t up,
                                       std::uint64_t down) noexcept
    {
        const auto i = static_cast<std::uint8_t>(proto);
        if (up)
        {
            total_uplink_.fetch_add(up, std::memory_order::relaxed);
            protocols_[i].uplink_bytes.fetch_add(up, std::memory_order::relaxed);
        }
        if (down)
        {
            total_downlink_.fetch_add(down, std::memory_order::relaxed);
            protocols_[i].downlink_bytes.fetch_add(down, std::memory_order::relaxed);
        }
    }

    void traffic_state::on_auth_success() noexcept
    {
        auth_success_.fetch_add(1, std::memory_order::relaxed);
    }

    void traffic_state::on_auth_failure() noexcept
    {
        auth_failure_.fetch_add(1, std::memory_order::relaxed);
    }

    auto traffic_state::snapshot() const noexcept
        -> traffic_snapshot
    {
        traffic_snapshot s;
        s.total_connections = total_connections_.load(std::memory_order::relaxed);
        s.total_active = total_active_.load(std::memory_order::relaxed);
        s.total_uplink = total_uplink_.load(std::memory_order::relaxed);
        s.total_downlink = total_downlink_.load(std::memory_order::relaxed);
        s.auth_success = auth_success_.load(std::memory_order::relaxed);
        s.auth_failure = auth_failure_.load(std::memory_order::relaxed);

        for (std::size_t i = 0; i < proto_slot_count; ++i)
        {
            s.protocols[i].connections = protocols_[i].connections.load(std::memory_order::relaxed);
            s.protocols[i].active = protocols_[i].active.load(std::memory_order::relaxed);
            s.protocols[i].uplink_bytes = protocols_[i].uplink_bytes.load(std::memory_order::relaxed);
            s.protocols[i].downlink_bytes = protocols_[i].downlink_bytes.load(std::memory_order::relaxed);
        }
        return s;
    }

    void traffic_state::reset() noexcept
    {
        total_connections_.store(0, std::memory_order::relaxed);
        total_active_.store(0, std::memory_order::relaxed);
        total_uplink_.store(0, std::memory_order::relaxed);
        total_downlink_.store(0, std::memory_order::relaxed);
        auth_success_.store(0, std::memory_order::relaxed);
        auth_failure_.store(0, std::memory_order::relaxed);

        for (std::size_t i = 0; i < proto_slot_count; ++i)
        {
            protocols_[i].connections.store(0, std::memory_order::relaxed);
            protocols_[i].active.store(0, std::memory_order::relaxed);
            protocols_[i].uplink_bytes.store(0, std::memory_order::relaxed);
            protocols_[i].downlink_bytes.store(0, std::memory_order::relaxed);
        }
    }

    // --- 全局注册表（COW 无锁） ---

    using registry_vector = std::vector<traffic_state *>;

    static std::atomic<registry_vector *> g_registry{nullptr};

    static auto load_registry() noexcept
        -> registry_vector *
    {
        return g_registry.load(std::memory_order::acquire);
    }

    static void store_registry(registry_vector *v) noexcept
    {
        g_registry.store(v, std::memory_order::release);
    }

    void traffic_state::register_instance(traffic_state *s) noexcept
    {
        auto *old = load_registry();
        auto *next = new registry_vector();
        if (old)
        {
            *next = *old;
        }
        next->push_back(s);
        store_registry(next);
    }

    void traffic_state::unregister_instance(traffic_state *s) noexcept
    {
        auto *old = load_registry();
        if (!old)
        {
            return;
        }
        auto *next = new registry_vector();
        *next = *old;
        for (auto it = next->begin(); it != next->end(); ++it)
        {
            if (*it == s)
            {
                next->erase(it);
                break;
            }
        }
        store_registry(next);
    }

    auto traffic_state::aggregate() noexcept
        -> traffic_snapshot
    {
        auto *reg = load_registry();
        if (!reg)
        {
            return {};
        }
        traffic_snapshot result;
        for (auto *instance : *reg)
        {
            auto s = instance->snapshot();
            result.total_connections += s.total_connections;
            result.total_active += s.total_active;
            result.total_uplink += s.total_uplink;
            result.total_downlink += s.total_downlink;
            result.auth_success += s.auth_success;
            result.auth_failure += s.auth_failure;
            for (std::size_t i = 0; i < proto_slot_count; ++i)
            {
                result.protocols[i].connections += s.protocols[i].connections;
                result.protocols[i].active += s.protocols[i].active;
                result.protocols[i].uplink_bytes += s.protocols[i].uplink_bytes;
                result.protocols[i].downlink_bytes += s.protocols[i].downlink_bytes;
            }
        }
        return result;
    }
} // namespace psm::stats::traffic
