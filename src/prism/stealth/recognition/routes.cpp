#include <prism/stealth/recognition/routes.hpp>

#include <prism/config/config.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

namespace psm::recognition
{

    auto route_table::build(const psm::config &cfg)
        -> route_table
    {
        route_table table;

        const auto &reality_cfg = cfg.stealth.reality;
        if (reality_cfg.enabled())
        {
            for (const auto &sni : reality_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "reality");
            }
        }

        const auto &shadowtls_cfg = cfg.stealth.shadowtls;
        if (shadowtls_cfg.enabled())
        {
            for (const auto &sni : shadowtls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "shadowtls");
            }
        }

        const auto &restls_cfg = cfg.stealth.restls;
        if (restls_cfg.enabled())
        {
            for (const auto &sni : restls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "restls");
            }
        }

        const auto &anytls_cfg = cfg.stealth.anytls;
        if (anytls_cfg.enabled())
        {
            for (const auto &sni : anytls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "anytls");
            }
        }

        const auto &trusttunnel_cfg = cfg.stealth.trusttunnel;
        if (trusttunnel_cfg.enabled())
        {
            for (const auto &sni : trusttunnel_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "trusttunnel");
            }
        }

        trace::info("built route table with {} SNI entries", table.route_map_.size());
        return table;
    }

    auto route_table::lookup(std::string_view sni) const
        -> memory::vector<memory::string>
    {
        if (sni.empty())
            return {};

        auto key = memory::string(sni);
        auto it = route_map_.find(key);
        if (it != route_map_.end())
        {
            return it->second;
        }

        return {};
    }

    auto route_table::matches_any(std::string_view sni) const
        -> bool
    {
        if (sni.empty())
            return false;

        auto key = memory::string(sni);
        return route_map_.find(key) != route_map_.end();
    }

    auto route_table::registered_snis() const
        -> memory::vector<memory::string>
    {
        memory::vector<memory::string> snis;
        for (const auto &[sni, _] : route_map_)
        {
            snis.push_back(sni);
        }
        return snis;
    }

    auto route_table::empty() const noexcept
        -> bool
    {
        return route_map_.empty();
    }

    void route_table::add_route(std::string_view sni, std::string_view scheme_name)
    {
        if (sni.empty())
            return;

        auto key = memory::string(sni);
        auto value = memory::string(scheme_name);

        auto it = route_map_.find(key);
        if (it != route_map_.end())
        {
            for (const auto &existing : it->second)
            {
                if (existing == value)
                    return;
            }
            it->second.push_back(value);
        }
        else
        {
            route_map_.emplace(std::move(key), memory::vector<memory::string>{std::move(value)});
        }
    }
} // namespace psm::recognition
