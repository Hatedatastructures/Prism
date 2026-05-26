#include <prism/recognition/routes.hpp>

#include <prism/config.hpp>
#include <prism/trace.hpp>

namespace psm::recognition
{

    auto route_table::build(const psm::config &cfg)
        -> route_table
    {
        route_table table;

        // Reality server_names → "reality"
        const auto &reality_cfg = cfg.stealth.reality;
        if (reality_cfg.enabled())
        {
            for (const auto &sni : reality_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "reality");
                trace::debug("[SchemeRouteTable] Register SNI '{}' → reality", sni);
            }
        }

        // ShadowTLS server_names → "shadowtls"
        const auto &shadowtls_cfg = cfg.stealth.shadowtls;
        if (shadowtls_cfg.enabled())
        {
            for (const auto &sni : shadowtls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "shadowtls");
                trace::debug("[SchemeRouteTable] Register SNI '{}' → shadowtls", sni);
            }
        }

        // Restls server_names → "restls"
        const auto &restls_cfg = cfg.stealth.restls;
        if (restls_cfg.enabled())
        {
            for (const auto &sni : restls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "restls");
                trace::debug("[SchemeRouteTable] Register SNI '{}' → restls", sni);
            }
        }

        // AnyTLS server_names → "anytls"
        const auto &anytls_cfg = cfg.stealth.anytls;
        if (anytls_cfg.enabled())
        {
            for (const auto &sni : anytls_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "anytls");
                trace::debug("[SchemeRouteTable] Register SNI '{}' → anytls", sni);
            }
        }

        // TrustTunnel server_names → "trusttunnel"
        const auto &trusttunnel_cfg = cfg.stealth.trusttunnel;
        if (trusttunnel_cfg.enabled())
        {
            for (const auto &sni : trusttunnel_cfg.server_names)
            {
                table.add_route(std::string_view(sni), "trusttunnel");
                trace::debug("[SchemeRouteTable] Register SNI '{}' → trusttunnel", sni);
            }
        }

        trace::info("[SchemeRouteTable] Built route table with {} SNI entries", table.route_map_.size());
        return table;
    }

    auto route_table::lookup(std::string_view sni) const
        -> memory::vector<memory::string>
    {
        if (sni.empty())
            return {};

        // 直接使用 string_view 作为 key 查找
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

        // 检查是否已存在，避免重复添加
        auto it = route_map_.find(key);
        if (it != route_map_.end())
        {
            // 检查方案是否已存在
            for (const auto &existing : it->second)
            {
                if (existing == value)
                    return; // 已存在，不重复添加
            }
            // 添加新方案到现有 SNI
            it->second.push_back(value);
        }
        else
        {
            // 新 SNI，创建方案列表
            route_map_.emplace(std::move(key), memory::vector<memory::string>{std::move(value)});
        }
    }
} // namespace psm::recognition
