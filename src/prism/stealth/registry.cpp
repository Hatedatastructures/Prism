#include <prism/stealth/registry.hpp>

#include <prism/stealth/anytls/scheme.hpp>
#include <prism/stealth/native.hpp>
#include <prism/stealth/reality/scheme.hpp>
#include <prism/stealth/restls/scheme.hpp>
#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/trusttunnel/scheme.hpp>

#include <algorithm>

namespace psm::stealth
{

    void register_schemes()
    {
        auto &reg = scheme_registry::instance();

        // 注册顺序即为默认优先级
        reg.add(std::make_shared<reality::scheme>());
        reg.add(std::make_shared<shadowtls::scheme>());
        reg.add(std::make_shared<restls::scheme>());
        reg.add(std::make_shared<anytls::scheme>());
        reg.add(std::make_shared<trusttunnel::scheme>());
        reg.add(std::make_shared<native::native>());
    }

    auto scheme_registry::instance()
        -> scheme_registry &
    {
        static scheme_registry reg;
        return reg;
    }

    void scheme_registry::add(shared_scheme scheme)
    {
        schemes_.push_back(std::move(scheme));
    }

    auto scheme_registry::all() const
        -> const std::vector<shared_scheme> &
    {
        return schemes_;
    }

    auto scheme_registry::find(const std::string_view name) const
        -> shared_scheme
    {
        auto iffunctor = [name](const auto &s)
        {
            return s->name() == name;
        };
        const auto it = std::ranges::find_if(schemes_, iffunctor);
        if (it != schemes_.end())
            return *it;
        return nullptr;
    }

} // namespace psm::stealth
