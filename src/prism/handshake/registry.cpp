#include <prism/handshake/anytls/scheme.hpp>
#include <prism/handshake/ech/scheme.hpp>
#include <prism/handshake/gun/scheme.hpp>
#include <prism/handshake/native.hpp>
#include <prism/handshake/reality/scheme.hpp>
#include <prism/handshake/registry.hpp>
#include <prism/handshake/restls/scheme.hpp>
#include <prism/handshake/shadowtls/scheme.hpp>
#include <prism/handshake/trusttunnel/scheme.hpp>
#include <prism/handshake/ws/scheme.hpp>
#include <prism/handshake/xhttp/scheme.hpp>

#include <algorithm>

namespace psm::handshake
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
        reg.add(std::make_shared<gun::scheme>());
        reg.add(std::make_shared<ech::scheme>());
        reg.add(std::make_shared<ws::scheme>());
        reg.add(std::make_shared<xhttp::scheme>());
        reg.add(std::make_shared<native::native>());
    }

    auto scheme_registry::instance() -> scheme_registry &
    {
        static scheme_registry reg;
        return reg;
    }

    void scheme_registry::add(shared_scheme scheme)
    {
        schemes_.push_back(std::move(scheme));
    }

    auto scheme_registry::all() const -> const std::vector<shared_scheme> &
    {
        return schemes_;
    }

    auto scheme_registry::find(const std::string_view name) const -> shared_scheme
    {
        auto iffunctor = [name](const auto &s) { return s->name() == name; };
        const auto it = std::ranges::find_if(schemes_, iffunctor);
        if (it != schemes_.end())
        {
            return *it;
        }
        return nullptr;
    }

} // namespace psm::handshake
