/** @file Provider.cpp @brief 接管 owning 值并编译 typed provider 绑定。 */

#include <Prism/Application/Assembly/Provider.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>

#include <string>
#include <utility>

namespace Prism::Application::Assembly
{

    auto BuildProviderCatalog(
        Prism::Composition::Provider::ConfigurationInput Input,
        Prism::Composition::Provider::BindingServices Services)
        -> std::expected<Prism::Composition::Provider::BoundCatalog, StartupError>
    {
        auto Prepared = Prism::Composition::Provider::Compile(
            std::move(Input), std::move(Services));
        if (!Prepared)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin,
                "Protocols." + Prepared.error().Instance + "." + Prepared.error().Path,
                "protocol provider preparation failed"));
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Builtin, "Protocols", "provider freeze failed"));
        }
        auto Bound = Frozen->Bind({});
        if (!Bound)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin,
                "Protocols." + Bound.error().Instance + "." + Bound.error().Path,
                "protocol provider binding failed"));
        }
        return std::move(*Bound);
    }

} // namespace Prism::Application::Assembly
