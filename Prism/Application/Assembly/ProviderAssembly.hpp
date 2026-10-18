/** @file ProviderAssembly.hpp @brief Application 向 Composition 编译入口交付 generation 和实际进程服务。 */
#pragma once
#include <Prism/Composition/Provider/ConfigurationCompiler.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
namespace Prism::Application::Assembly
{
    /** @brief 接管拥有值编译请求，无协议 wire/工厂/秘密解释；typed 失败只映射启动路径。 */
    [[nodiscard]] inline auto BuildProviderCatalog(
        Prism::Composition::Provider::ConfigurationInput Input,
        Prism::Composition::Provider::BindingServices Services)
        ->std::expected<Prism::Composition::Provider::BoundCatalog,StartupError>
    {
        auto Prepared=Prism::Composition::Provider::Compile(std::move(Input),std::move(Services));
        if(!Prepared)return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin,
            "Protocols."+Prepared.error().Instance+"."+Prepared.error().Path,"protocol provider preparation failed"));
        auto Frozen=Prepared->Freeze();
        if(!Frozen)return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin,"Protocols","provider freeze failed"));
        auto Bound=Frozen->Bind({});
        if(!Bound)return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin,
            "Protocols."+Bound.error().Instance+"."+Bound.error().Path,"protocol provider binding failed"));
        return std::move(*Bound);
    }
}
