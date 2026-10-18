/** @file ConfigurationCompiler.hpp @brief 冷路径把协议配置实例编译成真实 provider 槽位。 */
#pragma once
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
namespace Prism::Composition::Provider
{
    struct ConfigurationInput final
    {
        Prism::Foundation::GenerationPin Generation;
        /** @brief 与将发布 RuntimeGenerationServices 共用、且不反向持有 snapshot 的活动计数。 */
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::span<const Prism::Contract::ProtocolConfiguration> Protocols;
        std::span<const Prism::Contract::ProtocolBindingConfiguration> Bindings;
        std::unordered_map<std::string,Prism::Contract::AuthenticationServices> Authentication;
    };
    /** @brief 只选择本入口已实施的 typed 槽位；configured mux 共享传入的唯一代次活动计数。
     * @details 实例以 Id 保留，按 kind 去重禁止；服务全为 owning 值，prepare 不打开监听。
     */
    [[nodiscard]] inline auto Compile(ConfigurationInput Input,BindingServices Services)
        ->std::expected<PreparedCatalog,Prism::Contract::ProviderFailure>
    {
        Preparation Request{Input.Generation,Input.UseState,{},{}};
        Request.Bindings.assign(Input.Bindings.begin(),Input.Bindings.end());
        for(const auto& Protocol:Input.Protocols)
        {
            if(!ProviderCatalog::Handles(Protocol.Builtin))continue;
            ConfiguredInstance Instance{Protocol,false,false,{}};
            bool HasBinding=false;
            for(const auto& Binding:Input.Bindings)
                if(Binding.ProtocolId==Protocol.Id)
                { HasBinding=true;Instance.Tcp|=Binding.TcpEnabled;Instance.Udp|=Binding.UdpEnabled; }
            if(!HasBinding)Instance.Tcp=true;
            const auto Found=Input.Authentication.find(Protocol.Id);
            if(Found!=Input.Authentication.end())Instance.Authentication=Found->second;
            Request.Instances.push_back(std::move(Instance));
        }
        return ProviderCatalog::Prepare(std::move(Request),std::move(Services));
    }
}
