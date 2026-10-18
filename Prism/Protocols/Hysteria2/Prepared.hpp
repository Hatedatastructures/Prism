/** @file Prepared.hpp @brief Hysteria2 原 generation token、HTTP3 与 TLS 的 move-only 准备结果。 */
#pragma once
#include <Prism/Protocols/Common/QuicPreparation.hpp>
#include <Prism/Protocols/Http3/ServerFactory.hpp>
namespace Prism::Hysteria2
{
    struct BindingServices final
    {
        Prism::Contract::QuicBindingServices Network;
        Prism::Contract::AuthenticationServices Authentication;
        std::shared_ptr<Prism::Http3::ServerFactory> Http3;
    };
    struct Prepared final
    {
        Prism::Protocols::QuicPreparation Input;
        BindingServices Services;
        Prism::Protocols::ScopedMaterial Credential;
        Prepared(Prism::Protocols::QuicPreparation Value,BindingServices Ports,Prism::Protocols::ScopedMaterial Record)
            :Input(std::move(Value)),Services(std::move(Ports)),Credential(std::move(Record)){}
        Prepared(Prepared&&)=default;
        Prepared(const Prepared&)=delete;
    };
    /** @brief 接管配置和 owning 服务；不监听、不认证、不消耗账户租约，失败返回实际路径。 */
    [[nodiscard]] inline auto Prepare(Prism::Protocols::QuicPreparation Input,BindingServices Services)
        -> std::expected<Prepared,Prism::Contract::ProviderFailure>
    {
        auto Valid=Prism::Protocols::ValidateQuic(Input,Services.Network);
        if(!Valid)return std::unexpected(Valid.error());
        if(!Services.Http3)return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::MissingHttp3,Input.Instance,"Quic.Http3"});
        auto Record=Prism::Protocols::ValidateQuicAuthentication(Input,Services.Authentication);
        if(!Record)return std::unexpected(Record.error());
        return Prepared(std::move(Input),std::move(Services),std::move(*Record));
    }
}
