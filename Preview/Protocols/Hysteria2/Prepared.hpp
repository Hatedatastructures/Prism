/** @file Prepared.hpp @brief Hysteria2 原 generation token、HTTP3 与 TLS 的 move-only 准备结果。 */
#pragma once
#include <Preview/Protocols/Common/QuicPreparation.hpp>
#include <Preview/Protocols/Http3/ServerFactory.hpp>
namespace Preview::Hysteria2
{
    struct BindingServices final
    {
        Preview::Contract::QuicBindingServices Network;
        Preview::Contract::AuthenticationServices Authentication;
        std::shared_ptr<Preview::Http3::ServerFactory> Http3;
    };
    struct Prepared final
    {
        Preview::Protocols::QuicPreparation Input;
        BindingServices Services;
        Preview::Protocols::ScopedMaterial Credential;
        Prepared(Preview::Protocols::QuicPreparation Value,BindingServices Ports,Preview::Protocols::ScopedMaterial Record)
            :Input(std::move(Value)),Services(std::move(Ports)),Credential(std::move(Record)){}
        Prepared(Prepared&&)=default;
        Prepared(const Prepared&)=delete;
    };
    /** @brief 接管配置和 owning 服务；不监听、不认证、不消耗账户租约，失败返回实际路径。 */
    [[nodiscard]] inline auto Prepare(Preview::Protocols::QuicPreparation Input,BindingServices Services)
        -> std::expected<Prepared,Preview::Contract::ProviderFailure>
    {
        auto Valid=Preview::Protocols::ValidateQuic(Input,Services.Network);
        if(!Valid)return std::unexpected(Valid.error());
        if(!Services.Http3)return std::unexpected(Preview::Contract::ProviderFailure{
            Preview::Contract::ProviderError::MissingHttp3,Input.Instance,"Quic.Http3"});
        auto Record=Preview::Protocols::ValidateQuicAuthentication(Input,Services.Authentication);
        if(!Record)return std::unexpected(Record.error());
        return Prepared(std::move(Input),std::move(Services),std::move(*Record));
    }
}
