/** @file Prepared.hpp @brief TUIC owning token、UUID、TLS exporter 的 move-only 准备结果。 */
#pragma once
#include <Prism/Protocols/Common/QuicPreparation.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>
#include <openssl/ssl.h>
namespace Prism::Tuic
{
    struct BindingServices final
    {
        Prism::Contract::QuicBindingServices Network;
        Prism::Contract::AuthenticationServices Authentication;
    };
    struct Prepared final
    {
        Prism::Protocols::QuicPreparation Input;
        BindingServices Services;
        Prism::Protocols::ScopedMaterial Credential;
        std::array<std::uint8_t,UuidLen> Uuid;
        Prepared(Prism::Protocols::QuicPreparation Value,BindingServices Ports,Prism::Protocols::ScopedMaterial Record)
            :Input(std::move(Value)),Services(std::move(Ports)),Credential(std::move(Record)){}
        Prepared(Prepared&&)=default;
        Prepared(const Prepared&)=delete;
    };
    /** @brief UUID 只有 wire 长度和格式允许的 16 字节；无账户 lookup、秘密输出或 lease。 */
    [[nodiscard]] inline auto ParseBindingUuid(std::string_view Text)->std::optional<std::array<std::uint8_t,UuidLen>>
    {
        if(Text.size()!=36)return std::nullopt;
        std::array<std::uint8_t,UuidLen> Value{};std::size_t Offset=0;
        auto Digit=[](char C)->int{return C>='0' && C<='9'?C-'0':C>='a' && C<='f'?C-'a'+10:C>='A' && C<='F'?C-'A'+10:-1;};
        for(std::size_t I=0;I<Text.size();)
        {
            if(I==8 || I==13 || I==18 || I==23){if(Text[I++]!='-')return std::nullopt;continue;}
            const auto A=Digit(Text[I++]),B=Digit(Text[I++]);if(A<0 || B<0 || Offset>=Value.size())return std::nullopt;
            Value[Offset++]=static_cast<std::uint8_t>((A<<4)|B);
        }
        return Value;
    }
    /** @brief 校验 TLS1.3/exporter 和真实网络端口；TUIC 没有 HTTP3 服务依赖。 */
    [[nodiscard]] inline auto Prepare(Prism::Protocols::QuicPreparation Input,BindingServices Services)
        -> std::expected<Prepared,Prism::Contract::ProviderFailure>
    {
        auto Valid=Prism::Protocols::ValidateQuic(Input,Services.Network);
        if(!Valid)return std::unexpected(Valid.error());
        if(SSL_CTX_get_max_proto_version(Services.Network.Listener.Tls->native_handle())!=0 &&
            SSL_CTX_get_max_proto_version(Services.Network.Listener.Tls->native_handle())<TLS1_3_VERSION)
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingExporter,Input.Instance,"Quic.Tls.Exporter"});
        auto Uuid=ParseBindingUuid(Input.Config.Uuid);
        if(!Uuid)return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::InvalidConfiguration,Input.Instance,"Quic.Uuid"});
        auto Record=Prism::Protocols::ValidateQuicAuthentication(Input,Services.Authentication);
        if(!Record)return std::unexpected(Record.error());
        Prepared Result(std::move(Input),std::move(Services),std::move(*Record));Result.Uuid=*Uuid;return Result;
    }
}
