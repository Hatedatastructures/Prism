/** @file Prepared.hpp @brief SS2022 实例材料准备；全部 PSK 必须属于原 generation 的账户记录。 */
#pragma once
#include <Preview/Protocols/Common/Authentication/ScopedMaterial.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Services/DatagramEgress.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <expected>
namespace Preview::Shadowsocks2022
{
    struct BindingConfig final
    {
        bool EnableTcp{true};
        bool RawUdp{false};
        std::uint64_t TimeWindow{90};
        std::chrono::milliseconds RelayTimeout{2000};
        std::chrono::milliseconds PeerIdleTimeout{60000};
        std::size_t MaxPeers{1024};
    };
    struct Preparation final
    {
        std::string Instance;
        Preview::Foundation::GenerationPin Generation;
        BindingConfig Config;
    };
    struct BindingServices final
    {
        Net::any_io_executor Executor;
        Preview::Contract::AuthenticationServices Authentication;
        std::shared_ptr<Preview::Contract::DatagramEgress> Egress;
        std::shared_ptr<Preview::Contract::DatagramSender> Sender;
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic;
    };
    /** @brief 无活动 socket 的单次拥有值；记录拥有 SecureBytes，不保存 borrowed key span。 */
    struct Prepared final
    {
        Preparation Input;
        BindingServices Services;
        std::vector<Preview::Protocols::ScopedMaterial> Credentials;
        Prepared(Preparation InputValue, BindingServices ServicesValue)
            : Input(std::move(InputValue)), Services(std::move(ServicesValue)) {}
        Prepared(Prepared&&) = default;
        auto operator=(Prepared&&) -> Prepared& = default;
        Prepared(const Prepared&) = delete;
    };
    /** @brief 接管实际配置/材料/服务并验证；无 I/O，错误路径不含秘密，不产生租约。 */
    [[nodiscard]] inline auto Prepare(Preparation Input, BindingServices Services)
        -> std::expected<Prepared, Preview::Contract::ProviderFailure>
    {
        using Error = Preview::Contract::ProviderError;
        auto Fail = [&Input](Error Code, std::string Path)
        { return std::unexpected(Preview::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)}); };
        if (Input.Instance.empty() || !Services.Executor || (!Input.Config.EnableTcp && !Input.Config.RawUdp)
            || Input.Config.TimeWindow == 0 || Input.Config.MaxPeers == 0 || Input.Config.RelayTimeout.count() <= 0)
            return Fail(Error::InvalidConfiguration, "Options");
        if (!Services.Authentication.Matches(Input.Generation)) return Fail(Error::GenerationMismatch, "Generation");
        if (!Services.Authentication.Credentials || !Services.Authentication.Authenticator)
            return Fail(Error::MissingAuthentication, "Authentication");
        if (Input.Config.RawUdp && !Services.Egress) return Fail(Error::MissingResolver, "Datagrams.Egress");
        if (Input.Config.RawUdp && !Services.Sender) return Fail(Error::MissingSender, "Datagrams.Sender");
        Prepared Result(std::move(Input), std::move(Services));
        std::optional<Error> Invalid;
        const auto Enumerated = Result.Services.Authentication.Credentials.ForEachCredential(
            Preview::Account::CredentialKind::Psk, [&](const auto& Binding, const auto& Material)
            {
                auto Credential = Preview::Protocols::ScopedMaterial::Pin(Binding, Material);
                if (!Credential || Material.Credential.View().Size() != 16) Invalid = Error::InvalidCredential;
                else Result.Credentials.push_back(std::move(*Credential));
            });
        if (!Enumerated) Invalid = Error::InvalidCredential;
        if (Invalid || Result.Credentials.empty()) return std::unexpected(Preview::Contract::ProviderFailure{
            Invalid.value_or(Error::InvalidCredential), Result.Input.Instance, "Accounts.Credential"});
        return Result;
    }
    /** @brief 仅在协议 wire 边界复制固定长度工作 key；记录和秘密寿命继续由 owning credential 持有。 */
    [[nodiscard]] inline auto WireKey(const Preview::Protocols::ScopedMaterial& Record) -> std::array<std::uint8_t,16>
    {
        std::array<std::uint8_t,16> Key{};
        for (std::size_t I=0; I<Key.size(); ++I) Key[I]=std::to_integer<std::uint8_t>(Record.Material().Credential.View().Bytes()[I]);
        return Key;
    }
}
