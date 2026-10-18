/** @file ProviderBindings.hpp @brief 现存协议测试直接建立正式 Prepared/Binding；测试材料不进入生产。 */
#pragma once
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <boost/asio/system_executor.hpp>
#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace Prism::Testing
{
    inline constexpr std::array<std::uint8_t, 16> Ss2022FixturePsk{
        0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
        0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
    /** @brief fixture账户的唯一凭据域；同一view按该ordinal覆盖全部测试账户材料。 */
    inline constexpr Prism::Account::CredentialScope ProviderScope{1U};
    class ProviderGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit ProviderGeneration(Prism::GenerationId Value):Value_(Value){}
        auto Id() const noexcept->Prism::GenerationId override{return Value_;}
    private:
        Prism::GenerationId Value_;
    };
    /**
     * @brief fixture认证器pin实际store与账户准入publication。
     * @details view只共享store state，RuntimeRegistry只弱引用authority；认证器随binding保活时也要
     *          保活store与publication，才能在最终lease admission中验证同一发布账户集合。
     */
    class ProviderAuthenticator final : public Prism::Authenticator
    {
    public:
        ProviderAuthenticator(std::shared_ptr<Prism::Account::AccountStore> Store,
            Prism::Account::CredentialIndexView View,
            std::shared_ptr<Prism::Runtime::GenerationPublication> Publication)
            : Store_(std::move(Store)), Delegate_(std::move(View)),
              Publication_(std::move(Publication)) {}
        [[nodiscard]] auto InspectCredential(const Prism::Account::CredentialView& Credential) const noexcept
            ->std::expected<bool,Prism::Fault::Failure> override
        {return Delegate_.InspectCredential(Credential);}
        [[nodiscard]] auto Authenticate(const Prism::AuthenticationRequest& Request) const noexcept
            ->Prism::AuthenticationResult override
        {return Delegate_.Authenticate(Request);}
    private:
        std::shared_ptr<Prism::Account::AccountStore> Store_;
        Prism::DirectoryAuthenticator Delegate_;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication_;
    };
    /** @brief 单账户fixture持有store/view/认证器及其正式账户准入publication。 */
    struct ProviderAccounts final
    {
        std::shared_ptr<Prism::Account::AccountStore> Store;
        Prism::Account::CredentialIndexView Credentials;
        Prism::SharedAuthenticator Authenticator;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication;
        Prism::Foundation::GenerationPin Generation;
    };
    inline auto ProviderPin()->Prism::Foundation::GenerationPin
    {
        return std::make_shared<ProviderGeneration>(Prism::GenerationId{1});
    }
    /** @brief 单账户fixture的完整冷输入；Identity/DisplayIdentity直接进入正式materials。 */
    struct ProviderAccountInput final
    {
        Prism::AccountId Id;
        Prism::Account::Credential CredentialValue;
        std::string Identity;
        std::string DisplayIdentity;
        Prism::Account::QuotaPolicy Quota{};
    };
    /** @brief 以单条正式materials发布一个可认证fixture账户；失败不返回半成品owner。 */
    inline auto ProviderAccount(ProviderAccountInput Input,
        Prism::Foundation::GenerationPin Generation) ->std::shared_ptr<ProviderAccounts>
    {
        if (!Generation)
        {
            throw std::runtime_error("provider account generation pin is missing");
        }
        auto Result=std::make_shared<ProviderAccounts>();
        Result->Generation = Generation;
        Result->Store=std::make_shared<Prism::Account::AccountStore>();
        std::vector<Prism::Account::CredentialMaterial> Materials;
        Materials.push_back({ProviderScope,std::move(Input.Identity),std::move(Input.CredentialValue)});
        auto Owned=std::make_shared<const Prism::Account::AccountMaterials>(
            Prism::Account::AccountMaterials::CreateRequest{Input.Id,std::move(Input.DisplayIdentity),
                std::move(Materials)});
        auto Prepared=Result->Store->PrepareUpsert(Prism::Account::AccountDefinition{std::move(Owned),
            {.Quota=Input.Quota}});
        if(!Prepared)throw std::runtime_error("provider account prepare failed");
        if(!Result->Store->Commit(*Prepared))throw std::runtime_error("provider account commit failed");
        auto View=Result->Store->CompileScope(ProviderScope);
        if(!View)throw std::runtime_error("provider account scope failed");
        Result->Credentials=std::move(*View);
        auto Publication = std::make_shared<Prism::Runtime::GenerationPublication>();
        auto PreparedPublication = Publication->Prepare({}, std::move(Generation), {Input.Id});
        if (!PreparedPublication)
        {
            throw std::runtime_error("provider account publication prepare failed");
        }
        if (!Publication->Publish(*PreparedPublication))
        {
            throw std::runtime_error("provider account publication failed");
        }
        const auto Attached = Result->Store->RuntimeRegistry()->AttachAdmissionAuthority(Publication);
        if (!Attached)
        {
            throw std::runtime_error("provider account authority attachment failed");
        }
        Result->Publication = std::move(Publication);
        Result->Authenticator = std::make_shared<ProviderAuthenticator>(
            Result->Store, Result->Credentials, Result->Publication);
        return Result;
    }
    inline auto ProviderAccount(ProviderAccountInput Input) ->std::shared_ptr<ProviderAccounts>
    {
        return ProviderAccount(std::move(Input), ProviderPin());
    }
    inline auto ProviderAccount(Prism::Account::Credential Credential,
        Prism::AccountId Id=Prism::AccountId{1},
        Prism::Account::QuotaPolicy Quota={}) ->std::shared_ptr<ProviderAccounts>
    {
        return ProviderAccount(ProviderAccountInput{
            Id, std::move(Credential), "provider-fixture", "Provider Fixture", Quota});
    }
    inline auto MakeSocks5Binding(Prism::Socks5::ServerConfig Config,
        Prism::Contract::DatagramServices Services={}) ->std::shared_ptr<Prism::Socks5::Binding>
    {
        auto Accounts=ProviderAccount(Prism::Account::Credential::Password(
            "provider-fixture"));
        const auto Pin=Accounts->Generation;
        auto Auth=Config.Authenticator;
        if(!Auth)Auth=Accounts->Authenticator;
        if(!Services.Resolve)Services.Resolve=[](Prism::Network::Target Target)
            ->boost::asio::awaitable<std::expected<boost::asio::ip::udp::endpoint,Prism::Fault::Failure>>
        {
            const auto Address=Prism::Network::IpAddress(Target.Host);
            if (!Address) co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::UnsupportedAddress});
            co_return boost::asio::ip::udp::endpoint(*Address,Target.Port);
        };
        auto Prepared=Prism::Socks5::Prepare({"fixture",Pin,Config},{boost::asio::system_executor(),
            {Pin,Accounts->Credentials,Auth},std::move(Services)});
        if(!Prepared)throw std::runtime_error("SOCKS5 fixture prepare failed");
        auto Bound=Prism::Socks5::Bind(std::move(*Prepared),{});
        if(!Bound)throw std::runtime_error("SOCKS5 fixture bind failed");
        return *Bound;
    }
    inline auto MakeSs2022Binding(Prism::Shadowsocks2022::ServerConfig Config,
        std::shared_ptr<ProviderAccounts> Accounts)
        ->std::shared_ptr<Prism::Shadowsocks2022::Binding>
    {
        const auto Pin=Accounts->Generation;
        auto Auth=Config.Authenticator;
        if(!Auth)Auth=Accounts->Authenticator;
        auto Prepared=Prism::Shadowsocks2022::Prepare({"fixture",Pin,{.TimeWindow=Config.TimeWindow}},
            {boost::asio::system_executor(),{Pin,Accounts->Credentials,Auth},{},{},{}});
        if(!Prepared)throw std::runtime_error("SS2022 fixture prepare failed");
        auto Bound=Prism::Shadowsocks2022::Bind(std::move(*Prepared),{});
        if(!Bound)throw std::runtime_error("SS2022 fixture bind failed");
        return *Bound;
    }
    inline auto MakeSs2022Binding(Prism::Shadowsocks2022::ServerConfig Config)
        ->std::shared_ptr<Prism::Shadowsocks2022::Binding>
    {
        const auto Key=Config.Psk;
        const std::string Bytes(reinterpret_cast<const char*>(Key.data()),Key.size());
        return MakeSs2022Binding(Config,ProviderAccount(Prism::Account::Credential::Psk(Bytes)));
    }

    /** @brief 候选解析测试使用真实有退休 receipt 的 HTTP/1 binding owner。 */
    inline auto MakeHttp1Binding(
        std::string Instance = "http-fixture",
        boost::asio::any_io_executor Executor = boost::asio::system_executor())
        -> std::shared_ptr<Prism::Http11::Binding>
    {
        auto Accounts = ProviderAccount(Prism::Account::Credential::Password("provider-fixture"));
        const auto Pin = Accounts->Generation;
        auto Prepared = Prism::Http11::PrepareProviderBinding(
            std::move(Instance), {Pin, Accounts->Credentials, Accounts->Authenticator},
            std::move(Executor));
        if (!Prepared) throw std::runtime_error("HTTP1 fixture prepare failed");
        return Prism::Http11::BindProvider(std::move(*Prepared));
    }
}
