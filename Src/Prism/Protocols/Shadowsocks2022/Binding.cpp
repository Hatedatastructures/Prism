/** @file Binding.cpp @brief SS2022 provider、凭据绑定及最终关闭 owner 实现。 */
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Common/Authentication/ScopedMaterial.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Shadowsocks2022/TcpAdmission.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Prism::Shadowsocks2022
{
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>
    {
        const auto Psk=Prism::Shadowsocks2022::DecodePsk(Value);
        if(!Psk)return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::InvalidCredential,{},"Credential.Psk"});
        const std::string Bytes(reinterpret_cast<const char*>(Psk->data()),Psk->size());
        return Prism::Account::Credential::Psk(Bytes);
    }

    [[nodiscard]] auto Prepare(Preparation Input, BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>
    {
        using Error = Prism::Contract::ProviderError;
        auto Fail = [&Input](Error Code, std::string Path)
        { return std::unexpected(Prism::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)}); };
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
            Prism::Account::CredentialKind::Psk, [&](const auto& Binding, const auto& Material)
            {
                auto Credential = Prism::Protocols::ScopedMaterial::Pin(Binding, Material);
                if (!Credential || Material.Credential.View().Size() != 16) Invalid = Error::InvalidCredential;
                else Result.Credentials.push_back(std::move(*Credential));
            });
        if (!Enumerated) Invalid = Error::InvalidCredential;
        if (Invalid || Result.Credentials.empty()) return std::unexpected(Prism::Contract::ProviderFailure{
            Invalid.value_or(Error::InvalidCredential), Result.Input.Instance, "Accounts.Credential"});
        return Result;
    }
    [[nodiscard]] auto WireKey(const Prism::Protocols::ScopedMaterial& Record)
        -> std::array<std::uint8_t,16>
    {
        std::array<std::uint8_t,16> Key{};
        for (std::size_t I=0; I<Key.size(); ++I) Key[I]=std::to_integer<std::uint8_t>(Record.Material().Credential.View().Bytes()[I]);
        return Key;
    }

    BindingState::BindingState(Prepared Value):Material(std::make_shared<const Prepared>(std::move(Value))),
        Lifetime(std::make_shared<Prism::Protocols::BindingLifetime>(Material.load()->Services.Executor,Material.load()->Input.Generation))
    {if(Material.load()->Input.Config.RawUdp)Gateway=std::make_shared<Ss2022Gateway>(Material.load());}

    BindingState::~BindingState()
    {Close();}

    auto BindingState::Close() noexcept->void
    {Lifetime->Close();if(Gateway)Gateway->Close();for(const auto& Factory:MuxFactories)Factory->Close();}

    [[nodiscard]] auto BindingState::IsRetired() const noexcept -> bool
    {
        if (!Lifetime->IsRetired())
        {
            return false;
        }
        if (Gateway && !Gateway->IsRetired())
        {
            return false;
        }
        for (const auto& Factory : MuxFactories)
        {
            if (!Factory->IsRetired())
            {
                return false;
            }
        }
        return true;
    }

    auto BindingState::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Factories=MuxFactories;
        Close();
        auto FirstFailure=std::expected<void, Prism::Fault::Failure>{};
        for(const auto& Factory:Factories)
        {
            const auto Result=co_await Factory->Drain();
            if(!Result && FirstFailure)FirstFailure=std::unexpected(Result.error());
        }
        if(Gateway)
        {
            const auto GatewayDrain=co_await Gateway->Drain();
            if(!GatewayDrain && FirstFailure)FirstFailure=std::unexpected(GatewayDrain.error());
        }
        const auto ActivityDrain=co_await Lifetime->Drain();
        if(!ActivityDrain && FirstFailure)FirstFailure=std::unexpected(ActivityDrain.error());
        if(!FirstFailure)
        {
            if (IsRetired())
            {
                Material.store({});
                Gateway.reset();
                MuxFactories.clear();
            }
            co_return std::unexpected(FirstFailure.error());
        }
        Material.store({});
        Gateway.reset();
        MuxFactories.clear();
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto BindingState::Add(std::shared_ptr<Prism::Mux::RootBinding> Factory)->bool
    {if(!Factory||Lifetime->Closed())return false;MuxFactories.push_back(std::move(Factory));return true;}

    Binding::Binding(Prepared Value):State_(std::make_shared<BindingState>(std::move(Value)))
    {}

    Binding::Binding(std::shared_ptr<BindingState> State, std::shared_ptr<Prism::Mux::RootBinding> Mux)
        :State_(std::move(State)),Mux_(std::move(Mux))
    {}

    [[nodiscard]] auto Binding::WithMux(std::shared_ptr<Prism::Mux::RootBinding> Mux)->std::shared_ptr<Binding>
    {if(!State_->Add(Mux))return {};return std::shared_ptr<Binding>(new Binding(State_,std::move(Mux)));}

    [[nodiscard]] auto Binding::Inspect(std::span<const std::byte> Bytes) const -> Prism::Error
    {
        const auto Value=State_->Material.load();
        if (State_->Lifetime->Closed() || !Value)
        {
            return Prism::Error::NotOpen;
        }
        return InspectTcp(*Value,Bytes);
    }

    auto Binding::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto Inbound = std::move(Input.Inbound);
        [[maybe_unused]] auto Metadata = std::move(Input.Metadata);
        auto Bytes = std::move(Input.Bytes);
        auto PreparedAdmission =
            co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!PreparedAdmission)
        {
            co_return std::unexpected(PreparedAdmission.error());
        }
        auto Admission = std::move(*PreparedAdmission);
        const auto Value=State_->Material.load();
        if (!Inbound || !Bytes || !Value || State_->Lifetime->Closed() || !Value->Input.Config.EnableTcp)
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto Activity=State_->Lifetime->Enter(Inbound);
        if (!Activity || State_->Lifetime->Closed())
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto Carrier=std::make_shared<Prism::Protocols::BoundTransmission>(std::move(Activity));
        if (const auto Tracked = Admission.Track(Carrier); !Tracked)
        {
            co_return co_await Admission.Reject(Tracked.error());
        }
        co_return co_await AcceptTcp(
            TcpIngress{std::move(Carrier), Mux_, std::move(Bytes), std::move(Admission)},
            *Value);
    }

    auto Binding::Close() noexcept -> void
    {State_->Close();}

    auto Binding::Drain()-> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {co_return co_await State_->Drain();}

    [[nodiscard]] auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>
    {
        if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::Cancelled,Value.Input.Instance,"Bind"});
        auto Verified=Prepare(std::move(Value.Input),std::move(Value.Services));
        if(!Verified)return std::unexpected(Verified.error());
        auto Result=std::shared_ptr<Binding>(new Binding(std::move(*Verified)));
        if(Stop.stop_requested())
        {
            Result->Close();
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled,{},"Bind"});
        }
        return Result;
    }
}
