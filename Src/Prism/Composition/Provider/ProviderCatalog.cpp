/** @file ProviderCatalog.cpp @brief typed provider Prepare/Freeze/Bind 事务实现。 */

#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Provider/ProviderInstancePreparation.hpp>
#include <Prism/Composition/Detail/BoundCatalogOwnerClosure.hpp>

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Composition::Provider
{

    FrozenCatalog::FrozenCatalog(FrozenCatalog&& Other) noexcept
        : Entries_(std::move(Other.Entries_)), MuxValues_(std::move(Other.MuxValues_)),
          UseState_(std::move(Other.UseState_)),
          Bound_(std::exchange(Other.Bound_, true))
    {
    }

    FrozenCatalog::FrozenCatalog(std::vector<PreparedInstance> Values,
        std::vector<PreparedMux> MuxValues,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), MuxValues_(std::move(MuxValues)),
          UseState_(std::move(UseState))
    {
    }

    PreparedCatalog::PreparedCatalog(PreparedCatalog&& Other) noexcept
        : Entries_(std::move(Other.Entries_)), MuxValues_(std::move(Other.MuxValues_)),
          UseState_(std::move(Other.UseState_)),
          Frozen_(std::exchange(Other.Frozen_, true))
    {
    }

    PreparedCatalog::PreparedCatalog(std::vector<PreparedInstance> Values,
        std::vector<PreparedMux> MuxValues,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), MuxValues_(std::move(MuxValues)),
          UseState_(std::move(UseState))
    {
    }

    template<typename T>
    auto FrozenCatalog::InstanceId(const T& Value) -> std::string
    {
        if constexpr (requires { Value.Input.Instance; })
        {
            return Value.Input.Instance;
        }
        else
        {
            return Value.Instance;
        }
    }

    template<typename T>
    auto FrozenCatalog::BindInstance(T Value, const std::stop_token Stop)
        -> std::expected<BoundInstance, Prism::Contract::ProviderFailure>
    {
        const auto Id = InstanceId(Value);
        if constexpr (std::is_same_v<T, Prism::Socks5::Prepared>)
        {
            auto Bound = Prism::Socks5::Bind(std::move(Value), Stop);
            if (!Bound) return std::unexpected(Bound.error());
            return BoundInstance{Id, Prism::Contract::ProtocolType::Socks5, std::move(*Bound)};
        }
        else if constexpr (std::is_same_v<T, Prism::Shadowsocks2022::Prepared>)
        {
            auto Bound = Prism::Shadowsocks2022::Bind(std::move(Value), Stop);
            if (!Bound) return std::unexpected(Bound.error());
            return BoundInstance{Id, Prism::Contract::ProtocolType::Shadowsocks, std::move(*Bound)};
        }
        else if constexpr (std::is_same_v<T, Prism::Hysteria2::Prepared>)
        {
            auto Bound = Prism::Hysteria2::Bind(std::move(Value), Stop);
            if (!Bound) return std::unexpected(Bound.error());
            return BoundInstance{Id, Prism::Contract::ProtocolType::Hysteria2, std::move(*Bound)};
        }
        else if constexpr (std::is_same_v<T, Prism::Tuic::Prepared>)
        {
            auto Bound = Prism::Tuic::Bind(std::move(Value), Stop);
            if (!Bound) return std::unexpected(Bound.error());
            return BoundInstance{Id, Prism::Contract::ProtocolType::Tuic, std::move(*Bound)};
        }
        else if constexpr (std::is_same_v<T, Prism::Http11::PreparedBinding>)
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::Http,
                Prism::Http11::BindProvider(std::move(Value))};
        }
        else if constexpr (std::is_same_v<T, Prism::Vless::PreparedBinding>)
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::Vless,
                Prism::Vless::BindProvider(std::move(Value))};
        }
        else if constexpr (std::is_same_v<T, Prism::Trojan::PreparedBinding>)
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::Trojan,
                Prism::Trojan::BindProvider(std::move(Value))};
        }
        else if constexpr (std::is_same_v<T, Prism::Vmess::PreparedBinding>)
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::Vmess,
                Prism::Vmess::BindProvider(std::move(Value))};
        }
        else if constexpr (std::is_same_v<T, Prism::Anytls::PreparedBinding>)
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::AnyTls,
                Prism::Anytls::BindProvider(std::move(Value))};
        }
        else
        {
            if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Id, "Bind"});
            return BoundInstance{Id, Prism::Contract::ProtocolType::TrustTunnel,
                Prism::Trusttunnel::BindProvider(std::move(Value))};
        }
    }

    auto FrozenCatalog::CloseEntries(std::vector<BoundInstance>& Values) -> void
    {
        for (auto It = Values.rbegin(); It != Values.rend(); ++It)
        {
            std::visit([](const auto& Owner)
            {
                BoundCatalog::CloseOwner(Owner);
            }, It->Owner);
        }
    }

    auto FrozenCatalog::CloseMuxes(std::vector<BoundMux>& Values) noexcept -> void
    {
        for (auto It = Values.rbegin(); It != Values.rend(); ++It)
        {
            It->Close();
        }
    }

    auto FrozenCatalog::Bind(const std::stop_token Stop)
        -> std::expected<BoundCatalog, Prism::Contract::ProviderFailure>
    {
        using Error = Prism::Contract::ProviderError;
        if (Bound_)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{Error::AlreadyBound, {}, "Bind"});
        }
        Bound_ = true;
        std::vector<BoundInstance> Result;
        auto MuxValues = std::move(MuxValues_);
        for (auto& Value : Entries_)
        {
            auto Entry = std::visit([Stop](auto& Prepared)
                -> std::expected<BoundInstance, Prism::Contract::ProviderFailure>
            {
                return BindInstance(std::move(Prepared), Stop);
            }, Value);
            if (!Entry)
            {
                CloseEntries(Result);
                return std::unexpected(Entry.error());
            }
            Result.push_back(std::move(*Entry));
            if (Stop.stop_requested())
            {
                CloseEntries(Result);
                return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Bind"});
            }
        }
        Entries_.clear();
        std::vector<BoundMux> BoundMuxes;
        for (auto& Value : MuxValues)
        {
            auto Bound = Prism::Composition::Provider::BindMux(std::move(Value), Stop.stop_requested());
            if (!Bound)
            {
                CloseEntries(Result);
                CloseMuxes(BoundMuxes);
                return std::unexpected(Bound.error());
            }
            BoundMuxes.push_back(std::move(*Bound));
            if (Stop.stop_requested())
            {
                CloseEntries(Result);
                CloseMuxes(BoundMuxes);
                return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Bind"});
            }
        }
        MuxValues.clear();
        if (Stop.stop_requested())
        {
            CloseEntries(Result);
            CloseMuxes(BoundMuxes);
            return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Publish"});
        }
        return BoundCatalog(std::move(Result), std::move(BoundMuxes), std::move(UseState_));
    }

    auto PreparedCatalog::Freeze()
        -> std::expected<FrozenCatalog, Prism::Contract::ProviderFailure>
    {
        if (Frozen_)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::AlreadyFrozen, {}, "Freeze"});
        }
        Frozen_ = true;
        return FrozenCatalog(std::move(Entries_), std::move(MuxValues_), std::move(UseState_));
    }

    auto ProviderCatalog::Prepare(Preparation Input, BindingServices Services)
        -> std::expected<PreparedCatalog, Prism::Contract::ProviderFailure>
    {
        auto MuxValues = Prism::Composition::Provider::PrepareMuxes(
            MuxCatalogPreparation{Input.Bindings, Input.Instances, Services.Streams,
                Input.Generation, Input.UseState});
        if (!MuxValues)
        {
            return std::unexpected(MuxValues.error());
        }
        ProtocolProviderPreparation::State State;
        std::vector<PreparedInstance> Values;
        Values.reserve(Input.Instances.size());
        for (auto& Instance : Input.Instances)
        {
            auto Prepared = ProtocolProviderPreparation::Prepare(
                ProtocolProviderPreparation::Input{
                    std::move(Instance), Input.Generation, Input.UseState, Services}, State);
            if (!Prepared) return std::unexpected(Prepared.error());
            Values.push_back(std::move(*Prepared));
        }
        return PreparedCatalog(std::move(Values), std::move(*MuxValues), std::move(Input.UseState));
    }

    auto Compile(ConfigurationInput Input, BindingServices Services)
        -> std::expected<PreparedCatalog, Prism::Contract::ProviderFailure>
    {
        Preparation Request{Input.Generation, Input.UseState, {}, {}};
        Request.Bindings.assign(Input.Bindings.begin(), Input.Bindings.end());
        for (const auto& Protocol : Input.Protocols)
        {
            if (!ProviderCatalog::Handles(Protocol.Builtin))
            {
                continue;
            }
            ConfiguredInstance Instance{Protocol, false, false, {}};
            bool HasBinding = false;
            for (const auto& Binding : Input.Bindings)
            {
                if (Binding.ProtocolId == Protocol.Id)
                {
                    HasBinding = true;
                    Instance.Tcp = Instance.Tcp || Binding.TcpEnabled;
                    Instance.Udp = Instance.Udp || Binding.UdpEnabled;
                }
            }
            if (!HasBinding)
            {
                Instance.Tcp = true;
            }
            const auto Found = Input.Authentication.find(Protocol.Id);
            if (Found != Input.Authentication.end())
            {
                Instance.Authentication = Found->second;
            }
            Request.Instances.push_back(std::move(Instance));
        }
        return ProviderCatalog::Prepare(std::move(Request), std::move(Services));
    }

    auto ProviderCatalog::Handles(const std::string_view Name) -> bool
    {
        return ProtocolProviderPreparation::Handles(Name);
    }

} // namespace Prism::Composition::Provider
