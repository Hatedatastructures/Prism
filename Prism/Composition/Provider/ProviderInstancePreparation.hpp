/** @file ProviderInstancePreparation.hpp @brief 每个正式 proxy provider 的唯一冷 credential/Prepare 分派。 */
#pragma once

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Composition/Provider/ProviderCatalogTypes.hpp>

#include <expected>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace Prism::Composition::Provider::ProtocolProviderPreparation
{
    /** @brief 一次 catalog Prepare 的重复项与 listener 唯一性状态。 */
    struct State final
    {
        std::unordered_set<std::string> Seen;
        bool QuicListenerUsed{false};
    };

    /** @brief 一个协议实例的 cold owner 输入；Prepare 同步消费配置和 service handles。 */
    struct Input final
    {
        ConfiguredInstance Instance;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        BindingServices Services;
    };

    /** @brief 只接受 ProtocolCatalog 中具有真实 TCP 或 QUIC provider slot 的协议名。 */
    [[nodiscard]] inline auto Handles(const std::string_view Name) -> bool
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
        {
            return false;
        }
        const auto Category = Descriptor->Slot().Category;
        return Category == Prism::Composition::Protocol::ProviderCategory::TcpProxy ||
            Category == Prism::Composition::Protocol::ProviderCategory::QuicProxy;
    }

    [[nodiscard]] inline auto PrepareSpecialTcp(Input Value, const Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Prism::Contract::ProtocolType::AnyTls)
        {
            auto Prepared = Prism::Anytls::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Streams);
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Prism::Contract::ProtocolType::TrustTunnel)
        {
            auto Prepared = Prism::Trusttunnel::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Quic.Listener.Tls);
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::UnsupportedInstance, Protocol.Id, "ProviderSlot"});
    }    [[nodiscard]] inline auto PrepareStandardTcp(Input Value, const Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Prism::Contract::ProtocolType::Http)
        {
            auto Prepared = Prism::Http11::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Executor);
            if (!Prepared) return std::unexpected(Prepared.error());
            Prepared->Instance = Protocol.Id;
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Prism::Contract::ProtocolType::Vless)
        {
            auto Prepared = Prism::Vless::PrepareProviderBinding(Prism::Vless::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableUdp = Instance.Udp});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Prism::Contract::ProtocolType::Trojan)
        {
            auto Prepared = Prism::Trojan::PrepareProviderBinding(Prism::Trojan::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableTcp = Instance.Tcp, .EnableUdp = Instance.Udp, .EnableMux = true});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Prism::Contract::ProtocolType::Vmess)
        {
            auto Prepared = Prism::Vmess::PrepareProviderBinding(Prism::Vmess::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableUdp = Instance.Udp, .EnableMux = true});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return PrepareSpecialTcp(std::move(Value), Type);
    }

    [[nodiscard]] inline auto PrepareTcp(Input Value, const Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Prism::Contract::ProtocolType::Socks5)
        {
            Prism::Socks5::ServerConfig Config;
            Config.EnableTcp = Instance.Tcp;
            Config.EnableUdp = Instance.Udp;
            Config.EnableAuth = true;
            auto Prepared = Prism::Socks5::Prepare(
                {Protocol.Id, Value.Generation, std::move(Config)},
                {Value.Services.Executor, std::move(Instance.Authentication), Value.Services.Associations});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Prism::Contract::ProtocolType::Shadowsocks)
        {
            Prism::Shadowsocks2022::BindingConfig Config;
            Config.EnableTcp = Instance.Tcp;
            Config.RawUdp = Instance.Udp;
            auto Prepared = Prism::Shadowsocks2022::Prepare(
                {Protocol.Id, Value.Generation, Config},
                {Value.Services.Executor, std::move(Instance.Authentication), Value.Services.Egress,
                    Value.Services.Sender, Value.Services.Associations.Traffic});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return PrepareStandardTcp(std::move(Value), Type);
    }

    [[nodiscard]] inline auto PrepareQuic(Input Value,
        const Prism::Composition::Protocol::ProtocolDescriptor& Descriptor, State& Catalog)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (!Protocol.Quic)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration, Protocol.Id, "Quic"});
        }
        if (Catalog.QuicListenerUsed)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::AmbiguousListener, Protocol.Id, "Quic.Listener"});
        }
        if (!Value.Services.Quic.Listener.Sender)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingSender, Protocol.Id, "Quic.Sender"});
        }
        Catalog.QuicListenerUsed = true;
        Prism::Protocols::QuicPreparation Request{Protocol.Id, Value.Generation, *Protocol.Quic};
        if (Descriptor.Id == Prism::Contract::ProtocolType::Hysteria2)
        {
            auto Prepared = Prism::Hysteria2::Prepare(std::move(Request),
                {Value.Services.Quic, std::move(Instance.Authentication), Value.Services.Http3});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        auto Prepared = Prism::Tuic::Prepare(std::move(Request),
            {Value.Services.Quic, std::move(Instance.Authentication)});
        if (!Prepared) return std::unexpected(Prepared.error());
        return PreparedInstance{std::move(*Prepared)};
    }

    [[nodiscard]] inline auto Prepare(Input Value, State& Catalog)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>
    {
        const auto& Protocol = Value.Instance.Protocol;
        if (!Catalog.Seen.emplace(Protocol.Id).second)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::DuplicateInstance, Protocol.Id, "Id"});
        }
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
        if (!Descriptor || !Handles(Protocol.Builtin))
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::UnsupportedInstance, Protocol.Id, "Builtin"});
        }
        if (Descriptor->Slot().Category == Prism::Composition::Protocol::ProviderCategory::QuicProxy)
        {
            return PrepareQuic(std::move(Value), *Descriptor, Catalog);
        }
        return PrepareTcp(std::move(Value), Descriptor->Id);
    }


}
