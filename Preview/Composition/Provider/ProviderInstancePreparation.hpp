/** @file ProviderInstancePreparation.hpp @brief 每个正式 proxy provider 的唯一冷 credential/Prepare 分派。 */
#pragma once

#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>
#include <Preview/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Preview/Composition/Provider/ProviderCatalogTypes.hpp>

#include <expected>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace Preview::Composition::Provider::ProtocolProviderPreparation
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
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        BindingServices Services;
    };

    /** @brief 只接受 ProtocolCatalog 中具有真实 TCP 或 QUIC provider slot 的协议名。 */
    [[nodiscard]] inline auto Handles(const std::string_view Name) -> bool
    {
        const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Preview::Composition::Protocol::DescriptorKind::Protocol)
        {
            return false;
        }
        const auto Category = Descriptor->Slot().Category;
        return Category == Preview::Composition::Protocol::ProviderCategory::TcpProxy ||
            Category == Preview::Composition::Protocol::ProviderCategory::QuicProxy;
    }

    [[nodiscard]] inline auto PrepareSpecialTcp(Input Value, const Preview::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Preview::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Preview::Contract::ProtocolType::AnyTls)
        {
            auto Prepared = Preview::Anytls::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Streams);
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Preview::Contract::ProtocolType::TrustTunnel)
        {
            auto Prepared = Preview::Trusttunnel::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Quic.Listener.Tls);
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return std::unexpected(Preview::Contract::ProviderFailure{
            Preview::Contract::ProviderError::UnsupportedInstance, Protocol.Id, "ProviderSlot"});
    }    [[nodiscard]] inline auto PrepareStandardTcp(Input Value, const Preview::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Preview::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Preview::Contract::ProtocolType::Http)
        {
            auto Prepared = Preview::Http11::PrepareProviderBinding(
                Protocol.Id, std::move(Instance.Authentication), Value.Services.Executor);
            if (!Prepared) return std::unexpected(Prepared.error());
            Prepared->Instance = Protocol.Id;
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Preview::Contract::ProtocolType::Vless)
        {
            auto Prepared = Preview::Vless::PrepareProviderBinding(Preview::Vless::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableUdp = Instance.Udp});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Preview::Contract::ProtocolType::Trojan)
        {
            auto Prepared = Preview::Trojan::PrepareProviderBinding(Preview::Trojan::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableTcp = Instance.Tcp, .EnableUdp = Instance.Udp, .EnableMux = true});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Preview::Contract::ProtocolType::Vmess)
        {
            auto Prepared = Preview::Vmess::PrepareProviderBinding(Preview::Vmess::ProviderRequest{
                .Instance = Protocol.Id, .Authentication = std::move(Instance.Authentication),
                .Datagrams = Value.Services.Associations,
                .GenerationUseState = Value.UseState, .Executor = Value.Services.Executor,
                .EnableUdp = Instance.Udp, .EnableMux = true});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return PrepareSpecialTcp(std::move(Value), Type);
    }

    [[nodiscard]] inline auto PrepareTcp(Input Value, const Preview::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Preview::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (Type == Preview::Contract::ProtocolType::Socks5)
        {
            Preview::Socks5::ServerConfig Config;
            Config.EnableTcp = Instance.Tcp;
            Config.EnableUdp = Instance.Udp;
            Config.EnableAuth = true;
            auto Prepared = Preview::Socks5::Prepare(
                {Protocol.Id, Value.Generation, std::move(Config)},
                {Value.Services.Executor, std::move(Instance.Authentication), Value.Services.Associations});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        if (Type == Preview::Contract::ProtocolType::Shadowsocks)
        {
            Preview::Shadowsocks2022::BindingConfig Config;
            Config.EnableTcp = Instance.Tcp;
            Config.RawUdp = Instance.Udp;
            auto Prepared = Preview::Shadowsocks2022::Prepare(
                {Protocol.Id, Value.Generation, Config},
                {Value.Services.Executor, std::move(Instance.Authentication), Value.Services.Egress,
                    Value.Services.Sender, Value.Services.Associations.Traffic});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        return PrepareStandardTcp(std::move(Value), Type);
    }

    [[nodiscard]] inline auto PrepareQuic(Input Value,
        const Preview::Composition::Protocol::ProtocolDescriptor& Descriptor, State& Catalog)
        -> std::expected<PreparedInstance, Preview::Contract::ProviderFailure>
    {
        auto& Instance = Value.Instance;
        const auto& Protocol = Instance.Protocol;
        if (!Protocol.Quic)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidConfiguration, Protocol.Id, "Quic"});
        }
        if (Catalog.QuicListenerUsed)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::AmbiguousListener, Protocol.Id, "Quic.Listener"});
        }
        if (!Value.Services.Quic.Listener.Sender)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingSender, Protocol.Id, "Quic.Sender"});
        }
        Catalog.QuicListenerUsed = true;
        Preview::Protocols::QuicPreparation Request{Protocol.Id, Value.Generation, *Protocol.Quic};
        if (Descriptor.Id == Preview::Contract::ProtocolType::Hysteria2)
        {
            auto Prepared = Preview::Hysteria2::Prepare(std::move(Request),
                {Value.Services.Quic, std::move(Instance.Authentication), Value.Services.Http3});
            if (!Prepared) return std::unexpected(Prepared.error());
            return PreparedInstance{std::move(*Prepared)};
        }
        auto Prepared = Preview::Tuic::Prepare(std::move(Request),
            {Value.Services.Quic, std::move(Instance.Authentication)});
        if (!Prepared) return std::unexpected(Prepared.error());
        return PreparedInstance{std::move(*Prepared)};
    }

    [[nodiscard]] inline auto Prepare(Input Value, State& Catalog)
        -> std::expected<PreparedInstance, Preview::Contract::ProviderFailure>
    {
        const auto& Protocol = Value.Instance.Protocol;
        if (!Catalog.Seen.emplace(Protocol.Id).second)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::DuplicateInstance, Protocol.Id, "Id"});
        }
        const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
        if (!Descriptor || !Handles(Protocol.Builtin))
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::UnsupportedInstance, Protocol.Id, "Builtin"});
        }
        if (Descriptor->Slot().Category == Preview::Composition::Protocol::ProviderCategory::QuicProxy)
        {
            return PrepareQuic(std::move(Value), *Descriptor, Catalog);
        }
        return PrepareTcp(std::move(Value), Descriptor->Id);
    }


}
