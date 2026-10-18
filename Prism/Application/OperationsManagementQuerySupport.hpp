/**
 * @file OperationsManagementQuerySupport.hpp
 * @brief Operations 管理查询共享的账户与入口快照构造器。
 */

#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Statistics/Statistics.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::OperationsManagementQueries
{
    using RuntimeState = Prism::Application::Application::RuntimeState;

    [[nodiscard]] inline auto FindProtocol(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        std::string_view Id) -> const Prism::Contract::ProtocolConfiguration *;
    [[nodiscard]] inline auto FindCarrier(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        std::string_view Id) -> const Prism::Contract::CarrierConfiguration *;
    [[nodiscard]] inline auto BindingMatchesTransport(
        const Prism::Contract::ProtocolBindingConfiguration &Binding,
        const Prism::Contract::ProtocolConfiguration &Protocol, std::string_view Transport) -> bool;

    /** @brief 同一 generation 与 admission 发布记录下的账户只读事实。 */
    struct ManagementAccountSnapshotContext final
    {
        const std::shared_ptr<RuntimeState> &State;
        std::shared_ptr<const Prism::Application::RuntimeGenerationSnapshot> Generation;
        Prism::Contract::AccountAdmissionAuthority::SnapshotPin Admission;
    };

    template <typename BindingValue>
    [[nodiscard]] inline auto MakeAccountValue(
        const ManagementAccountSnapshotContext &Snapshot,
        const BindingValue &Binding) -> Prism::Operations::AccountSnapshot
    {
        Prism::Operations::AccountSnapshot Item;
        Item.Id = Binding->AccountId();
        Item.Generation = Snapshot.Generation->Id();
        Item.ActiveSessions = Binding->Runtime()->ActiveConnections();
        Item.Label = std::string(Binding->Materials()->DisplayIdentity());
        const auto &Configured = Snapshot.Generation->Generation->Configuration().Accounts;
        const auto Entry = std::find_if(Configured.begin(), Configured.end(),
            [&Item](const auto &Value) { return Value.Id == Item.Label; });
        if (Entry != Configured.end()) Item.GroupId = Entry->GroupId;
        Item.Revoked = !Snapshot.Admission->IsAdmitted(Item.Id);
        if (Snapshot.State->Traffic)
            Item.Traffic = Snapshot.State->Traffic->Value(
                Prism::Statistics::Scope::Account, Item.Id.Value());
        return Item;
    }

    struct AccountSnapshotCollector final
    {
        std::vector<Prism::Operations::AccountSnapshot> &Values;
        const ManagementAccountSnapshotContext &Snapshot;

        template <typename BindingValue>
        auto operator()(const BindingValue &Binding) const -> void
        {
            Values.push_back(MakeAccountValue(Snapshot, Binding));
        }
    };

    /** @brief 一个传输入口的配置身份与当前运行状态。 */
    struct IngressTransportSnapshot final
    {
        std::string_view Transport;
        bool Ready;
        std::optional<std::string> BoundAddress;
        std::optional<std::uint64_t> ActiveConnections;
    };

    /** @brief 把配置绑定和入口运行状态投影为 owning 管理快照。 */
    struct IngressSnapshotBuilder final
    {
        const Prism::Application::Configuration::PrismConfiguration &Configuration;
        std::vector<Prism::Operations::IngressSnapshot> &Values;

        template <typename EndpointCollection>
        auto Append(const EndpointCollection &Endpoints,
            const IngressTransportSnapshot &Runtime) const -> void
        {
            for (std::size_t Index = 0; Index < Endpoints.size(); ++Index)
            {
                const auto &Endpoint = Endpoints[Index];
                Prism::Operations::IngressSnapshot Item;
                Item.Id = Endpoint.Id;
                Item.Transport = std::string(Runtime.Transport);
                Item.ConfiguredAddress = Endpoint.Address + ":" + std::to_string(Endpoint.Port);
                if (Index == 0U) Item.BoundAddress = Runtime.BoundAddress;
                Item.Ready = Index == 0U && Runtime.Ready;
                if (Index == 0U) Item.ActiveConnections = Runtime.ActiveConnections;
                for (const auto &Binding : Configuration.ProtocolBindings)
                {
                    const auto *Protocol = FindProtocol(Configuration, Binding.ProtocolId);
                    if (!Protocol || !BindingMatchesTransport(Binding, *Protocol, Runtime.Transport))
                        continue;
                    Item.Protocols.push_back(Protocol->Name);
                    if (Binding.CarrierId)
                    {
                        const auto *Carrier = FindCarrier(Configuration, *Binding.CarrierId);
                        Item.Carriers.push_back(Carrier ? Carrier->Name : *Binding.CarrierId);
                    }
                }
                Values.push_back(std::move(Item));
            }
        }
    };

    /** @brief 一次入口查询所需的 query、健康读数与 correlation。 */
    struct IngressesQueryRequest final
    {
        const Prism::Operations::IngressesRead &Query;
        const Prism::Statistics::HealthSnapshot &Health;
        Prism::RequestId Correlation;
    };


    [[nodiscard]] inline auto FindProtocol(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        const std::string_view Id) -> const Prism::Contract::ProtocolConfiguration *
    {
        const auto It = std::find_if(Configuration.Protocols.begin(), Configuration.Protocols.end(),
            [Id](const auto &Value) { return Value.Id == Id; });
        return It == Configuration.Protocols.end() ? nullptr : std::addressof(*It);
    }

    [[nodiscard]] inline auto FindCarrier(
        const Prism::Application::Configuration::PrismConfiguration &Configuration,
        const std::string_view Id) -> const Prism::Contract::CarrierConfiguration *
    {
        const auto It = std::find_if(Configuration.Carriers.begin(), Configuration.Carriers.end(),
            [Id](const auto &Value) { return Value.Id == Id; });
        return It == Configuration.Carriers.end() ? nullptr : std::addressof(*It);
    }

    [[nodiscard]] inline auto BindingMatchesTransport(
        const Prism::Contract::ProtocolBindingConfiguration &Binding,
        const Prism::Contract::ProtocolConfiguration &Protocol, const std::string_view Transport) -> bool
    {
        if (Transport == "tcp") return Binding.TcpEnabled && !Protocol.Quic;
        if (Transport == "quic") return Binding.UdpEnabled && Protocol.Quic.has_value();
        return Binding.UdpEnabled && !Protocol.Quic;
    }

} // namespace Prism::Application::OperationsManagementQueries
