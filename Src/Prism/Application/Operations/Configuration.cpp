/** @file Configuration.cpp @brief Operations 安全配置视图、合并与查询实现。 */
#include <Prism/Application/Operations/Configuration.hpp>
#include <Prism/Application/Operations/Configuration/Detail/Query.hpp>

#include <glaze/glaze.hpp>
#include <expected>
#include <memory>
#include <string>
#include <utility>

namespace Prism::Application::OperationsConfiguration
{

    [[nodiscard]] auto MakeQuery(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const Prism::Operations::ConfigurationQuery &Query)
        -> Prism::Operations::QueryResult
    {
        if (!State)
        {
            return Prism::Operations::QueryResult::Unavailable(Query.Correlation);
        }
        const auto Snapshot = State->ActiveGenerationSnapshot();
        if (!Snapshot || !Snapshot->Generation)
        {
            return Prism::Operations::QueryResult::Unavailable(Query.Correlation);
        }
        auto Json = SerializePublicConfiguration(Snapshot->Generation->Configuration());
        if (!Json)
        {
            auto Result = Prism::Operations::QueryResult::Unavailable(Query.Correlation);
            Result.Message = Json.error().Code == Prism::Fault::Code::ResourceUnavailable
                ? "configuration_snapshot_limit"
                : "configuration_snapshot_failed";
            return Result;
        }
        Prism::Operations::ConfigurationSnapshot Value;
        Value.Generation = Snapshot->Id();
        Value.Reloadable = Snapshot->Generation->Configuration().HotReload.Enabled;
        Value.Json = std::move(*Json);
        return Prism::Operations::QueryResult::Configuration(Query.Correlation, std::move(Value));
    }

    [[nodiscard]] auto SerializePublicConfiguration(
        const Configuration::PrismConfiguration &Source)
        -> std::expected<std::string, Prism::Fault::Failure>
    {
        auto Json = glz::write_json(PublicView(Source));
        if (!Json)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ConfigErr});
        }
        if (Json->size() > MaxSafeConfigurationBytes)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        return std::move(*Json);
    }

    auto MergeExistingSecretSources(
        const Configuration::PrismConfiguration &Current,
        Configuration::PrismConfiguration &Candidate) -> void
    {
        for (auto &Account : Candidate.Accounts)
        {
            if (!Account.SecretRef.empty()) continue;
            for (const auto &Existing : Current.Accounts)
            {
                if (Existing.Id != Account.Id) continue;
                Account.Credential = Existing.Credential;
                Account.Credentials = Existing.Credentials;
                break;
            }
        }
        for (auto &Protocol : Candidate.Protocols)
        {
            if (!Protocol.Quic || !Protocol.Quic->Uuid.empty()) continue;
            for (const auto &Existing : Current.Protocols)
            {
                if (Existing.Id != Protocol.Id || !Existing.Quic) continue;
                Protocol.Quic->Uuid = Existing.Quic->Uuid;
                break;
            }
        }
    }

    [[nodiscard]] auto PublicView(const Configuration::PrismConfiguration &Source)
        -> PublicConfiguration
    {
        PublicConfiguration Result;
        Result.SchemaVersion = Source.SchemaVersion;
        Result.Runtime = Source.Runtime;
        Result.Listeners = Source.Listeners;
        Result.NativeTls = Source.NativeTls;
        Result.Builtins = Source.Builtins;
        Result.Protocols.reserve(Source.Protocols.size());
        for (const auto &Protocol : Source.Protocols)
        {
            ProtocolReference Item;
            Item.Id = Protocol.Id;
            Item.Name = Protocol.Name;
            Item.Builtin = Protocol.Builtin;
            Item.Requires = Protocol.Requires;
            if (Protocol.Quic)
            {
                const auto &Quic = *Protocol.Quic;
                Item.Quic = QuicReference{
                    Quic.Alpn, Quic.ServerName, Quic.CredentialSecretRef,
                    Quic.MaxStreams, Quic.MaxDatagrams};
            }
            Result.Protocols.push_back(std::move(Item));
        }
        Result.Carriers = Source.Carriers;
        Result.ProtocolBindings = Source.ProtocolBindings;
        Result.Recognition = Source.Recognition;
        Result.AccountGroups = Source.AccountGroups;
        Result.Accounts.reserve(Source.Accounts.size());
        for (const auto &Account : Source.Accounts)
        {
            Result.Accounts.push_back(AccountReference{Account.Id, Account.SecretRef, Account.GroupId,
                                                       Account.Policy});
        }
        Result.Routes = Source.Routes;
        Result.Dns = Source.Dns;
        Result.Logging = Source.Logging;
        Result.Trace = Source.Trace;
        Result.Statistics = Source.Statistics;
        Result.Operations = Source.Operations;
        Result.Storage = Source.Storage;
        Result.HotReload = Source.HotReload;
        Result.Shutdown = Source.Shutdown;
        return Result;
    }

}
