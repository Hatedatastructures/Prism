/** @file OperationsStreamQuery.cpp @brief Operations stream 查询快照实现。 */
#include <Prism/Application/OperationsStreamQuery.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>

#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Prism::Application::OperationsStartup
{

    [[nodiscard]] auto MakeOperationsStreamListQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::StreamListQuery &QueryValue)
        -> Prism::Operations::QueryResult
    {
        using Prism::Contract::Ingress::StreamCatalogStatus;
        using Prism::Operations::QueryResult;
        if (!State || !State->Process || !State->Listener)
            return QueryResult::Unavailable(QueryValue.Correlation);
        if (!QueryValue.Process || !QueryValue.Generation || !QueryValue.Worker || !QueryValue.Session)
            return QueryResult::Invalid(QueryValue.Correlation);
        if (QueryValue.Process != State->Process->Id())
            return QueryResult::NotFound(QueryValue.Correlation);
        const Prism::Contract::Ingress::StreamListRequest Request{
            {QueryValue.Session, QueryValue.Worker, QueryValue.Generation},
            QueryValue.Page.Cursor, QueryValue.Page.BoundedLimit()};
        const auto Snapshot = State->Listener->Registry().ListStreams(Request);
        if (Snapshot.Status == StreamCatalogStatus::NotFound)
            return QueryResult::NotFound(QueryValue.Correlation);
        if (Snapshot.Status == StreamCatalogStatus::CapabilityUnavailable)
            return MakeStreamCatalogUnavailable(QueryValue.Correlation);
        Prism::Operations::Page<Prism::Operations::StreamSnapshot> Page;
        Page.NextCursor = Snapshot.NextCursor;
        Page.HasMore = Snapshot.HasMore;
        Page.Items.reserve(Snapshot.Items.size());
        for (const auto &Descriptor : Snapshot.Items)
        {
            const auto Item = MakeStreamSnapshot(State, Descriptor);
            if (!Item) return MakeStreamCatalogUnavailable(QueryValue.Correlation);
            Page.Items.push_back(*Item);
        }
        return QueryResult::Streams(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] auto MakeOperationsStreamQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::StreamQuery &QueryValue)
        -> Prism::Operations::QueryResult
    {
        using Prism::Contract::Ingress::StreamCatalogStatus;
        using Prism::Operations::QueryResult;
        using Prism::Operations::StreamSnapshot;
        if (!State || !State->Process || !State->Listener)
        {
            return QueryResult::Unavailable(QueryValue.Correlation);
        }
        if (!QueryValue.Process || !QueryValue.Generation || !QueryValue.Worker ||
            !QueryValue.Session || !QueryValue.Id)
        {
            return QueryResult::Invalid(QueryValue.Correlation);
        }
        if (QueryValue.Process != State->Process->Id())
        {
            return QueryResult::NotFound(QueryValue.Correlation);
        }
        const Prism::Contract::Ingress::StreamIdentity Identity{
            QueryValue.Session, QueryValue.Worker, QueryValue.Generation, QueryValue.Id};
        const auto Lookup = State->Listener->Registry().FindStream(Identity);
        if (Lookup.Status == StreamCatalogStatus::NotFound)
        {
            return QueryResult::NotFound(QueryValue.Correlation);
        }
        if (Lookup.Status == StreamCatalogStatus::CapabilityUnavailable)
        {
            return MakeStreamCatalogUnavailable(QueryValue.Correlation);
        }
        const auto Snapshot = MakeStreamSnapshot(State, Lookup.Value);
        if (!Snapshot) return MakeStreamCatalogUnavailable(QueryValue.Correlation);
        Prism::Operations::Page<StreamSnapshot> Page;
        Page.Items.push_back(*Snapshot);
        return QueryResult::Streams(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] auto MakeStreamSnapshot(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Contract::Ingress::StreamDescriptor &Value)
        -> std::optional<Prism::Operations::StreamSnapshot>
    {
        Prism::Operations::StreamSnapshot Snapshot;
        Snapshot.Id = Value.Identity.Id;
        Snapshot.Task = Value.Task;
        Snapshot.ParentTask = Value.ParentTask;
        Snapshot.Process = State->Process->Id();
        Snapshot.Session = Value.Identity.Session;
        Snapshot.Account = Value.Account;
        Snapshot.Worker = Value.Identity.Worker;
        Snapshot.Generation = Value.Identity.Generation;
        switch (Value.Protocol)
        {
        case Prism::Contract::Ingress::StreamProtocol::Smux: Snapshot.Protocol = "Smux"; break;
        case Prism::Contract::Ingress::StreamProtocol::Yamux: Snapshot.Protocol = "Yamux"; break;
        case Prism::Contract::Ingress::StreamProtocol::H2Mux: Snapshot.Protocol = "H2Mux"; break;
        default: return std::nullopt;
        }
        Snapshot.Active = Value.State == Prism::Contract::Ingress::StreamState::Active;
        if (State->Traffic)
        {
            Snapshot.Traffic = State->Traffic->StreamValue(Snapshot.Session, Snapshot.Id);
        }
        return Snapshot;
    }

    [[nodiscard]] auto MakeStreamCatalogUnavailable(
        const Prism::RequestId Correlation) -> Prism::Operations::QueryResult
    {
        auto Result = Prism::Operations::QueryResult::Unavailable(Correlation);
        Result.Message = "stream_catalog_unavailable";
        return Result;
    }

}
