/** @file OperationsStreamQuery.hpp @brief 管理面 Mux stream 快照的精确身份查询。 */
#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
#include <Preview/Operations/Models.hpp>

#include <memory>
#include <optional>
#include <utility>

namespace Preview::Application::OperationsStartup
{
    /** @brief 把真实 catalog 能力缺失映射到既有 Unavailable 结果和 HTTP 503。 */
    [[nodiscard]] inline auto MakeStreamCatalogUnavailable(
        const Preview::RequestId Correlation) -> Preview::Operations::QueryResult
    {
        auto Result = Preview::Operations::QueryResult::Unavailable(Correlation);
        Result.Message = "stream_catalog_unavailable";
        return Result;
    }

    [[nodiscard]] inline auto MakeStreamSnapshot(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Contract::Ingress::StreamDescriptor &Value)
        -> std::optional<Preview::Operations::StreamSnapshot>
    {
        Preview::Operations::StreamSnapshot Snapshot;
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
        case Preview::Contract::Ingress::StreamProtocol::Smux: Snapshot.Protocol = "Smux"; break;
        case Preview::Contract::Ingress::StreamProtocol::Yamux: Snapshot.Protocol = "Yamux"; break;
        case Preview::Contract::Ingress::StreamProtocol::H2Mux: Snapshot.Protocol = "H2Mux"; break;
        default: return std::nullopt;
        }
        Snapshot.Active = Value.State == Preview::Contract::Ingress::StreamState::Active;
        if (State->Traffic)
        {
            Snapshot.Traffic = State->Traffic->StreamValue(Snapshot.Session, Snapshot.Id);
        }
        return Snapshot;
    }

    /** @brief 按完整父身份查询真实 Mux stream catalog；退休流返回 NotFound。 */
    [[nodiscard]] inline auto MakeOperationsStreamQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::StreamQuery &QueryValue)
        -> Preview::Operations::QueryResult
    {
        using Preview::Contract::Ingress::StreamCatalogStatus;
        using Preview::Operations::QueryResult;
        using Preview::Operations::StreamSnapshot;
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
        const Preview::Contract::Ingress::StreamIdentity Identity{
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
        Preview::Operations::Page<StreamSnapshot> Page;
        Page.Items.push_back(*Snapshot);
        return QueryResult::Streams(QueryValue.Correlation, std::move(Page));
    }

    /** @brief 按完整 session 父身份返回有界真实 stream registry 快照。 */
    [[nodiscard]] inline auto MakeOperationsStreamListQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::StreamListQuery &QueryValue)
        -> Preview::Operations::QueryResult
    {
        using Preview::Contract::Ingress::StreamCatalogStatus;
        using Preview::Operations::QueryResult;
        if (!State || !State->Process || !State->Listener)
            return QueryResult::Unavailable(QueryValue.Correlation);
        if (!QueryValue.Process || !QueryValue.Generation || !QueryValue.Worker || !QueryValue.Session)
            return QueryResult::Invalid(QueryValue.Correlation);
        if (QueryValue.Process != State->Process->Id())
            return QueryResult::NotFound(QueryValue.Correlation);
        const Preview::Contract::Ingress::StreamListRequest Request{
            {QueryValue.Session, QueryValue.Worker, QueryValue.Generation},
            QueryValue.Page.Cursor, QueryValue.Page.BoundedLimit()};
        const auto Snapshot = State->Listener->Registry().ListStreams(Request);
        if (Snapshot.Status == StreamCatalogStatus::NotFound)
            return QueryResult::NotFound(QueryValue.Correlation);
        if (Snapshot.Status == StreamCatalogStatus::CapabilityUnavailable)
            return MakeStreamCatalogUnavailable(QueryValue.Correlation);
        Preview::Operations::Page<Preview::Operations::StreamSnapshot> Page;
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
}
