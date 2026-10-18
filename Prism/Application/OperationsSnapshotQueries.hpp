/**
 * @file OperationsSnapshotQueries.hpp
 * @brief Application 所有的 Operations 健康与资源快照查询。
 */

#pragma once

#include <Prism/Account/Account.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Statistics/Statistics.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>

namespace Prism::Application::OperationsStartup
{
    [[nodiscard]] inline auto InvalidOperationsQuery(const Prism::RequestId Correlation)
        -> Prism::Operations::QueryResult
    {
        return Prism::Operations::QueryResult{Correlation, Prism::Operations::QueryStatus::Invalid,
            std::monostate{}, "query_invalid"};
    }
    [[nodiscard]] inline auto MakeOperationsHealth(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::HealthQuery& QueryValue) -> Prism::Operations::QueryResult
    {
        Prism::Operations::HealthSnapshot Health;
        const auto Phase = State->Phase.load(std::memory_order_acquire);
        switch (Phase)
        {
        case RuntimePhase::Ready:
            Health.Status = Prism::Operations::HealthStatus::Healthy;
            Health.Ready = true;
            break;
        case RuntimePhase::Stopping:
            Health.Status = Prism::Operations::HealthStatus::Draining;
            break;
        case RuntimePhase::Failed:
            Health.Status = Prism::Operations::HealthStatus::Unhealthy;
            Health.Errors = 1;
            break;
        case RuntimePhase::Created:
        case RuntimePhase::Stopped:
            Health.Status = Prism::Operations::HealthStatus::Unknown;
            break;
        }
        Health.CheckedAt =
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        if (State->Listener)
        {
            Health.Active = State->Listener->Registry().Size();
        }
        Health.TcpReady = State->Listener && State->Listener->IsReady();
        const auto DatagramReady = State->DatagramListener && State->DatagramListener->IsReady();
        const auto DatagramBound = State->DatagramListener && State->DatagramListener->IsBound();
        Health.UdpReady = DatagramReady;
        Health.UdpSocketReady = DatagramBound;
        Health.QuicReady = State->QuicConfigured && DatagramReady &&
                           State->Ready.QuicHandshakeReady && State->Ready.QuicProtocolReady;
        Health.QuicSocketReady = State->QuicConfigured && DatagramBound;
        Health.QuicHandshakeReady = State->Ready.QuicHandshakeReady;
        Health.QuicProtocolReady = State->Ready.QuicProtocolReady;
        Health.Ready = false;
        if (Phase == RuntimePhase::Ready && Health.TcpReady &&
            (!State->DatagramListener || Health.UdpReady) && (!State->QuicConfigured || Health.QuicReady))
        {
            Health.Ready = true;
        }
        if (Phase == RuntimePhase::Ready && !Health.Ready)
            Health.Status = Health.TcpReady ? Prism::Operations::HealthStatus::Degraded :
                                             Prism::Operations::HealthStatus::Unhealthy;
        if (State->Traffic)
        {
            Health.ProcessRetirementFailures.Session = State->Traffic->SessionRetirementFailures();
            Health.ProcessRetirementFailures.Stream = State->Traffic->StreamRetirementFailures();
            Health.ProcessRetirementFailures.Task = State->Traffic->TaskRetirementFailures();
        }
        return Prism::Operations::QueryResult::Health(QueryValue.Correlation, std::move(Health));
    }

    [[nodiscard]] inline auto MakeOperationsWorkers(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::WorkerQuery& QueryValue) -> Prism::Operations::QueryResult
    {
        Prism::Operations::Page<Prism::Operations::WorkerSnapshot> Page;
        if (State->Process)
        {
            for (const auto& Source : State->Process->Snapshot())
            {
                if (QueryValue.Id && QueryValue.Id != Source.Id)
                {
                    continue;
                }
                if (Source.Id.Value() <= QueryValue.Page.Cursor)
                {
                    continue;
                }
                if (Page.Items.size() >= QueryValue.Page.BoundedLimit())
                {
                    Page.HasMore = true;
                    break;
                }
                Prism::Operations::WorkerSnapshot Item;
                Item.Process = Source.Process;
                Item.Id = Source.Id;
                Item.Generation = Source.Generation;
                if (Source.Running)
                {
                    Item.Health.Status = Prism::Operations::HealthStatus::Healthy;
                }
                else
                {
                    Item.Health.Status = Prism::Operations::HealthStatus::Draining;
                }
                Item.Health.Ready = Source.Running;
                Item.Health.Active = Source.ActiveTasks;
                Item.Running = Source.Running;
                Item.Accepting = Source.Accepting;
                if (State->Traffic)
                {
                    Item.Traffic = State->Traffic->Value(Prism::Statistics::Scope::Worker, Source.Id.Value());
                    Item.DroppedEvents = State->Traffic->Dropped(Source.Id) +
                        State->Traffic->AggregationFailures(Source.Id);
                }
                Item.ActiveTasks = Source.ActiveTasks;
                Item.MailboxDepth = Source.MailboxSize; Item.MailboxCapacity = Source.MailboxCapacity;
                Item.StartedTasks = Source.StartedTasks; Item.CompletedTasks = Source.CompletedTasks;
                Item.CancelledTasks = Source.CancelledTasks; Item.DispatchAccepted = Source.DispatchAccepted;
                Item.DispatchFull = Source.DispatchFull; Item.DispatchClosed = Source.DispatchClosed;
                Item.DispatchUnavailable = Source.DispatchWorkerUnavailable;
                Item.DispatchGenerationRejected = Source.DispatchGenerationRejected;
                Item.CommandsExecuted = Source.CommandsExecuted; Item.CommandsFailed = Source.CommandsFailed;
                Page.Items.push_back(std::move(Item));
            }
        }
        if (!Page.Items.empty())
        {
            Page.NextCursor = Page.Items.back().Id.Value();
        }
        else
        {
            Page.NextCursor = QueryValue.Page.Cursor;
        }
        return Prism::Operations::QueryResult::Workers(QueryValue.Correlation, std::move(Page));
    }

    /** @brief 一次账户查询固定运行状态、generation 与同一发布记录的 admission。 */
    struct OperationsAccountQuerySnapshot final
    {
        std::shared_ptr<Application::RuntimeState> State;
        std::shared_ptr<const RuntimeGenerationSnapshot> Generation;
        Prism::Contract::AccountAdmissionAuthority::SnapshotPin Admission;
    };

    /** @brief 从唯一Binding派生账户值，不按配置位置重新猜测AccountId。 */
    [[nodiscard]] inline auto MakeOperationsAccount(
        const OperationsAccountQuerySnapshot &Snapshot,
        const std::shared_ptr<const Prism::Account::AccountBinding>& Binding)
        -> Prism::Operations::AccountSnapshot
    {
        Prism::Operations::AccountSnapshot Item;
        Item.Id = Binding->AccountId();
        Item.Generation = Snapshot.Generation->Id();
        Item.ActiveSessions = Binding->Runtime()->ActiveConnections();
        Item.Label = std::string(Binding->Materials()->DisplayIdentity());
        const auto &ConfiguredAccounts = Snapshot.Generation->Generation->Configuration().Accounts;
        const auto Configured = std::find_if(ConfiguredAccounts.begin(), ConfiguredAccounts.end(),
            [&Item](const auto &Value) { return Value.Id == Item.Label; });
        if (Configured != ConfiguredAccounts.end()) Item.GroupId = Configured->GroupId;
        Item.Revoked = !Snapshot.Admission->IsAdmitted(Binding->AccountId());
        if (Snapshot.State->Traffic)
            Item.Traffic = Snapshot.State->Traffic->Value(
                Prism::Statistics::Scope::Account, Item.Id.Value());
        return Item;
    }
    [[nodiscard]] inline auto MakeOperationsAccounts(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::AccountQuery& QueryValue) -> Prism::Operations::QueryResult
    {
        Prism::Operations::Page<Prism::Operations::AccountSnapshot> Page;
        if (!State || !State->GenerationPublisher)
            return Prism::Operations::QueryResult::Unavailable(QueryValue.Correlation);
        const auto Publication = State->GenerationPublisher->Read();
        const auto Generation = std::dynamic_pointer_cast<const RuntimeGenerationSnapshot>(
            Publication.Active);
        if (!Generation || !Generation->Accounts.Store || !Publication.Accounts)
            return Prism::Operations::QueryResult::Unavailable(QueryValue.Correlation);
        const OperationsAccountQuerySnapshot Snapshot{
            State, Generation, Publication.Accounts};
        Generation->Accounts.Store->ForEach([&](const auto& Binding)
        {
            if (QueryValue.Id && QueryValue.Id != Binding->AccountId()) return;
            if (Binding->AccountId().Value() <= QueryValue.Page.Cursor) return;
            if (Page.Items.size() >= QueryValue.Page.BoundedLimit()) { Page.HasMore = true; return; }
            Page.Items.push_back(MakeOperationsAccount(Snapshot, Binding));
        });
        if (!Page.Items.empty()) Page.NextCursor = Page.Items.back().Id.Value();
        else Page.NextCursor = QueryValue.Page.Cursor;
        return Prism::Operations::QueryResult::Accounts(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] inline auto MakeOperationsSessions(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::SessionQuery& QueryValue) -> Prism::Operations::QueryResult
    {
        Prism::Operations::Page<Prism::Operations::SessionSnapshot> Page;
        if (!State->Listener || !State->Process)
        {
            return Prism::Operations::QueryResult::Sessions(QueryValue.Correlation, std::move(Page));
        }
        const auto Snapshot = State->Listener->Registry().Snapshot();
        for (const auto& [RawId, Source] : *Snapshot)
        {
            const Prism::SessionId Id{RawId};
            if (QueryValue.Id && QueryValue.Id != Id)
            {
                continue;
            }
            if (RawId <= QueryValue.Page.Cursor)
            {
                continue;
            }
            if (Page.Items.size() >= QueryValue.Page.BoundedLimit())
            {
                Page.HasMore = true;
                break;
            }
            Prism::Operations::SessionSnapshot Item;
            Item.Id = Id;
            Item.Process = State->Process->Id();
            Item.Account = Source.AccountId;
            Item.Worker = Source.Worker;
            Item.Generation = Source.Generation;
            Item.StartedAt = Source.StartedAtUnixMilliseconds;
            Item.Identity = Source.identity; Item.SourceAddress = Source.peer;
            Item.Protocol = std::to_string(Source.Protocol);
            Item.Target = Source.Target;
            Item.Active = true;
            Item.Draining = State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready;
            Item.ActiveTasks = State->Listener->Registry().ActiveTasks(Id);
            if (State->Traffic)
                Item.Traffic = State->Traffic->Value(Prism::Statistics::Scope::Session, Id.Value());
            Page.Items.push_back(std::move(Item));
        }
        if (!Page.Items.empty())
        {
            Page.NextCursor = Page.Items.back().Id.Value();
        }
        else
        {
            Page.NextCursor = QueryValue.Page.Cursor;
        }
        return Prism::Operations::QueryResult::Sessions(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] inline auto MakeOperationsEvents(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::EventQuery& QueryValue) -> Prism::Operations::QueryResult
    {
        Prism::Statistics::EventPage Page;
        if (!State->Events)
        {
            return Prism::Operations::QueryResult::Events(QueryValue.Correlation, std::move(Page));
        }

        const auto Events = State->Events->Page(QueryValue.Page.Cursor, QueryValue.Page.BoundedLimit());
        Page.NextCursor = Events.NextCursor;
        Page.Dropped = Events.Dropped;
        Page.TerminalDropped = Events.TerminalDropped;
        Page.Overwritten = Events.Overwritten;
        Page.HasMore = Events.HasMore;
        Page.EarliestCursor = Events.EarliestCursor;
        Page.Lost = Events.Lost;
        Page.LostRanges = Events.LostRanges;
        Page.Items.reserve(Events.Items.size());
        for (auto Event : Events.Items)
        {
            if (!QueryValue.IncludeDetails)
            {
                Event.Detail.clear();
            }
            Page.Items.push_back(std::move(Event));
        }
        return Prism::Operations::QueryResult::Events(QueryValue.Correlation, std::move(Page));
    }

    /** @brief 在 EventRing 的唯一 application strand 复制值页。 */
    [[nodiscard]] inline auto ReadOperationsEventsOnOwner(
        std::shared_ptr<Application::RuntimeState> State,
        Prism::Operations::EventQuery QueryValue)
        -> Net::awaitable<Prism::Operations::QueryResult>
    {
        co_return MakeOperationsEvents(State, QueryValue);
    }

    /** @brief 返回当前进程唯一已装配 generation 的值快照。 */
    [[nodiscard]] inline auto MakeOperationsGeneration(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::GenerationQuery &QueryValue)
        -> Prism::Operations::QueryResult
    {
        const auto Generation = State->ActiveGenerationSnapshot();
        if (!State->Process || !Generation ||
            (QueryValue.Process && QueryValue.Process != State->Process->Id()) ||
            (QueryValue.Id && QueryValue.Id != Generation->Id()))
        {
            return Prism::Operations::QueryResult::Unavailable(QueryValue.Correlation);
        }
        Prism::Statistics::GenerationSnapshot Snapshot;
        Snapshot.Id = Generation->Id();
        const auto Phase = State->Phase.load(std::memory_order_acquire);
        Snapshot.Active = Phase == RuntimePhase::Ready;
        Snapshot.Retiring = Phase == RuntimePhase::Stopping;
        const auto HealthResult = MakeOperationsHealth(
            State, Prism::Operations::HealthQuery{QueryValue.Correlation});
        if (const auto *Health = std::get_if<Prism::Operations::HealthSnapshot>(
                &HealthResult.Value))
        {
            Snapshot.Health = *Health;
        }
        return Prism::Operations::QueryResult::Generation(
            QueryValue.Correlation, std::move(Snapshot));
    }

} // namespace Prism::Application::OperationsStartup
