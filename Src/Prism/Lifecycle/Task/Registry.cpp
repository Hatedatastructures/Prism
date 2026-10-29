/** @file Registry.cpp @brief 非模板 registry 查询、取消及生命周期实现。 */
#include <Prism/Lifecycle/Task/Registry.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

namespace Prism::Lifecycle
{
    std::atomic<std::uint64_t> TaskRegistry::NextTaskId_{1};

    auto TaskRegistry::AllocateId() noexcept
        -> std::expected<Prism::TaskId, Prism::Fault::Failure>
    {
        auto Current = NextTaskId_.load();
        while (Current != 0)
        {
            std::uint64_t Next = 0;
            if (Current != std::numeric_limits<std::uint64_t>::max()) Next = Current + 1;
            if (NextTaskId_.compare_exchange_weak(Current, Next)) return Prism::TaskId{Current};
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto TaskRegistry::CancelOnExecutor(const std::shared_ptr<State>& Value) -> void
    {
        (void)Value->Domain->Cancel();
        for (const auto& Slot : Value->Pool->Slots)
            if (Slot.Scope.load() == Value.get()) Detail::RequestTaskCancel(Value, Slot.Task);
    }

    auto TaskRegistry::BelongsToRootScope(const State *Root, const State *Scope) noexcept -> bool
    {
        for (auto Current = Scope; Current; Current = Current->Parent.get())
            if (Current == Root) return true;
        return false;
    }

    auto TaskRegistry::FindTaskOnExecutor(std::shared_ptr<State> Root,
        const TaskIdentity Identity) -> Net::awaitable<TaskLookupResult>
    {
        if (!Root || Root->Parent || !Identity.TaskId)
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        if (!Root->Reclaimer->CanDispatch())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        for (const auto &Slot : Root->Pool->Slots)
        {
            if (!Slot.Used.load(std::memory_order_acquire)) continue;
            const auto *Scope = Slot.Scope.load(std::memory_order_acquire);
            if (!Scope || !BelongsToRootScope(Root.get(), Scope)) continue;
            const auto Task = Slot.Task;
            if (Task && Task->Identity() == Identity)
                co_return std::optional<TaskHandle>{TaskHandle{Task}};
        }
        co_return std::optional<TaskHandle>{};
    }

    auto TaskRegistry::MatchesListScope(const TaskObservation &Observation,
        const TaskRegistryListRequest &Request) noexcept -> bool
    {
        const auto &Identity = Observation.Identity;
        return Identity.SessionId == Request.Session && Identity.WorkerId == Request.Worker &&
            Identity.Generation == Request.Generation && Identity.TaskId.Value() > Request.Cursor;
    }

    auto TaskRegistry::ListTasksOnExecutor(std::shared_ptr<State> Root,
        TaskRegistryListRequest Request)
        -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        if (!Root || Root->Parent || !Request.Session || !Request.Worker || !Request.Generation)
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        if (!Root->Reclaimer->CanDispatch())
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        constexpr std::size_t MaxPageSize{256U};
        const auto Limit = (std::min)(Request.Limit, MaxPageSize);
        std::vector<TaskObservation> Matches;
        for (const auto &Slot : Root->Pool->Slots)
        {
            if (!Slot.Used.load(std::memory_order_acquire)) continue;
            const auto *Scope = Slot.Scope.load(std::memory_order_acquire);
            if (!Scope || !BelongsToRootScope(Root.get(), Scope)) continue;
            const auto Task = Slot.Task;
            if (!Task) continue;
            auto Observation = Task->Observation();
            if (MatchesListScope(Observation, Request)) Matches.push_back(std::move(Observation));
        }
        std::sort(Matches.begin(), Matches.end(), [](const auto &Left, const auto &Right)
        { return Left.Identity.TaskId.Value() < Right.Identity.TaskId.Value(); });
        TaskRegistryListPage Result;
        Result.NextCursor = Request.Cursor;
        Result.HasMore = Matches.size() > Limit;
        if (Matches.size() > Limit) Matches.resize(Limit);
        if (!Matches.empty()) Result.NextCursor = Matches.back().Identity.TaskId.Value();
        Result.Items = std::move(Matches);
        co_return Result;
    }

    auto TaskRegistry::ListTasksOnOwner(std::shared_ptr<State> Root,
        TaskRegistryListRequest Request)
        -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>
    {
        if (!Root || Root->Parent || !Root->Reclaimer->CanDispatch())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        try
        {
            co_return co_await Net::co_spawn(Root->CommandExecutor,
                ListTasksOnExecutor(Root, std::move(Request)), Net::use_awaitable);
        }
        catch (const std::bad_alloc&)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (const boost::system::system_error &Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error &Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
    }

    auto TaskRegistry::FindTaskOnOwner(std::shared_ptr<State> Root,
        const TaskIdentity Identity) -> Net::awaitable<TaskLookupResult>
    {
        if (!Root || Root->Parent || !Identity.TaskId)
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        if (!Root->Reclaimer->CanDispatch())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        try
        {
            co_return co_await Net::co_spawn(Root->CommandExecutor,
                FindTaskOnExecutor(Root, Identity), Net::use_awaitable);
        }
        catch (const boost::system::system_error &Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error &Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
    }

    auto TaskRegistry::CancelCommand::operator()() const noexcept -> void
    {
        try { CancelOnExecutor(Value); }
        catch (...) { if (Value) Detail::MarkTaskRegistryBlocked(Value); }
    }

    auto TaskRegistry::CancelCommand::OnQuarantine() const noexcept -> void
    {
        if (Value) Detail::MarkTaskRegistryBlocked(Value);
    }

    TaskRegistry::TaskRegistry(Net::any_io_executor Executor, FailureHandler Failure)
        : State_(std::make_shared<State>(std::move(Executor), std::move(Failure))) {}

    TaskRegistry::TaskRegistry(std::shared_ptr<State> Parent, FailureHandler Failure)
        : State_(std::make_shared<State>(Parent->Executor, std::move(Failure), Parent)) {}

    TaskRegistry::~TaskRegistry()
    {
        Seal();
        State_->CancelRequested.store(true, std::memory_order_release);
        State_->TearingDown.store(true, std::memory_order_release);
        State_->RetainClosing();
        const auto Self = State_;
        if (!State_->Reclaimer->Post(Detail::TaskRegistryRetirementCommand(Self)))
        {
            State_->RetainUnavailableRetirement();
        }
    }

    auto TaskRegistry::BindTrafficSink(std::shared_ptr<Prism::Foundation::TrafficSink> Sink)
        -> std::expected<void, Prism::Fault::Failure>
    {
        using Failure = Prism::Fault::Failure;
        if (!Sink || State_->Parent || !State_->Accepting.load(std::memory_order_acquire))
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        if (State_->Traffic || State_->Barrier.Active() != 0U ||
            State_->Descendants.Active.load(std::memory_order_acquire) != 0U)
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        State_->Traffic = std::move(Sink);
        return {};
    }

    auto TaskRegistry::CreateChild(FailureHandler Failure) -> std::shared_ptr<TaskRegistry>
    {
        return std::shared_ptr<TaskRegistry>(new TaskRegistry(State_, std::move(Failure)));
    }

    auto TaskRegistry::FindTask(TaskIdentity Identity) const
        -> Net::awaitable<std::expected<std::optional<TaskHandle>, Prism::Fault::Failure>>
    {
        return FindTaskOnOwner(State_, Identity);
    }

    auto TaskRegistry::ListTasks(TaskRegistryListRequest Request) const
        -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>
    {
        return ListTasksOnOwner(State_, std::move(Request));
    }

    auto TaskRegistry::Cancel() -> bool
    {
        if (State_->CancelRequested.exchange(true)) return false;
        Seal();
        State_->Domain->RequestCancellation();
        if (!State_->Reclaimer->Post(CancelCommand{State_}))
        {
            State_->RetainClosing();
            State_->RetainUnavailableRetirement();
        }
        return true;
    }

    auto TaskRegistry::Seal() noexcept -> void
    {
        Detail::SealTaskRegistryState(State_);
    }

    auto TaskRegistry::Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Value = State_;
        Detail::SealTaskRegistryState(Value);
        if (Value->Blocked.load())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return co_await Value->Barrier.Drain();
    }

    auto TaskRegistry::Stats() const noexcept -> TaskStats
    {
        TaskStats Value;
        Detail::AddTaskStats(Value, State_);
        return Value;
    }

    auto TaskRegistry::Block() noexcept -> void
    {
        Detail::MarkTaskRegistryBlocked(State_);
    }
}
