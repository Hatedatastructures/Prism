/** @file StreamCatalog.cpp @brief 多路复用子流值目录及精确退休实现。 */
#include <Prism/Contract/Ingress/StreamCatalog.hpp>

#include <algorithm>
#include <new>
#include <utility>

namespace Prism::Contract::Ingress
{
    StreamCatalog::Entry::Entry(StreamDescriptor Value, StreamResetBinding Reset)
        : Descriptor(std::move(Value)), Reset(std::move(Reset))
    {
    }

    auto StreamCatalog::Enable(const std::size_t Capacity) noexcept -> bool
    {
        if (Capacity == 0U)
        {
            return false;
        }
        std::size_t Empty = 0U;
        if (!Capacity_.compare_exchange_strong(Empty, Capacity, std::memory_order_acq_rel))
        {
            return Empty == Capacity && IsAvailable();
        }
        Available_.store(true, std::memory_order_release);
        return true;
    }

    auto StreamCatalog::Disable() noexcept -> void
    {
        Available_.store(false, std::memory_order_release);
    }

    auto StreamCatalog::IsAvailable() const noexcept -> bool
    {
        return Available_.load(std::memory_order_acquire);
    }

    auto StreamCatalog::Register(StreamDescriptor Value, StreamResetBinding Reset)
        -> std::expected<void, Prism::Fault::Failure>
    {
        using Failure = Prism::Fault::Failure;
        if (!IsValid(Value.Identity) || !Value.Task || !Value.ParentTask ||
            Reset.Owner.expired() ||
            (Value.Protocol != StreamProtocol::Smux && Value.Protocol != StreamProtocol::Yamux &&
             Value.Protocol != StreamProtocol::H2Mux))
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!IsAvailable())
        {
            return std::unexpected(Failure{Prism::Fault::Code::NotSupported});
        }
        const auto Capacity = Capacity_.load(std::memory_order_acquire);
        if (Capacity == 0U)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        try
        {
            while (IsAvailable())
            {
                auto Current = Directory_.load(std::memory_order_acquire);
                auto Next = std::make_shared<Directory>();
                if (Current)
                {
                    for (const auto &[Id, Existing] : *Current)
                    {
                        if (Existing->State.load(std::memory_order_acquire) != StreamState::Retired)
                        {
                            Next->emplace(Id, Existing);
                        }
                    }
                }
                const auto Id = Value.Identity.Id.Value();
                if (const auto Existing = Next->find(Id); Existing != Next->end())
                {
                    if (Existing->second->Descriptor.Identity == Value.Identity)
                    {
                        return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
                    }
                    return std::unexpected(Failure{Prism::Fault::Code::Blocked});
                }
                if (Next->size() >= Capacity)
                {
                    return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
                }
                Value.State = StreamState::Active;
                Next->emplace(Id, std::make_shared<Entry>(Value, Reset));
                std::shared_ptr<const Directory> Published(std::move(Next));
                if (Directory_.compare_exchange_weak(
                        Current, Published, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return {};
                }
            }
            return std::unexpected(Failure{Prism::Fault::Code::NotSupported});
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (...)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto StreamCatalog::ResetAndDrain(StreamResetRequest Request)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        if (!IsValid(Request.Identity) || !Request.Task || !Request.ParentTask)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!IsAvailable())
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::NotSupported});
        }
        const auto Item = FindEntry(Request.Identity);
        if (!Item || Item->Descriptor.Task != Request.Task ||
            Item->Descriptor.ParentTask != Request.ParentTask)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        auto Current = Item->State.load(std::memory_order_acquire);
        if (Current == StreamState::Retired)
        {
            co_return std::expected<void, Failure>{};
        }
        if (Current == StreamState::Active &&
            !Item->State.compare_exchange_strong(
                Current, StreamState::Draining, std::memory_order_acq_rel))
        {
            if (Current == StreamState::Retired)
            {
                co_return std::expected<void, Failure>{};
            }
            if (Current != StreamState::Draining)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
        }
        if (Current != StreamState::Active && Current != StreamState::Draining)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Owner = Item->Reset.Owner.lock();
        if (!Owner)
        {
            Disable();
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Result = co_await Owner->ResetAndDrain(std::move(Request));
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (Item->State.load(std::memory_order_acquire) != StreamState::Retired)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Failure>{};
    }

    auto StreamCatalog::MarkDraining(const StreamIdentity &Identity) const noexcept -> bool
    {
        const auto Item = FindEntry(Identity);
        if (!Item)
        {
            return false;
        }
        auto Expected = StreamState::Active;
        if (Item->State.compare_exchange_strong(
                Expected, StreamState::Draining, std::memory_order_acq_rel))
        {
            return true;
        }
        return Expected == StreamState::Draining;
    }

    auto StreamCatalog::Retire(const StreamIdentity &Identity) const noexcept -> bool
    {
        const auto Item = FindEntry(Identity);
        if (!Item)
        {
            return false;
        }
        auto Expected = StreamState::Draining;
        if (Item->State.compare_exchange_strong(
                Expected, StreamState::Retired, std::memory_order_acq_rel))
        {
            return true;
        }
        return Expected == StreamState::Retired;
    }

    auto StreamCatalog::Find(const StreamIdentity &Identity) const noexcept -> StreamCatalogLookup
    {
        if (!IsAvailable())
        {
            return {StreamCatalogStatus::CapabilityUnavailable, {}};
        }
        const auto Item = FindEntry(Identity);
        if (!Item)
        {
            if (!IsAvailable())
            {
                return {StreamCatalogStatus::CapabilityUnavailable, {}};
            }
            return {StreamCatalogStatus::NotFound, {}};
        }
        const auto State = Item->State.load(std::memory_order_acquire);
        if (State == StreamState::Retired)
        {
            if (!IsAvailable())
            {
                return {StreamCatalogStatus::CapabilityUnavailable, {}};
            }
            return {StreamCatalogStatus::NotFound, {}};
        }
        auto Snapshot = Item->Descriptor;
        Snapshot.State = State;
        if (!IsAvailable())
        {
            return {StreamCatalogStatus::CapabilityUnavailable, {}};
        }
        return {StreamCatalogStatus::Found, std::move(Snapshot)};
    }

    auto StreamCatalog::List(const StreamListRequest &Request) const -> StreamCatalogPage
    {
        StreamCatalogPage Result;
        Result.NextCursor = Request.Cursor;
        if (!IsAvailable())
        {
            return Result;
        }
        if (!Request.Parent.Session || !Request.Parent.Worker || !Request.Parent.Generation)
        {
            Result.Status = StreamCatalogStatus::NotFound;
            return Result;
        }
        const auto Current = Directory_.load(std::memory_order_acquire);
        if (Current)
        {
            constexpr std::size_t MaxPageSize{256U};
            const auto Limit = (std::min)(Request.Limit, MaxPageSize);
            for (auto It = Current->upper_bound(Request.Cursor); It != Current->end(); ++It)
            {
                const auto &EntryValue = *It->second;
                const auto &Identity = EntryValue.Descriptor.Identity;
                if (Identity.Session != Request.Parent.Session ||
                    Identity.Worker != Request.Parent.Worker ||
                    Identity.Generation != Request.Parent.Generation)
                {
                    continue;
                }
                const auto State = EntryValue.State.load(std::memory_order_acquire);
                if (State == StreamState::Retired)
                {
                    continue;
                }
                if (Result.Items.size() == Limit)
                {
                    Result.HasMore = true;
                    break;
                }
                auto Descriptor = EntryValue.Descriptor;
                Descriptor.State = State;
                Result.NextCursor = Identity.Id.Value();
                Result.Items.push_back(std::move(Descriptor));
            }
        }
        if (!IsAvailable())
        {
            Result.Items.clear();
            Result.NextCursor = Request.Cursor;
            Result.HasMore = false;
            return Result;
        }
        Result.Status = StreamCatalogStatus::Found;
        return Result;
    }

    auto StreamCatalog::IsValid(const StreamIdentity &Identity) noexcept -> bool
    {
        return Identity.Session && Identity.Worker && Identity.Generation && Identity.Id;
    }

    auto StreamCatalog::FindEntry(const StreamIdentity &Identity) const noexcept
        -> std::shared_ptr<Entry>
    {
        const auto Current = Directory_.load(std::memory_order_acquire);
        if (!Current)
        {
            return {};
        }
        const auto Found = Current->find(Identity.Id.Value());
        if (Found == Current->end() || Found->second->Descriptor.Identity != Identity)
        {
            return {};
        }
        return Found->second;
    }
}
