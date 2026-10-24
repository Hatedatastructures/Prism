/**
 * @file ClosingStorage.cpp
 * @brief 进程级关闭实物存储实现。
 */
#include <Prism/Foundation/Executor/ClosingStorage.hpp>

namespace Prism::Executor
{
    auto ClosingStorage::ProcessStorage() -> std::shared_ptr<ClosingStorage>
    {
        static auto* const Owner = new std::shared_ptr<ClosingStorage>(std::make_shared<ClosingStorage>());
        return *Owner;
    }

    auto ClosingStorage::Retain(std::shared_ptr<ClosingResource> Resource) noexcept -> void
    {
        if (!Resource) return;
        if (!Resource->Registered_.exchange(true))
        {
            Retained_.fetch_add(1);
            auto Current = Head_.load();
            do { Resource->Next_.store(Current); } while (!Head_.compare_exchange_weak(Current, Resource));
        }
        if (Resource->IsDispatchUnavailable() && !Sealed_.exchange(true))
            if (auto Observer = Observer_.load().lock()) Observer->OnDispatchUnavailable();
    }

    auto ClosingStorage::Observe(std::weak_ptr<ClosingFailureObserver> Observer) noexcept -> void
    {
        Observer_.store(std::move(Observer));
    }

    auto ClosingStorage::Retry() -> void
    {
        if (Traversing_.test_and_set(std::memory_order_acquire)) return;
        {
            TraversalLease Lease{Traversing_};
            for (auto Value = Head_.load(); Value; Value = Value->Next_.load())
                if (!Value->IsRetired()) Value->RequestRetirement();
        }
        Collect();
    }

    auto ClosingStorage::Collect() noexcept -> void
    {
        if (Traversing_.test_and_set(std::memory_order_acquire)) return;
        TraversalLease Lease{Traversing_};
        auto* Link = &Head_;
        auto Value = Link->load();
        std::shared_ptr<ClosingResource> Previous;
        while (Value)
        {
            const auto Next = Value->Next_.load();
            if (Value->IsRetired())
            {
                if (!Link->compare_exchange_weak(Value, Next)) continue;
                Value->Next_.store({});
                Retained_.fetch_sub(1);
                Value = Next;
            }
            else
            {
                Previous = std::move(Value);
                Link = &Previous->Next_;
                Value = Next;
            }
        }
    }

    [[nodiscard]] auto ClosingStorage::HasPendingExcept(
        const ClosingResource* Excluded) const noexcept -> bool
    {
        for (auto Value = Head_.load(); Value; Value = Value->Next_.load())
        {
            if (Value.get() == Excluded || Value->IsRetirementSupport()) continue;
            if (!Value->IsRetired()) return true;
        }
        return false;
    }

    ClosingStorage::TraversalLease::~TraversalLease()
    {
        Flag.clear(std::memory_order_release);
    }
} // namespace Prism::Executor
