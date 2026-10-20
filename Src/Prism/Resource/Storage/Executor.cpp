/** @file Executor.cpp @brief 单线程存储执行域的关闭计数实现。 */
#include <Prism/Resource/Storage/Executor.hpp>

#include <atomic>
#include <utility>

namespace Prism::Resource::Storage
{
    Executor::Executor() : Pool_(1) {}

    Executor::~Executor()
    {
        Pool_.join();
    }

    auto Executor::Join() -> void
    {
        Pool_.join();
    }

    auto Executor::Enter() -> bool
    {
        auto Value = Gate_.load(std::memory_order_acquire);
        while (!(Value & ClosedBit))
        {
            if (Gate_.compare_exchange_weak(Value, Value + 1, std::memory_order_acq_rel)) return true;
        }
        return false;
    }

    auto Executor::Leave() -> void
    {
        if (Gate_.fetch_sub(1, std::memory_order_acq_rel) == ClosedBit + 1) NotifyDrain();
    }

    auto Executor::NotifyDrain() -> void
    {
        if (Gate_.load(std::memory_order_acquire) != ClosedBit) return;
        auto Waiting = std::move(DrainWaiters_);
        DrainWaiters_.clear();
        for (auto& Complete : Waiting) Complete();
    }
}
