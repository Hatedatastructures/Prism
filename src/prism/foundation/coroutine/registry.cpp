#include <prism/foundation/coroutine/registry.hpp>

#include <algorithm>
#include <utility>

namespace psm::coroutine
{
    task_token::~task_token() noexcept
    {
        if (!released_)
        {
            release();
        }
    }

    auto task_token::release() noexcept -> void
    {
        if (released_)
        {
            return;
        }
        released_ = true;
        if (owner_ != nullptr)
        {
            owner_->release_internal(*this);
        }
    }

    auto task_registry::cancel_and_wait(
        const std::chrono::milliseconds /*timeout*/) -> bool
    {
        cancelling_ = true;
        total_cancelled_ += tokens_.size();
        tokens_.clear();
        return true;
    }

    auto task_registry::stats() const noexcept -> task_stats
    {
        return task_stats{
            tokens_.size(),
            total_spawned_,
            total_released_,
            total_cancelled_};
    }

    auto task_registry::release_internal(const task_token &token) noexcept -> void
    {
        if (cancelling_)
        {
            return;
        }

        const auto it = std::find_if(
            tokens_.begin(), tokens_.end(),
            [&token](const std::shared_ptr<task_token> &ptr)
            { return ptr.get() == &token; });

        if (it != tokens_.end())
        {
            tokens_.erase(it);
            ++total_released_;
        }
    }

} // namespace psm::coroutine
