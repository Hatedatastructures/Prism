/**
 * @file Lifetime.cpp
 * @brief 配置代次活动预约实现。
 */
#include <Prism/Foundation/Generation/Lifetime.hpp>

namespace Prism::Foundation
{
    GenerationUseLease::GenerationUseLease(std::shared_ptr<GenerationUseState> Owner) noexcept
        : Owner_(std::move(Owner))
    {
    }

    GenerationUseLease::~GenerationUseLease() noexcept
    {
        Release();
    }

    auto GenerationUseLease::operator=(GenerationUseLease&& Other) noexcept -> GenerationUseLease&
    {
        if (this != &Other)
        {
            Release();
            Owner_ = std::move(Other.Owner_);
        }
        return *this;
    }

    auto GenerationUseLease::Release() noexcept -> void
    {
        if (Owner_)
        {
            Owner_->Release();
            Owner_.reset();
        }
    }

    auto GenerationUseState::Acquire() noexcept
        -> std::expected<GenerationUseLease, Prism::Fault::Failure>
    {
        auto Owner = weak_from_this().lock();
        if (!Owner)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        auto State = State_.load(std::memory_order_acquire);
        while ((State & AdmissionClosed) == 0U && (State & UseCountMask) != UseCountMask)
        {
            if (State_.compare_exchange_weak(
                State, State + 1U, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return GenerationUseLease{std::move(Owner)};
            }
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto GenerationUseState::CloseAdmissionIfUnused() noexcept -> bool
    {
        auto State = State_.load(std::memory_order_acquire);
        while ((State & AdmissionClosed) == 0U)
        {
            if ((State & UseCountMask) != 0U)
            {
                return false;
            }
            if (State_.compare_exchange_weak(
                State, State | AdmissionClosed, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return true;
            }
        }
        return (State & UseCountMask) == 0U;
    }

    auto GenerationUseState::Release() noexcept -> void
    {
        State_.fetch_sub(1U, std::memory_order_acq_rel);
    }
} // namespace Prism::Foundation
