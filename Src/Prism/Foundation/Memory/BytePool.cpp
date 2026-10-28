/**
 * @file BytePool.cpp
 * @brief 固定容量字节池的准入实现。
 */
#include <Prism/Foundation/Memory/BytePool.hpp>

#include <Prism/Foundation/Memory/BytePool/State.hpp>

#include <memory>
#include <utility>

namespace Prism::Memory
{
    BytePool::BytePool(const BytePoolOptions Options)
        : State_(std::make_shared<Detail::BytePoolState>(Options))
    {
    }

    OwnedBytes::~OwnedBytes() noexcept
    {
        Release();
    }

    OwnedBytes::OwnedBytes(OwnedBytes&& Other) noexcept
        : State_(std::move(Other.State_)), Index_(std::exchange(Other.Index_, 0)),
          Size_(std::exchange(Other.Size_, 0))
    {
    }

    auto OwnedBytes::operator=(OwnedBytes&& Other) noexcept -> OwnedBytes&
    {
        if (this != &Other)
        {
            Release();
            State_ = std::move(Other.State_);
            Index_ = std::exchange(Other.Index_, 0);
            Size_ = std::exchange(Other.Size_, 0);
        }
        return *this;
    }

    auto OwnedBytes::Resize(const std::size_t Size) noexcept -> std::expected<void, Fault::Failure>
    {
        if (Size > Capacity())
        {
            return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg, {}});
        }
        Size_ = Size;
        return {};
    }

    auto OwnedBytes::Release() noexcept -> void
    {
        if (State_)
        {
            State_->Release(Index_);
            State_.reset();
        }
        Index_ = 0;
        Size_ = 0;
    }

    OwnedBytes::OwnedBytes(std::shared_ptr<Detail::BytePoolState> State,
        const std::size_t Index) noexcept
        : State_(std::move(State)), Index_(Index)
    {
    }

    auto BytePool::TryAcquire(const std::size_t Size) noexcept
        -> std::expected<OwnedBytes, Fault::Failure>
    {
        if (Size > BlockSize())
        {
            return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg, {}});
        }
        const auto Index = State_->TryReserve();
        if (!Index)
        {
            return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
        }
        OwnedBytes Result(State_, *Index);
        Result.Size_ = Size;
        return Result;
    }
} // namespace Prism::Memory
