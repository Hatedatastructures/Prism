/**
 * @file FlatBuffer.cpp
 * @brief 连续内存缓冲区的增长与读写实现。
 */
#include <Prism/Foundation/FlatBuffer.hpp>

#include <algorithm>
#include <cstring>

namespace Prism
{
    FlatBuffer::FlatBuffer(const std::size_t InitialSize)
        : Storage_((std::min)(InitialSize, MaxSizeLimit)),
          InitialSize_((std::min)(InitialSize, MaxSizeLimit))
    {
    }

    auto FlatBuffer::Prepare(const std::size_t N) -> std::span<std::uint8_t>
    {
        if (Size_ > MaxSizeLimit || N > MaxSizeLimit - Size_)
        {
            return {};
        }
        if (N > MaxSize())
        {
            if (!Grow(Size_ + N))
            {
                return {};
            }
        }
        return {Storage_.data() + Size_, MaxSize()};
    }

    auto FlatBuffer::Commit(const std::size_t N) -> void
    {
        Size_ += std::min(N, MaxSize());
    }

    auto FlatBuffer::Consume(std::size_t N) -> void
    {
        N = std::min(N, Size_);
        if (N == 0)
        {
            return;
        }
        std::memmove(Storage_.data(), Storage_.data() + N, Size_ - N);
        Size_ -= N;
    }

    auto FlatBuffer::Clear() noexcept -> void
    {
        Size_ = 0;
    }

    auto FlatBuffer::ShrinkToFit() -> void
    {
        const auto Target = std::max(Size_, InitialSize_);
        if (Target < Storage_.size())
        {
            std::vector<std::uint8_t> tmp(Target);
            if (Size_ > 0)
            {
                std::memcpy(tmp.data(), Storage_.data(), Size_);
            }
            Storage_.swap(tmp);
        }
    }

    auto FlatBuffer::Append(const std::span<const std::uint8_t> src) -> std::size_t
    {
        auto Space = Prepare(src.size());
        if (Space.empty())
        {
            return 0;
        }
        const auto N = std::min(Space.size(), src.size());
        std::memcpy(Space.data(), src.data(), N);
        Commit(N);
        return N;
    }

    auto FlatBuffer::Reserve(const std::size_t N) -> void
    {
        if (N > Storage_.size())
        {
            Grow(N);
        }
    }

    auto FlatBuffer::Grow(const std::size_t N) -> bool
    {
        if (N > MaxSizeLimit)
        {
            return false;
        }
        const auto Current = Storage_.size();
        std::size_t Doubled = Current * 2;
        if (Current > MaxSizeLimit / 2)
        {
            Doubled = MaxSizeLimit;
        }
        auto NewCap = std::max(Doubled, N);
        NewCap = std::min(NewCap, MaxSizeLimit);
        try
        {
            Storage_.resize(NewCap);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }
} // namespace Prism
