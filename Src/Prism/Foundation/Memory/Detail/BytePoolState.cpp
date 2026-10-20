/**
 * @file BytePoolState.cpp
 * @brief 字节池位图与租约指标实现。
 */
#include <Prism/Foundation/Memory/Detail/BytePoolState.hpp>

#include <bit>

namespace Prism::Memory::Detail
{
    BytePoolError::BytePoolError(const Fault::Code Reason, const std::source_location Location)
        : Deviant(Fault::make_error_code(Reason), "字节池冷配置无效或容量溢出", Location)
    {
    }

    auto BytePoolError::TypeName() const noexcept -> std::string_view
    {
        return "BYTE_POOL";
    }

    BytePoolState::BytePoolState(const BytePoolOptions Options)
        : Options_(ColdValidate(Options)), WordCount_(CountWords(Options_.BlockCount)),
          Storage_(std::make_unique<std::byte[]>(CapacityBytes())),
          Occupied_(std::make_unique<std::atomic<std::uint64_t>[]>(WordCount_))
    {
        for (std::size_t Word = 0; Word < WordCount_; ++Word)
        {
            Occupied_[Word].store(0, std::memory_order_relaxed);
        }
    }

    auto BytePoolState::TryReserve() noexcept -> std::optional<std::size_t>
    {
        auto Word = static_cast<std::size_t>(Hint_.fetch_add(1, std::memory_order_relaxed) % WordCount_);
        for (std::size_t Visited = 0; Visited < WordCount_; ++Visited)
        {
            if (const auto Index = TryReserveWord(Word))
            {
                const auto Current = ActiveBlocks_.fetch_add(1, std::memory_order_relaxed) + 1;
                AllocationCount_.fetch_add(1, std::memory_order_relaxed);
                RecordPeak(Current);
                return Index;
            }
            ++Word;
            if (Word == WordCount_)
            {
                Word = 0;
            }
        }
        return std::nullopt;
    }

    auto BytePoolState::Release(const std::size_t Index) noexcept -> void
    {
        ActiveBlocks_.fetch_sub(1, std::memory_order_relaxed);
        ReleaseCount_.fetch_add(1, std::memory_order_relaxed);
        const auto Mask = std::uint64_t{1} << (Index % WordBits);
        Occupied_[Index / WordBits].fetch_and(~Mask, std::memory_order_release);
    }

    auto BytePoolState::UsedBlocks() const noexcept -> std::size_t
    {
        std::size_t Count = 0;
        for (std::size_t Word = 0; Word < WordCount_; ++Word)
        {
            const auto Occupied = Occupied_[Word].load(std::memory_order_relaxed);
            Count += static_cast<std::size_t>(std::popcount(Occupied & ValidMask(Word)));
        }
        return Count;
    }

    auto BytePoolState::Metrics() const noexcept -> BytePoolMetrics
    {
        const auto Used = UsedBlocks();
        const auto Peak = PeakUsedBlocks_.load(std::memory_order_relaxed);
        const auto PeakAtLeastUsed = Peak > Used ? Peak : Used;
        const auto BlockSizeValue = BlockSize();
        const auto UsedBytesValue = Used * BlockSizeValue;
        const auto Capacity = CapacityBytes();
        return BytePoolMetrics{Capacity, UsedBytesValue, Capacity - UsedBytesValue,
            AllocationCount_.load(std::memory_order_relaxed),
            ReleaseCount_.load(std::memory_order_relaxed), PeakAtLeastUsed * BlockSizeValue};
    }

    auto BytePoolState::RecordPeak(const std::size_t Current) noexcept -> void
    {
        auto Peak = PeakUsedBlocks_.load(std::memory_order_relaxed);
        if (Current > Peak)
        {
            (void)PeakUsedBlocks_.compare_exchange_strong(
                Peak, Current, std::memory_order_relaxed, std::memory_order_relaxed);
        }
    }

    auto BytePoolState::CountWords(const std::size_t Blocks) noexcept -> std::size_t
    {
        auto Count = Blocks / WordBits;
        if (Blocks % WordBits != 0)
        {
            ++Count;
        }
        return Count;
    }

    auto BytePoolState::ValidMask(const std::size_t Word) const noexcept -> std::uint64_t
    {
        const auto TailBits = Options_.BlockCount % WordBits;
        if (Word + 1 < WordCount_ || TailBits == 0)
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return (std::uint64_t{1} << TailBits) - 1;
    }

    auto BytePoolState::TryReserveWord(const std::size_t Word) noexcept
        -> std::optional<std::size_t>
    {
        auto Observed = Occupied_[Word].load(std::memory_order_relaxed);
        for (std::size_t Attempt = 0; Attempt < AttemptsPerWord; ++Attempt)
        {
            const auto Free = ~Observed & ValidMask(Word);
            if (Free == 0)
            {
                return std::nullopt;
            }
            const auto Bit = static_cast<std::size_t>(std::countr_zero(Free));
            const auto Desired = Observed | (std::uint64_t{1} << Bit);
            if (Occupied_[Word].compare_exchange_strong(Observed, Desired,
                std::memory_order_acquire, std::memory_order_relaxed))
            {
                return Word * WordBits + Bit;
            }
        }
        return std::nullopt;
    }

    auto BytePoolState::ColdValidate(const BytePoolOptions Options) -> BytePoolOptions
    {
        if (Options.BlockSize == 0 || Options.BlockCount == 0)
        {
            throw BytePoolError(Fault::Code::InvalidArgument);
        }
        constexpr auto Limit = std::numeric_limits<std::size_t>::max();
        const auto WordCount = CountWords(Options.BlockCount);
        if (Options.BlockCount > Limit / Options.BlockSize ||
            WordCount > Limit / sizeof(std::atomic<std::uint64_t>))
        {
            throw BytePoolError(Fault::Code::OversizedMsg);
        }
        const auto StorageBytes = Options.BlockCount * Options.BlockSize;
        const auto MarkerBytes = WordCount * sizeof(std::atomic<std::uint64_t>);
        if (StorageBytes > Limit - MarkerBytes)
        {
            throw BytePoolError(Fault::Code::OversizedMsg);
        }
        return Options;
    }
} // namespace Prism::Memory::Detail
