/**
 * @file BytePoolState.cpp
 * @brief 字节池分段增长、位图与租约指标实现。
 */
#include <Prism/Foundation/Memory/BytePool/State.hpp>

#include <algorithm>
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
          ChunkCount_(
              GrowthChunkCount(Options_.BlockCount, Options_.InitialBlockCount, Options_.GrowthBlockCount)),
          Chunks_(std::make_unique<std::atomic<std::byte*>[]>(ChunkCount_)),
          Occupied_(std::make_unique<std::atomic<std::uint64_t>[]>(WordCount_))
    {
        for (std::size_t Chunk = 0; Chunk < ChunkCount_; ++Chunk)
        {
            Chunks_[Chunk].store(nullptr, std::memory_order_relaxed);
        }
        for (std::size_t Word = 0; Word < WordCount_; ++Word)
        {
            Occupied_[Word].store(0, std::memory_order_relaxed);
        }
        auto InitialStorage = std::make_unique<std::byte[]>(Options_.InitialBlockCount * Options_.BlockSize);
        Chunks_[0].store(InitialStorage.get(), std::memory_order_release);
        CommittedBlocks_.store(Options_.InitialBlockCount, std::memory_order_release);
        RecordPeakCapacity(Options_.InitialBlockCount);
        (void)InitialStorage.release();
    }

    BytePoolState::~BytePoolState() noexcept
    {
        for (std::size_t Chunk = 0; Chunk < ChunkCount_; ++Chunk)
        {
            delete[] Chunks_[Chunk].load(std::memory_order_relaxed);
        }
    }

    auto BytePoolState::TryReserve() noexcept -> std::optional<std::size_t>
    {
        if (const auto Index = TryReserveCommitted())
        {
            return Index;
        }
        if (CommittedBlocks_.load(std::memory_order_acquire) >= Options_.BlockCount)
        {
            return std::nullopt;
        }
        return GrowAndReserve();
    }

    auto BytePoolState::TryReserveCommitted() noexcept -> std::optional<std::size_t>
    {
        const auto Committed = CommittedBlocks_.load(std::memory_order_acquire);
        const auto CommittedWords = CountWords(Committed);
        if (CommittedWords == 0)
        {
            return std::nullopt;
        }
        auto Word = static_cast<std::size_t>(Hint_.fetch_add(1, std::memory_order_relaxed) % CommittedWords);
        for (std::size_t Visited = 0; Visited < CommittedWords; ++Visited)
        {
            if (const auto Index = TryReserveWord(Word, Committed))
            {
                const auto Current = ActiveBlocks_.fetch_add(1, std::memory_order_relaxed) + 1;
                AllocationCount_.fetch_add(1, std::memory_order_relaxed);
                RecordPeak(Current);
                return Index;
            }
            ++Word;
            if (Word == CommittedWords)
            {
                Word = 0;
            }
        }
        return std::nullopt;
    }

    auto BytePoolState::GrowAndReserve() noexcept -> std::optional<std::size_t>
    {
        try
        {
            const std::lock_guard Lock(Growth_);
            if (const auto Index = TryReserveCommitted())
            {
                return Index;
            }
            for (;;)
            {
                const auto Committed = CommittedBlocks_.load(std::memory_order_acquire);
                if (Committed >= Options_.BlockCount)
                {
                    return std::nullopt;
                }
                const auto BlocksToAdd =
                    (std::min)(Options_.GrowthBlockCount, Options_.BlockCount - Committed);
                auto Storage = std::make_unique<std::byte[]>(BlocksToAdd * Options_.BlockSize);
                Chunks_[ChunkIndexForBlock(Committed)].store(Storage.get(), std::memory_order_release);
                (void)Storage.release();
                const auto NewCommitted = Committed + BlocksToAdd;
                CommittedBlocks_.store(NewCommitted, std::memory_order_release);
                GrowthCount_.fetch_add(1, std::memory_order_relaxed);
                RecordPeakCapacity(NewCommitted);
                if (const auto Index = TryReserveCommitted())
                {
                    return Index;
                }
            }
        }
        catch (...)
        {
            return std::nullopt;
        }
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
            Count +=
                static_cast<std::size_t>(std::popcount(Occupied & CommittedMask(Word, Options_.BlockCount)));
        }
        return Count;
    }

    auto BytePoolState::Metrics() const noexcept -> BytePoolMetrics
    {
        const auto Used = UsedBlocks();
        const auto Peak = PeakUsedBlocks_.load(std::memory_order_relaxed);
        const auto PeakAtLeastUsed = Peak > Used ? Peak : Used;
        const auto BlockSizeValue = BlockSize();
        const auto Committed = CommittedBlocks_.load(std::memory_order_acquire);
        const auto Capacity = Committed * BlockSizeValue;
        const auto UsedBytesValue = Used * BlockSizeValue;
        const auto AvailableBytesValue = Capacity > UsedBytesValue ? Capacity - UsedBytesValue : 0;
        const auto PeakCommitted = PeakCommittedBlocks_.load(std::memory_order_relaxed);
        return BytePoolMetrics{Capacity, UsedBytesValue, AvailableBytesValue,
            AllocationCount_.load(std::memory_order_relaxed), ReleaseCount_.load(std::memory_order_relaxed),
            PeakAtLeastUsed * BlockSizeValue, Options_.BlockSize * Options_.BlockCount,
            PeakCommitted * BlockSizeValue, GrowthCount_.load(std::memory_order_relaxed)};
    }

    auto BytePoolState::RecordPeak(const std::size_t Current) noexcept -> void
    {
        auto Peak = PeakUsedBlocks_.load(std::memory_order_relaxed);
        if (Current > Peak)
        {
            (void)PeakUsedBlocks_.compare_exchange_strong(Peak, Current, std::memory_order_relaxed,
                std::memory_order_relaxed);
        }
    }

    auto BytePoolState::RecordPeakCapacity(const std::size_t Current) noexcept -> void
    {
        auto Peak = PeakCommittedBlocks_.load(std::memory_order_relaxed);
        if (Current > Peak)
        {
            (void)PeakCommittedBlocks_.compare_exchange_strong(Peak, Current, std::memory_order_relaxed,
                std::memory_order_relaxed);
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

    auto BytePoolState::GrowthChunkCount(const std::size_t BlockCount, const std::size_t InitialBlockCount,
        const std::size_t GrowthBlockCount) noexcept -> std::size_t
    {
        if (BlockCount <= InitialBlockCount)
        {
            return 1;
        }
        const auto Remaining = BlockCount - InitialBlockCount;
        return 1 + Remaining / GrowthBlockCount + (Remaining % GrowthBlockCount != 0 ? 1 : 0);
    }

    auto BytePoolState::CommittedMask(const std::size_t Word,
        const std::size_t CommittedBlocks) const noexcept -> std::uint64_t
    {
        const auto Start = Word * WordBits;
        if (Start >= CommittedBlocks)
        {
            return 0;
        }
        const auto Bits = (std::min)(CommittedBlocks - Start, WordBits);
        if (Bits == WordBits)
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return (std::uint64_t{1} << Bits) - 1;
    }

    auto BytePoolState::TryReserveWord(const std::size_t Word, const std::size_t CommittedBlocks) noexcept
        -> std::optional<std::size_t>
    {
        auto Observed = Occupied_[Word].load(std::memory_order_relaxed);
        for (std::size_t Attempt = 0; Attempt < AttemptsPerWord; ++Attempt)
        {
            const auto Free = ~Observed & CommittedMask(Word, CommittedBlocks);
            if (Free == 0)
            {
                return std::nullopt;
            }
            const auto Bit = static_cast<std::size_t>(std::countr_zero(Free));
            const auto Desired = Observed | (std::uint64_t{1} << Bit);
            if (Occupied_[Word].compare_exchange_strong(Observed, Desired, std::memory_order_acquire,
                    std::memory_order_relaxed))
            {
                return Word * WordBits + Bit;
            }
        }
        return std::nullopt;
    }

    auto BytePoolState::ChunkForBlock(const std::size_t Index) noexcept -> std::byte*
    {
        return Chunks_[ChunkIndexForBlock(Index)].load(std::memory_order_acquire);
    }

    auto BytePoolState::ChunkIndexForBlock(const std::size_t Index) const noexcept -> std::size_t
    {
        if (Index < Options_.InitialBlockCount)
        {
            return 0;
        }
        return 1 + (Index - Options_.InitialBlockCount) / Options_.GrowthBlockCount;
    }

    auto BytePoolState::BlockOffset(const std::size_t Index) const noexcept -> std::size_t
    {
        if (Index < Options_.InitialBlockCount)
        {
            return Index;
        }
        return (Index - Options_.InitialBlockCount) % Options_.GrowthBlockCount;
    }

    auto BytePoolState::ColdValidate(const BytePoolOptions Options) -> BytePoolOptions
    {
        if (Options.BlockSize == 0 || Options.BlockCount == 0 || Options.InitialBlockCount == 0 ||
            Options.GrowthBlockCount == 0)
        {
            throw BytePoolError(Fault::Code::InvalidArgument);
        }
        auto Normalized = Options;
        Normalized.InitialBlockCount = (std::min)(Options.InitialBlockCount, Options.BlockCount);
        Normalized.GrowthBlockCount = (std::min)(Options.GrowthBlockCount, Options.BlockCount);
        constexpr auto Limit = std::numeric_limits<std::size_t>::max();
        const auto WordCount = CountWords(Normalized.BlockCount);
        const auto ChunkCount = GrowthChunkCount(Normalized.BlockCount, Normalized.InitialBlockCount,
            Normalized.GrowthBlockCount);
        if (Normalized.BlockCount > Limit / Normalized.BlockSize ||
            WordCount > Limit / sizeof(std::atomic<std::uint64_t>) ||
            ChunkCount > Limit / sizeof(std::atomic<std::byte*>))
        {
            throw BytePoolError(Fault::Code::OversizedMsg);
        }
        const auto StorageBytes = Normalized.BlockCount * Normalized.BlockSize;
        const auto MarkerBytes = WordCount * sizeof(std::atomic<std::uint64_t>);
        const auto ChunkBytes = ChunkCount * sizeof(std::atomic<std::byte*>);
        if (MarkerBytes > Limit - ChunkBytes || StorageBytes > Limit - MarkerBytes - ChunkBytes)
        {
            throw BytePoolError(Fault::Code::OversizedMsg);
        }
        return Normalized;
    }
} // namespace Prism::Memory::Detail
