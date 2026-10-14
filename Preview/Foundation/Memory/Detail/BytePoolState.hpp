/**
 * @file BytePoolState.hpp
 * @brief 字节池真实存储与有界无等待块准入。
 */
#pragma once

#include <Preview/Foundation/Exception/Deviant.hpp>
#include <Preview/Foundation/Memory/BytePoolOptions.hpp>

#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <source_location>
#include <span>
#include <string_view>

namespace Preview::Memory::Detail
{
    /** @brief 仅用于池冷构造的领域异常，保留错误类别与实际拒绝源码位置。 */
    class BytePoolError final : public Exception::Deviant
    {
    public:
        /** @brief 记录 InvalidArgument 或 OversizedMsg；不用于热路径容量拒绝。 */
        explicit BytePoolError(const Fault::Code Reason,
            const std::source_location Location = std::source_location::current())
            : Deviant(Fault::make_error_code(Reason), "字节池冷配置无效或容量溢出", Location)
        {
        }

    protected:
        /** @brief 返回冷路径字节池异常所属类别。 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return "BYTE_POOL";
        }
    };

    /**
     * @brief 由池与租约共同持有的存储 owner。
     * @details 位图在冷路径一次分配；构建目标必须提供无锁的 64 位原子操作。
     *          轮转起点最多扫描一次位图，每个字有限预约尝试，不等待占用者。
     *          release/acquire 保护复用交接；尾部无效位永远不参与准入和观察。
     *          任意线程可获取或归还不同租约，同一租约仍需调用者串行访问。
     */
    class BytePoolState final
    {
    public:
        /** @brief 冷构造真实存储；无效配置或分配失败向启动边界抛出异常。 */
        explicit BytePoolState(const BytePoolOptions Options)
            : Options_(ColdValidate(Options)), WordCount_(CountWords(Options_.BlockCount)),
              Storage_(std::make_unique<std::byte[]>(CapacityBytes())),
              Occupied_(std::make_unique<std::atomic<std::uint64_t>[]>(WordCount_))
        {
            for (std::size_t Word = 0; Word < WordCount_; ++Word)
            {
                Occupied_[Word].store(0, std::memory_order_relaxed);
            }
        }

        /** @brief 有界尝试预约整块；失败不证明统一时刻全满，调用者按即时拒绝处理。 */
        [[nodiscard]] auto TryReserve() noexcept -> std::optional<std::size_t>
        {
            auto Word = static_cast<std::size_t>(Hint_.fetch_add(1, std::memory_order_relaxed) % WordCount_);
            for (std::size_t Visited = 0; Visited < WordCount_; ++Visited)
            {
                if (const auto Index = TryReserveWord(Word))
                {
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

        /** @brief 归还调用者独占的有效块；不分配、不等待、不清除业务数据。 */
        auto Release(const std::size_t Index) noexcept -> void
        {
            const auto Mask = std::uint64_t{1} << (Index % WordBits);
            Occupied_[Index / WordBits].fetch_and(~Mask, std::memory_order_release);
        }

        /** @brief 借用已预约块的完整字节范围；期限受对应租约约束。 */
        [[nodiscard]] auto Block(const std::size_t Index) noexcept -> std::span<std::byte>
        {
            return {Storage_.get() + Index * Options_.BlockSize, Options_.BlockSize};
        }

        /** @brief 返回固定单块容量。 */
        [[nodiscard]] auto BlockSize() const noexcept -> std::size_t
        {
            return Options_.BlockSize;
        }

        /** @brief 返回真实字节存储容量，不包含冷路径状态与标记数组的固定开销。 */
        [[nodiscard]] auto CapacityBytes() const noexcept -> std::size_t
        {
            return Options_.BlockSize * Options_.BlockCount;
        }

        /** @brief 返回有效位的逐字占用观察；并发时非一致快照，但永不超总块数。 */
        [[nodiscard]] auto UsedBlocks() const noexcept -> std::size_t
        {
            std::size_t Count = 0;
            for (std::size_t Word = 0; Word < WordCount_; ++Word)
            {
                const auto Occupied = Occupied_[Word].load(std::memory_order_relaxed);
                Count += static_cast<std::size_t>(std::popcount(Occupied & ValidMask(Word)));
            }
            return Count;
        }

        /** @brief 返回当前可用块数观察值；实际准入以 TryReserve 为准。 */
        [[nodiscard]] auto AvailableBlocks() const noexcept -> std::size_t
        {
            return Options_.BlockCount - UsedBlocks();
        }

    private:
        static constexpr std::size_t WordBits = std::numeric_limits<std::uint64_t>::digits;
        static constexpr std::size_t AttemptsPerWord = 4;
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

        [[nodiscard]] static auto CountWords(const std::size_t Blocks) noexcept -> std::size_t
        {
            auto Count = Blocks / WordBits;
            if (Blocks % WordBits != 0)
            {
                ++Count;
            }
            return Count;
        }

        [[nodiscard]] auto ValidMask(const std::size_t Word) const noexcept -> std::uint64_t
        {
            const auto TailBits = Options_.BlockCount % WordBits;
            if (Word + 1 < WordCount_ || TailBits == 0)
            {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return (std::uint64_t{1} << TailBits) - 1;
        }

        [[nodiscard]] auto TryReserveWord(const std::size_t Word) noexcept -> std::optional<std::size_t>
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

        [[nodiscard]] static auto ColdValidate(const BytePoolOptions Options) -> BytePoolOptions
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

        const BytePoolOptions Options_;
        const std::size_t WordCount_;
        std::unique_ptr<std::byte[]> Storage_;
        std::unique_ptr<std::atomic<std::uint64_t>[]> Occupied_;
        std::atomic<std::uint64_t> Hint_{0};
    };
}
