/**
 * @file State.hpp
 * @brief 字节池分段真实存储与有界块准入。
 */
#pragma once

#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Foundation/Memory/BytePoolModels.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <source_location>
#include <span>
#include <string_view>

namespace Prism::Memory::Detail
{
    /** @brief 仅用于池冷构造的领域异常，保留错误类别与实际拒绝源码位置。 */
    class BytePoolError final : public Exception::Deviant
    {
    public:
        /** @brief 记录 InvalidArgument 或 OversizedMsg；不用于热路径容量拒绝。 */
        explicit BytePoolError(const Fault::Code Reason,
            const std::source_location Location = std::source_location::current());

    protected:
        /** @brief 返回冷路径字节池异常所属类别。 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override;
    };

    /**
     * @brief 由池与租约共同持有的存储 owner。
     * @details 位图按容量上限在冷路径一次分配；真实存储按 InitialBlockCount 起步，
     *          耗尽后在增长锁内按 GrowthBlockCount 分段扩容。构建目标必须提供无锁的 64 位原子操作。
     *          常态租用轮转扫描已提交位图，每个字有限预约尝试，不等待占用者。
     *          release/acquire 保护复用交接；尾部无效位永远不参与准入和观察。
     *          任意线程可获取或归还不同租约，同一租约仍需调用者串行访问。
     *          已分配分段不会缩回，保证已租约 span 的地址稳定。
     */
    class BytePoolState final
    {
    public:
        /** @brief 冷构造初始存储；无效配置或初始分配失败向启动边界抛出异常。 */
        explicit BytePoolState(const BytePoolOptions Options);
        ~BytePoolState() noexcept;

        /** @brief 尝试预约现有块，必要时增长一段；增长分配失败或达到上限时返回空。 */
        [[nodiscard]] auto TryReserve() noexcept -> std::optional<std::size_t>;

        /** @brief 归还调用者独占的有效块；不分配、不等待、不清除业务数据。 */
        auto Release(std::size_t Index) noexcept -> void;

        /** @brief 借用已预约块的完整字节范围；期限受对应租约约束。 */
        [[nodiscard]] auto Block(const std::size_t Index) noexcept -> std::span<std::byte>
        {
            return {ChunkForBlock(Index) + BlockOffset(Index) * Options_.BlockSize, Options_.BlockSize};
        }

        /** @brief 返回固定单块容量。 */
        [[nodiscard]] auto BlockSize() const noexcept -> std::size_t
        {
            return Options_.BlockSize;
        }

        /** @brief 返回当前已经分配的真实字节容量，不包含状态与标记数组开销。 */
        [[nodiscard]] auto CapacityBytes() const noexcept -> std::size_t
        {
            return Options_.BlockSize * CommittedBlocks_.load(std::memory_order_acquire);
        }

        /** @brief 返回配置允许的最大真实字节容量。 */
        [[nodiscard]] auto LimitBytes() const noexcept -> std::size_t
        {
            return Options_.BlockSize * Options_.BlockCount;
        }

        /** @brief 返回有效位的逐字占用观察；并发时非一致快照，但永不超总块数。 */
        [[nodiscard]] auto UsedBlocks() const noexcept -> std::size_t;

        /** @brief 返回当前已分配但未占用块数；实际准入以 TryReserve 为准。 */
        [[nodiscard]] auto AvailableBlocks() const noexcept -> std::size_t
        {
            const auto Used = UsedBlocks();
            const auto Committed = CommittedBlocks_.load(std::memory_order_acquire);
            return Committed > Used ? Committed - Used : 0;
        }

        /** @brief 生成容量、租约计数和峰值的独立值快照；允许与获取/归还并发。 */
        [[nodiscard]] auto Metrics() const noexcept -> BytePoolMetrics;

    private:
        static constexpr std::size_t WordBits = std::numeric_limits<std::uint64_t>::digits;
        static constexpr std::size_t AttemptsPerWord = 4;
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
        static_assert(std::atomic<std::size_t>::is_always_lock_free);
        static_assert(std::atomic<std::byte*>::is_always_lock_free);

        /** @brief 单次 CAS 更新高水位；竞争下允许漏记瞬时峰值，保持准入工作有界。 */
        auto RecordPeak(std::size_t Current) noexcept -> void;

        /** @brief 单次 CAS 更新已分配容量高水位。 */
        auto RecordPeakCapacity(std::size_t Current) noexcept -> void;

        [[nodiscard]] static auto CountWords(std::size_t Blocks) noexcept -> std::size_t;

        [[nodiscard]] static auto GrowthChunkCount(std::size_t BlockCount, std::size_t InitialBlockCount,
            std::size_t GrowthBlockCount) noexcept -> std::size_t;

        [[nodiscard]] auto CommittedMask(std::size_t Word, std::size_t CommittedBlocks) const noexcept
            -> std::uint64_t;

        [[nodiscard]] auto TryReserveWord(std::size_t Word, std::size_t CommittedBlocks) noexcept
            -> std::optional<std::size_t>;

        [[nodiscard]] auto TryReserveCommitted() noexcept -> std::optional<std::size_t>;

        [[nodiscard]] auto GrowAndReserve() noexcept -> std::optional<std::size_t>;

        [[nodiscard]] auto ChunkForBlock(std::size_t Index) noexcept -> std::byte*;

        [[nodiscard]] auto ChunkIndexForBlock(std::size_t Index) const noexcept -> std::size_t;

        [[nodiscard]] auto BlockOffset(std::size_t Index) const noexcept -> std::size_t;

        [[nodiscard]] static auto ColdValidate(BytePoolOptions Options) -> BytePoolOptions;

        const BytePoolOptions Options_;
        const std::size_t WordCount_;
        const std::size_t ChunkCount_;
        std::unique_ptr<std::atomic<std::byte*>[]> Chunks_;
        std::unique_ptr<std::atomic<std::uint64_t>[]> Occupied_;
        std::mutex Growth_;
        std::atomic<std::size_t> CommittedBlocks_{0};
        std::atomic<std::uint64_t> Hint_{0};
        std::atomic<std::size_t> ActiveBlocks_{0};
        std::atomic<std::size_t> PeakUsedBlocks_{0};
        std::atomic<std::size_t> PeakCommittedBlocks_{0};
        std::atomic<std::uint64_t> AllocationCount_{0};
        std::atomic<std::uint64_t> ReleaseCount_{0};
        std::atomic<std::uint64_t> GrowthCount_{0};
    };
} // namespace Prism::Memory::Detail
