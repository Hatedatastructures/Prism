/**
 * @file BytePool.hpp
 * @brief 小容量起步、分段增长、有界准入且可回收的字节池。
 */
#pragma once

#include <Prism/Foundation/Memory/BytePoolModels.hpp>
#include <Prism/Foundation/Memory/OwnedBytes.hpp>

#include <cstddef>
#include <expected>
#include <memory>

namespace Prism::Memory
{
    /**
     * @brief 创建按需增长真实存储并发放独占块租约的冷路径 owner。
     * @details 无全局池或 PMR 回退；启动只分配 InitialBlockCount，容量耗尽后在增长边界
     *          按 GrowthBlockCount 分段扩容，达到 BlockCount 上限后拒绝。
     *          每份排队或在途 OwnedBytes 均占整块，缩短逻辑长度不提前释放额度。
     *          标记数组与分段指针按容量上限固定；外部队列节点须另行预约预算。
     *          不绑定 executor；可并发获取不同租约，不可与池析构并发调用成员。
     *          池析构后已发放租约仍保活存储，最后一个 owner 负责最终释放。
     */
    class BytePool final
    {
    public:
        /**
         * @brief 在冷路径创建初始块、容量上限标记与分段控制器。
         * @param Options 按值消费；默认初始 4 MiB、每次增长 4 MiB、最大 128 MiB。
         * @throws Detail::BytePoolError 任一容量参数为零为 InvalidArgument，容量溢出为 OversizedMsg。
         * @throws std::bad_alloc 初始真实存储分配失败，由启动边界收口。
         */
        explicit BytePool(const BytePoolOptions Options = {});

        BytePool(const BytePool&) = delete;
        auto operator=(const BytePool&) -> BytePool& = delete;
        BytePool(BytePool&&) = delete;
        auto operator=(BytePool&&) -> BytePool& = delete;

        /**
         * @brief 即时预约一个整块并返回拥有型字节；零长度同样持有真实块。
         * @param Size 初始逻辑长度，不能超过单块容量；大消息由业务逐块处理。
         * @return 超单块容量为 OversizedMsg；达到上限或增长分配失败为 ResourceUnavailable。
         * @details 成功租约由调用者持有至异步访问全部结束；不取消或半关闭 I/O。
         *          常态执行有界原子扫描；只有现有容量耗尽时才串行增长并分配下一段。
         *          不抛出异常，增长失败统一投影为 ResourceUnavailable。
         */
        [[nodiscard]] auto TryAcquire(const std::size_t Size) noexcept
            -> std::expected<OwnedBytes, Fault::Failure>;

        /** @brief 返回池当前已经分配的真实字节容量，不含状态与标记开销。 */
        [[nodiscard]] auto CapacityBytes() const noexcept -> std::size_t
        {
            return State_->CapacityBytes();
        }

        /** @brief 返回配置允许的最大真实字节容量，不含状态与标记开销。 */
        [[nodiscard]] auto LimitBytes() const noexcept -> std::size_t
        {
            return State_->LimitBytes();
        }

        /** @brief 返回预约整块容量观察值；并发变化时不是一致快照。 */
        [[nodiscard]] auto UsedBytes() const noexcept -> std::size_t
        {
            return State_->UsedBlocks() * State_->BlockSize();
        }

        /** @brief 返回当前已分配但未占用的块数观察值。 */
        [[nodiscard]] auto AvailableBlocks() const noexcept -> std::size_t
        {
            return State_->AvailableBlocks();
        }

        /** @brief 返回单块上限，供合法大消息分块使用。 */
        [[nodiscard]] auto BlockSize() const noexcept -> std::size_t
        {
            return State_->BlockSize();
        }

        /** @brief 在冷快照边界返回容量、使用量、可用量及租约计数的独立值快照。 */
        [[nodiscard]] auto Snapshot() const noexcept -> BytePoolMetrics
        {
            return State_->Metrics();
        }

    private:
        std::shared_ptr<Detail::BytePoolState> State_;
    };
} // namespace Prism::Memory
