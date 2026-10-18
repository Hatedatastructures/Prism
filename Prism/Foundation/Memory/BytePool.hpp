/**
 * @file BytePool.hpp
 * @brief 冷构造、有界准入、可回收的字节池。
 */
#pragma once

#include <Prism/Foundation/Memory/BytePoolOptions.hpp>
#include <Prism/Foundation/Memory/BytePoolMetrics.hpp>
#include <Prism/Foundation/Memory/OwnedBytes.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Memory
{
    /**
     * @brief 创建固定容量真实存储并发放独占块租约的冷路径 owner。
     * @details 无全局池或 PMR 回退；所有分配发生在构造，热路径不新增控制块。
     *          每份排队或在途 OwnedBytes 均占整块，缩短逻辑长度不提前释放额度。
     *          标记数组和共享状态另有固定冷路径开销；外部队列节点须另行预约预算。
     *          不绑定 executor；可并发获取不同租约，不可与池析构并发调用成员。
     *          池析构后已发放租约仍保活存储，最后一个 owner 负责最终释放。
     */
    class BytePool final
    {
    public:
        /**
         * @brief 在冷路径创建并持有全部块与占用标记。
         * @param Options 按值消费的固定容量配置；默认 2048 个 64 KiB 块，共 128 MiB。
         * @throws Detail::BytePoolError 零尺寸或零块数为 InvalidArgument，容量溢出为 OversizedMsg。
         * @throws std::bad_alloc 冷路径真实存储分配失败，由启动边界收口。
         */
        explicit BytePool(const BytePoolOptions Options = {})
            : State_(std::make_shared<Detail::BytePoolState>(Options))
        {
        }

        BytePool(const BytePool&) = delete;
        auto operator=(const BytePool&) -> BytePool& = delete;
        BytePool(BytePool&&) = delete;
        auto operator=(BytePool&&) -> BytePool& = delete;

        /**
         * @brief 即时预约一个整块并返回拥有型字节；零长度同样持有真实块。
         * @param Size 初始逻辑长度，不能超过单块容量；大消息由业务逐块处理。
         * @return 超单块容量为 OversizedMsg，有界尝试未取得块为 ResourceUnavailable；均不等待。
         * @details 成功租约由调用者持有至异步访问全部结束；不取消或半关闭 I/O。
         *          只执行有界原子扫描和既有状态引用计数，不分配或抛出异常。
         */
        [[nodiscard]] auto TryAcquire(const std::size_t Size) noexcept
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

        /** @brief 返回池实际字节容量，不含固定状态与标记开销。 */
        [[nodiscard]] auto CapacityBytes() const noexcept -> std::size_t
        {
            return State_->CapacityBytes();
        }

        /** @brief 返回预约整块容量观察值；并发变化时不是一致快照。 */
        [[nodiscard]] auto UsedBytes() const noexcept -> std::size_t
        {
            return State_->UsedBlocks() * State_->BlockSize();
        }

        /** @brief 返回可用块数观察值，仅准入操作能够实际预约容量。 */
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
}
