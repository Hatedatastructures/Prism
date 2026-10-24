/**
 * @file DatagramInbox.hpp
 * @brief 原生 QUIC 的有界数据报接收队列。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Quic::Detail
{

    /**
     * @class DatagramInbox
     * @brief 在所属执行器上串行访问的 FIFO 数据报队列
     * @details 队列同时限制待处理数据报数量和 payload 字节数；超限时丢弃新包。
     */
    class DatagramInbox final
    {
    public:
        /**
         * @struct Limits
         * @brief 单连接 Native 暂存队列预算
         */
        struct Limits
        {
            std::size_t MaxDatagrams{64};
            std::size_t MaxBytes{64U * 1024U};
        };

        DatagramInbox();
        explicit DatagramInbox(Limits LimitsValue);

        /**
         * @brief 复制并尝试加入一个完整数据报
         * @return 成功入队时为 true；容量不足或分配失败时丢弃新包并返回 false
         */
        [[nodiscard]] auto Enqueue(std::span<const std::byte> Data) noexcept -> bool;

        /**
         * @brief 移交队首数据报
         * @return 队列非空时的完整数据报；队列为空时为 std::nullopt
         */
        [[nodiscard]] auto Dequeue() -> std::optional<std::vector<std::byte>>;

        [[nodiscard]] auto PendingCount() const noexcept -> std::size_t
        {
            return Datagrams_.size();
        }
        [[nodiscard]] auto PendingBytes() const noexcept -> std::size_t
        {
            return PendingBytes_;
        }
        [[nodiscard]] auto DroppedCount() const noexcept -> std::uint64_t
        {
            return DroppedCount_;
        }

    private:
        auto CountDrop() noexcept -> void;

        Limits Limits_;
        std::deque<std::vector<std::byte>> Datagrams_;
        std::size_t PendingBytes_{0};
        std::uint64_t DroppedCount_{0};
    };

} // namespace Prism::Quic
