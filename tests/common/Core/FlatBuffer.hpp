/**
 * @file FlatBuffer.hpp
 * @brief 连续内存缓冲区（借鉴 Boost.Beast FlatBuffer）
 * @details 热路径零堆分配：单块连续内存，支持 Prepare/Commit 追加、
 *          Consume 消费、按需增长（倍增策略）、ShrinkToFit 收缩。
 *          与协议解析器配合，避免逐包拷贝。
 * @note 线程安全：非线程安全，单线程（strand）内使用。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

namespace Preview
{

    /// 连续缓冲区（flat Buffer）
    class FlatBuffer
    {
    public:
        /// 默认初始容量
        static constexpr std::size_t DefaultInitialSize = 1024;
        /// 最大容量上限
        static constexpr std::size_t MaxSizeLimit = std::numeric_limits<std::size_t>::max() / 2;

        /**
         * @brief 构造
         * @param InitialSize 初始容量
         */
        explicit FlatBuffer(std::size_t InitialSize = DefaultInitialSize) : storage_(InitialSize)
        {
        }

        FlatBuffer(const FlatBuffer &) = delete;
        auto operator=(const FlatBuffer &) -> FlatBuffer & = delete;

        /**
         * @brief 移动构造
         */
        FlatBuffer(FlatBuffer &&) noexcept = default;

        /**
         * @brief 移动赋值
         */
        auto operator=(FlatBuffer &&) noexcept -> FlatBuffer & = default;

        /**
         * @brief 已缓冲数据大小
         * @return 已缓冲字节数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return size_;
        }

        /**
         * @brief 当前容量
         * @return 当前容量（字节）
         */
        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return storage_.size();
        }

        /**
         * @brief 是否为空
         * @return 空返回 true
         */
        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return size_ == 0;
        }

        /**
         * @brief 可写空间大小（容量 - 已用）
         * @return 可写字节数
         */
        [[nodiscard]] auto MaxSize() const noexcept -> std::size_t
        {
            return storage_.size() - size_;
        }

        /**
         * @brief 已缓冲数据的只读视图
         * @return 已缓冲数据的只读 span
         */
        [[nodiscard]] auto Data() const noexcept -> std::span<const std::uint8_t>
        {
            return {storage_.data(), size_};
        }

        /**
         * @brief 已缓冲数据的可变视图
         * @return 已缓冲数据的可变 span
         */
        [[nodiscard]] auto MutableData() noexcept -> std::span<std::uint8_t>
        {
            return {storage_.data(), size_};
        }

        /**
         * @brief 预留追加空间
         * @param n 期望追加的字节数
         * @return 可写区间（[0, n)），实际可用可能更大
         * @note 空间不足时自动增长（倍增），失败返回空区间
         */
        [[nodiscard]] auto Prepare(std::size_t n) -> std::span<std::uint8_t>
        {
            if (n > MaxSize())
            {
                if (!Grow(size_ + n))
                {
                    return {};
                }
            }
            return {storage_.data() + size_, MaxSize()};
        }

        /**
         * @brief 提交已写入的字节数（与 Prepare 配套）
         * @param n 已写入字节数，不得超过 Prepare 返回区间大小
         */
        auto Commit(std::size_t n) -> void
        {
            size_ += std::min(n, MaxSize());
        }

        /**
         * @brief 从头部消费字节（丢弃最早的数据）
         * @param n 消费字节数，超过 Size() 时全部消费
         * @note 消费后内存前移，O(n)
         */
        auto Consume(std::size_t n) -> void
        {
            n = std::min(n, size_);
            if (n == 0)
            {
                return;
            }
            std::memmove(storage_.data(), storage_.data() + n, size_ - n);
            size_ -= n;
        }

        /**
         * @brief 清空缓冲区（保留容量）
         */
        auto Clear() noexcept -> void
        {
            size_ = 0;
        }

        /**
         * @brief 收缩容量至当前数据大小（最低保留 InitialSize）
         */
        auto ShrinkToFit() -> void
        {
            const auto Target = std::max(size_, InitialSize_);
            if (Target < storage_.size())
            {
                std::vector<std::uint8_t> tmp(Target);
                if (size_ > 0)
                {
                    std::memcpy(tmp.data(), storage_.data(), size_);
                }
                storage_.swap(tmp);
            }
        }

        /**
         * @brief 追加一段数据（拷贝）
         * @return 成功追加的字节数（0 = 空间不足）
         */
        auto Append(std::span<const std::uint8_t> src) -> std::size_t
        {
            auto space = Prepare(src.size());
            if (space.empty())
            {
                return 0;
            }
            const auto n = std::min(space.size(), src.size());
            std::memcpy(space.data(), src.data(), n);
            Commit(n);
            return n;
        }

        /**
         * @brief 尝试预分配容量（不改变已有数据）
         */
        auto Reserve(std::size_t n) -> void
        {
            if (n > storage_.size())
            {
                Grow(n);
            }
        }

    private:
        std::vector<std::uint8_t> storage_;
        std::size_t size_{0};
        std::size_t InitialSize_{DefaultInitialSize};

        /**
         * @brief 增长到至少 n 字节（倍增），失败返回 false
         * @param n 目标容量
         * @return 增长成功返回 true
         */
        auto Grow(std::size_t n) -> bool
        {
            if (n > MaxSizeLimit)
            {
                return false;
            }
            auto NewCap = std::max(storage_.size() * 2, n);
            NewCap = std::min(NewCap, MaxSizeLimit);
            try
            {
                storage_.resize(NewCap);
                return true;
            }
            catch (...)
            {
                return false;
            }
        }
    };

} // namespace Preview
