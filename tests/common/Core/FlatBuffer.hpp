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
        explicit FlatBuffer(std::size_t InitialSize = DefaultInitialSize) : Storage_(InitialSize)
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
            return Size_;
        }

        /**
         * @brief 当前容量
         * @return 当前容量（字节）
         */
        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return Storage_.size();
        }

        /**
         * @brief 是否为空
         * @return 空返回 true
         */
        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Size_ == 0;
        }

        /**
         * @brief 可写空间大小（容量 - 已用）
         * @return 可写字节数
         */
        [[nodiscard]] auto MaxSize() const noexcept -> std::size_t
        {
            return Storage_.size() - Size_;
        }

        /**
         * @brief 已缓冲数据的只读视图
         * @return 已缓冲数据的只读 span
         */
        [[nodiscard]] auto Data() const noexcept -> std::span<const std::uint8_t>
        {
            return {Storage_.data(), Size_};
        }

        /**
         * @brief 已缓冲数据的可变视图
         * @return 已缓冲数据的可变 span
         */
        [[nodiscard]] auto MutableData() noexcept -> std::span<std::uint8_t>
        {
            return {Storage_.data(), Size_};
        }

        /**
         * @brief 预留追加空间
         * @param n 期望追加的字节数
         * @return 可写区间（[0, n)），实际可用可能更大
         * @note 空间不足时自动增长（倍增），失败返回空区间
         */
        [[nodiscard]] auto Prepare(std::size_t N) -> std::span<std::uint8_t>
        {
            if (N > MaxSize())
            {
                if (!Grow(Size_ + N))
                {
                    return {};
                }
            }
            return {Storage_.data() + Size_, MaxSize()};
        }

        /**
         * @brief 提交已写入的字节数（与 Prepare 配套）
         * @param n 已写入字节数，不得超过 Prepare 返回区间大小
         */
        auto Commit(std::size_t N) -> void
        {
            Size_ += std::min(N, MaxSize());
        }

        /**
         * @brief 从头部消费字节（丢弃最早的数据）
         * @param n 消费字节数，超过 Size() 时全部消费
         * @note 消费后内存前移，O(n)
         */
        auto Consume(std::size_t N) -> void
        {
            N = std::min(N, Size_);
            if (N == 0)
            {
                return;
            }
            std::memmove(Storage_.data(), Storage_.data() + N, Size_ - N);
            Size_ -= N;
        }

        /**
         * @brief 清空缓冲区（保留容量）
         */
        auto Clear() noexcept -> void
        {
            Size_ = 0;
        }

        /**
         * @brief 收缩容量至当前数据大小（最低保留 InitialSize）
         */
        auto ShrinkToFit() -> void
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

        /**
         * @brief 追加一段数据（拷贝）
         * @return 成功追加的字节数（0 = 空间不足）
         */
        auto Append(std::span<const std::uint8_t> src) -> std::size_t
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

        /**
         * @brief 尝试预分配容量（不改变已有数据）
         */
        auto Reserve(std::size_t N) -> void
        {
            if (N > Storage_.size())
            {
                Grow(N);
            }
        }

    private:
        std::vector<std::uint8_t> Storage_;
        std::size_t Size_{0};
        std::size_t InitialSize_{DefaultInitialSize};

        /**
         * @brief 增长到至少 n 字节（倍增），失败返回 false
         * @param n 目标容量
         * @return 增长成功返回 true
         */
        auto Grow(std::size_t N) -> bool
        {
            if (N > MaxSizeLimit)
            {
                return false;
            }
            auto NewCap = std::max(Storage_.size() * 2, N);
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
    };

} // namespace Preview
