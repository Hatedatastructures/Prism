/**
 * @file flat_buffer.hpp
 * @brief 连续内存缓冲区（借鉴 Boost.Beast flat_buffer）
 * @details 热路径零堆分配：单块连续内存，支持 prepare/commit 追加、
 *          consume 消费、按需增长（倍增策略）、shrink_to_fit 收缩。
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

namespace psmtest
{

    /// 连续缓冲区（flat buffer）
    class flat_buffer
    {
    public:
        /// 默认初始容量
        static constexpr std::size_t default_initial_size = 1024;
        /// 最大容量上限
        static constexpr std::size_t max_size_limit = std::numeric_limits<std::size_t>::max() / 2;

        /// @brief 构造
        /// @param initial_size 初始容量
        explicit flat_buffer(std::size_t initial_size = default_initial_size)
            : storage_(initial_size)
        {
        }

        flat_buffer(const flat_buffer &) = delete;
        auto operator=(const flat_buffer &) -> flat_buffer & = delete;

        /// 移动构造
        flat_buffer(flat_buffer &&) noexcept = default;

        /// 移动赋值
        auto operator=(flat_buffer &&) noexcept -> flat_buffer & = default;

        /// 已缓冲数据大小
        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return size_;
        }

        /// 当前容量
        [[nodiscard]] auto capacity() const noexcept -> std::size_t
        {
            return storage_.size();
        }

        /// 是否为空
        [[nodiscard]] auto empty() const noexcept -> bool
        {
            return size_ == 0;
        }

        /// 可写空间大小（容量 - 已用）
        [[nodiscard]] auto max_size() const noexcept -> std::size_t
        {
            return storage_.size() - size_;
        }

        /// 已缓冲数据的只读视图
        [[nodiscard]] auto data() const noexcept -> std::span<const std::uint8_t>
        {
            return {storage_.data(), size_};
        }

        /// 已缓冲数据的可变视图
        [[nodiscard]] auto mutable_data() noexcept -> std::span<std::uint8_t>
        {
            return {storage_.data(), size_};
        }

        /// @brief 预留追加空间
        /// @param n 期望追加的字节数
        /// @return 可写区间（[0, n)），实际可用可能更大
        /// @note 空间不足时自动增长（倍增），失败返回空区间
        [[nodiscard]] auto prepare(std::size_t n) -> std::span<std::uint8_t>
        {
            if (n > max_size())
            {
                if (!grow(size_ + n))
                    return {};
            }
            return {storage_.data() + size_, max_size()};
        }

        /// @brief 提交已写入的字节数（与 prepare 配套）
        /// @param n 已写入字节数，不得超过 prepare 返回区间大小
        auto commit(std::size_t n) -> void
        {
            size_ += std::min(n, max_size());
        }

        /// @brief 从头部消费字节（丢弃最早的数据）
        /// @param n 消费字节数，超过 size() 时全部消费
        /// @note 消费后内存前移，O(n)
        auto consume(std::size_t n) -> void
        {
            n = std::min(n, size_);
            if (n == 0)
                return;
            std::memmove(storage_.data(), storage_.data() + n, size_ - n);
            size_ -= n;
        }

        /// @brief 清空缓冲区（保留容量）
        auto clear() noexcept -> void
        {
            size_ = 0;
        }

        /// @brief 收缩容量至当前数据大小（最低保留 initial_size）
        auto shrink_to_fit() -> void
        {
            const auto target = std::max(size_, initial_size_);
            if (target < storage_.size())
            {
                std::vector<std::uint8_t> tmp(target);
                if (size_ > 0)
                    std::memcpy(tmp.data(), storage_.data(), size_);
                storage_.swap(tmp);
            }
        }

        /// @brief 追加一段数据（拷贝）
        /// @return 成功追加的字节数（0 = 空间不足）
        auto append(std::span<const std::uint8_t> src) -> std::size_t
        {
            auto space = prepare(src.size());
            if (space.empty())
                return 0;
            const auto n = std::min(space.size(), src.size());
            std::memcpy(space.data(), src.data(), n);
            commit(n);
            return n;
        }

        /// @brief 尝试预分配容量（不改变已有数据）
        auto reserve(std::size_t n) -> void
        {
            if (n > storage_.size())
                grow(n);
        }

    private:
        std::vector<std::uint8_t> storage_;
        std::size_t size_{0};
        std::size_t initial_size_{default_initial_size};

        /// 增长到至少 n 字节（倍增），失败返回 false
        auto grow(std::size_t n) -> bool
        {
            if (n > max_size_limit)
                return false;
            auto new_cap = std::max(storage_.size() * 2, n);
            new_cap = std::min(new_cap, max_size_limit);
            try
            {
                storage_.resize(new_cap);
                return true;
            }
            catch (...)
            {
                return false;
            }
        }
    };

} // namespace psmtest
