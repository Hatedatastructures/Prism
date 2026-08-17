/**
 * @file directory.hpp
 * @brief 账户目录（T5-3 O3）
 * @details 凭证 → 账户条目的写时复制目录：
 *          - entry：原子活跃连接 + 连接上限 + 禁用/过期标志
 *          - directory：upsert/insert/remove/find + 快照遍历
 *          - lease：RAII 租约（析构自动释放活跃连接）
 *          - try_acquire：CAS 限流获取（未禁用/未过期/未超限）
 * @note 测试库自包含；认证（T5-1 O1）基于本目录的 disabled/expire 判断
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/memory/cow_map.hpp>

namespace preview::account
{

    /**
     * @class entry
     * @brief 账户条目
     * @details 原子活跃连接数 + 静态配置（上限/禁用/过期）。
     *          活跃连接经 lease RAII 增减。
     */
    class entry
    {
    public:
        /**
         * @brief 构造
         * @param max_connections 连接上限（0 = 无限制）
         * @param disabled 是否禁用
         * @param expire_at 过期时间戳（0 = 永不过期）
         */
        explicit entry(std::uint32_t max_connections = 0, bool disabled = false,
                       std::uint64_t expire_at = 0)
            : max_connections_(max_connections), disabled_(disabled), expire_at_(expire_at)
        {
        }

        /**
         * @brief 尝试增加活跃连接（CAS）
         * @return 成功返回 true
         */
        [[nodiscard]] auto try_add_active() -> bool
        {
            if (disabled_.load(std::memory_order_acquire))
            {
                return false;
            }
            if (max_connections_ == 0)
            {
                active_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            auto current = active_.load(std::memory_order_relaxed);
            while (true)
            {
                if (current >= max_connections_)
                {
                    return false;
                }
                if (active_.compare_exchange_weak(current, current + 1, std::memory_order_relaxed,
                                                  std::memory_order_relaxed))
                {
                    return true;
                }
            }
        }

        /**
         * @brief 释放活跃连接
         */
        void release_active()
        {
            active_.fetch_sub(1, std::memory_order_relaxed);
        }

        /**
         * @brief 活跃连接数
         */
        [[nodiscard]] auto active() const -> std::uint32_t
        {
            return active_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 连接上限
         */
        [[nodiscard]] auto max_connections() const -> std::uint32_t
        {
            return max_connections_;
        }

        /**
         * @brief 是否禁用
         */
        [[nodiscard]] auto disabled() const -> bool
        {
            return disabled_.load(std::memory_order_acquire);
        }

        /**
         * @brief 过期时间戳
         */
        [[nodiscard]] auto expire_at() const -> std::uint64_t
        {
            return expire_at_.load(std::memory_order_acquire);
        }

        /**
         * @brief 是否已过期
         * @param now 当前时间戳（须传入；expire_at 为 0 永不过期）
         */
        [[nodiscard]] auto expired(std::uint64_t now) const -> bool
        {
            const auto at = expire_at_.load(std::memory_order_acquire);
            return at != 0 && now >= at;
        }

    private:
        std::atomic<std::uint32_t> active_{0}; ///< 活跃连接数
        std::uint32_t max_connections_{0};     ///< 连接上限（0 = 无限制）
        std::atomic<bool> disabled_{false};    ///< 禁用标志
        std::atomic<std::uint64_t> expire_at_{0}; ///< 过期时间戳（0 = 永不过期）
    };

    /// 条目共享指针
    using shared_entry = std::shared_ptr<entry>;

    /**
     * @class lease
     * @brief 账户连接租约（RAII）
     * @details 持有时占用一条活跃连接，析构自动释放。
     *          move-only；bool 判空。
     */
    class lease
    {
    public:
        /**
         * @brief 构造空租约
         */
        lease() = default;

        /**
         * @brief 构造持约
         * @param e 条目
         */
        explicit lease(shared_entry e) : entry_(std::move(e))
        {
        }

        /**
         * @brief 析构：释放活跃连接
         */
        ~lease()
        {
            if (entry_)
            {
                entry_->release_active();
            }
        }

        lease(const lease &) = delete;
        auto operator=(const lease &) -> lease & = delete;

        /**
         * @brief 移动构造
         */
        lease(lease &&other) noexcept : entry_(std::move(other.entry_))
        {
        }

        /**
         * @brief 移动赋值
         */
        auto operator=(lease &&other) noexcept -> lease &
        {
            if (this != &other)
            {
                if (entry_)
                {
                    entry_->release_active();
                }
                entry_ = std::move(other.entry_);
            }
            return *this;
        }

        /**
         * @brief 是否持有租约
         */
        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(entry_);
        }

        /**
         * @brief 条目
         */
        [[nodiscard]] auto get() const -> shared_entry
        {
            return entry_;
        }

    private:
        shared_entry entry_; ///< 条目
    };

    /**
     * @class directory
     * @brief 账户目录
     * @details 凭证 → 条目的写时复制映射（无锁读 + CAS 写）。
     */
    class directory
    {
    public:
        /**
         * @brief 插入或更新条目
         * @param credential 凭证
         * @param max_connections 连接上限（0 = 无限制）
         * @param disabled 禁用
         * @param expire_at 过期时间戳（0 = 永不过期）
         */
        void upsert(std::string_view credential, std::uint32_t max_connections = 0, bool disabled = false,
                    std::uint64_t expire_at = 0)
        {
            entries_.set(std::string(credential),
                         std::make_shared<entry>(max_connections, disabled, expire_at));
        }

        /**
         * @brief 注册已有条目（多协议共享同一 entry → 共享配额）
         * @param credential 凭证
         * @param existing 已有条目
         */
        void insert(std::string_view credential, shared_entry existing)
        {
            entries_.set(std::string(credential), std::move(existing));
        }

        /**
         * @brief 移除条目
         * @param credential 凭证
         * @return 存在并移除返回 true
         */
        auto remove(std::string_view credential) -> bool
        {
            return entries_.remove(std::string(credential));
        }

        /**
         * @brief 查找条目
         * @param credential 凭证
         * @return 条目（未找到 nullptr）
         */
        [[nodiscard]] auto find(std::string_view credential) const -> shared_entry
        {
            shared_entry e;
            if (entries_.find(std::string(credential), e))
            {
                return e;
            }
            return nullptr;
        }

        /**
         * @brief 是否存在
         */
        [[nodiscard]] auto contains(std::string_view credential) const -> bool
        {
            return static_cast<bool>(find(credential));
        }

        /**
         * @brief 快照遍历
         * @tparam Fn 回调签名 void(string_view, const shared_entry &)
         * @param fn 回调
         */
        template <typename Fn>
        void for_each(Fn &&fn) const
        {
            const auto snap = entries_.snapshot();
            for (const auto &[cred, e] : *snap)
            {
                fn(std::string_view(cred), e);
            }
        }

        /**
         * @brief 条目数
         */
        [[nodiscard]] auto size() const -> std::size_t
        {
            return entries_.size();
        }

        /**
         * @brief 清空
         */
        void clear()
        {
            entries_.clear();
        }

    private:
        preview::memory::cow_map<std::string, shared_entry> entries_; ///< 凭证 → 条目
    };

    /**
     * @brief 尝试获取租约
     * @param dir 账户目录
     * @param credential 凭证
     * @param now 当前时间戳（0 = 不过期校验）
     * @return 持约 lease；失败（不存在/禁用/过期/超限）返回空
     */
    [[nodiscard]] inline auto try_acquire(const directory &dir, std::string_view credential,
                                          std::uint64_t now = 0) -> lease
    {
        auto e = dir.find(credential);
        if (!e || e->disabled() || (now != 0 && e->expired(now)))
        {
            return lease{};
        }
        if (!e->try_add_active())
        {
            return lease{};
        }
        return lease(std::move(e));
    }

} // namespace preview::account
