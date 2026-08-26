/**
 * @file Directory.hpp
 * @brief 账户目录（T5-3 O3）
 * @details 凭证 → 账户条目的写时复制目录：
 *          - Entry：原子活跃连接 + 连接上限 + 禁用/过期标志
 *          - Directory：Upsert/Insert/Remove/Find + 快照遍历
 *          - Lease：RAII 租约（析构自动释放活跃连接）
 *          - TryAcquire：CAS 限流获取（未禁用/未过期/未超限）
 * @note 测试库自包含；认证（T5-1 O1）基于本目录的 Disabled/Expire 判断
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/Core/Memory/CowMap.hpp>

namespace Preview::Account
{

    /**
     * @class Entry
     * @brief 账户条目
     * @details 原子活跃连接数 + 静态配置（上限/禁用/过期）。
     *          活跃连接经 Lease RAII 增减。
     */
    class Entry
    {
    public:
        /**
         * @brief 构造
         * @param MaxConnections 连接上限（0 = 无限制）
         * @param Disabled 是否禁用
         * @param ExpireAt 过期时间戳（0 = 永不过期）
         */
        explicit Entry(std::uint32_t MaxConnections = 0, bool Disabled = false,
                       std::uint64_t ExpireAt = 0)
            : MaxConnections_(MaxConnections), Disabled_(Disabled), ExpireAt_(ExpireAt)
        {
        }

        /**
         * @brief 尝试增加活跃连接（CAS）
         * @return 成功返回 true
         */
        [[nodiscard]] auto TryAddActive() -> bool
        {
            if (Disabled_.load(std::memory_order_acquire))
            {
                return false;
            }
            if (MaxConnections_ == 0)
            {
                Active_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            auto Current = Active_.load(std::memory_order_relaxed);
            while (true)
            {
                if (Current >= MaxConnections_)
                {
                    return false;
                }
                if (Active_.compare_exchange_weak(Current, Current + 1, std::memory_order_relaxed,
                                                  std::memory_order_relaxed))
                {
                    return true;
                }
            }
        }

        /**
         * @brief 释放活跃连接
         */
        void ReleaseActive()
        {
            Active_.fetch_sub(1, std::memory_order_relaxed);
        }

        /**
         * @brief 活跃连接数
         */
        [[nodiscard]] auto Active() const -> std::uint32_t
        {
            return Active_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 连接上限
         */
        [[nodiscard]] auto MaxConnections() const -> std::uint32_t
        {
            return MaxConnections_;
        }

        /**
         * @brief 是否禁用
         */
        [[nodiscard]] auto Disabled() const -> bool
        {
            return Disabled_.load(std::memory_order_acquire);
        }

        /**
         * @brief 过期时间戳
         */
        [[nodiscard]] auto ExpireAt() const -> std::uint64_t
        {
            return ExpireAt_.load(std::memory_order_acquire);
        }

        /**
         * @brief 是否已过期
         * @param now 当前时间戳（须传入；ExpireAt 为 0 永不过期）
         */
        [[nodiscard]] auto Expired(std::uint64_t Now) const -> bool
        {
            const auto At = ExpireAt_.load(std::memory_order_acquire);
            return At != 0 && Now >= At;
        }

    private:
        std::atomic<std::uint32_t> Active_{0}; ///< 活跃连接数
        std::uint32_t MaxConnections_{0};     ///< 连接上限（0 = 无限制）
        std::atomic<bool> Disabled_{false};    ///< 禁用标志
        std::atomic<std::uint64_t> ExpireAt_{0}; ///< 过期时间戳（0 = 永不过期）
    };

    /// 条目共享指针
    using SharedEntry = std::shared_ptr<Entry>;

    /**
     * @class Lease
     * @brief 账户连接租约（RAII）
     * @details 持有时占用一条活跃连接，析构自动释放。
     *          move-only；bool 判空。
     */
    class Lease
    {
    public:
        /**
         * @brief 构造空租约
         */
        Lease() = default;

        /**
         * @brief 构造持约
         * @param e 条目
         */
        explicit Lease(SharedEntry E) : Entry_(std::move(E))
        {
        }

        /**
         * @brief 析构：释放活跃连接
         */
        ~Lease()
        {
            if (Entry_)
            {
                Entry_->ReleaseActive();
            }
        }

        Lease(const Lease &) = delete;
        auto operator=(const Lease &) -> Lease & = delete;

        /**
         * @brief 移动构造
         */
        Lease(Lease &&other) noexcept : Entry_(std::move(other.Entry_))
        {
        }

        /**
         * @brief 移动赋值
         */
        auto operator=(Lease &&other) noexcept -> Lease &
        {
            if (this != &other)
            {
                if (Entry_)
                {
                    Entry_->ReleaseActive();
                }
                Entry_ = std::move(other.Entry_);
            }
            return *this;
        }

        /**
         * @brief 是否持有租约
         */
        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(Entry_);
        }

        /**
         * @brief 条目
         */
        [[nodiscard]] auto Get() const -> SharedEntry
        {
            return Entry_;
        }

    private:
        SharedEntry Entry_; ///< 条目
    };

    /**
     * @class Directory
     * @brief 账户目录
     * @details 凭证 → 条目的写时复制映射（无锁读 + CAS 写）。
     */
    class Directory
    {
    public:
        /**
         * @brief 插入或更新条目
         * @param Credential 凭证
         * @param MaxConnections 连接上限（0 = 无限制）
         * @param Disabled 禁用
         * @param ExpireAt 过期时间戳（0 = 永不过期）
         */
        void Upsert(std::string_view Credential, std::uint32_t MaxConnections = 0, bool Disabled = false,
                    std::uint64_t ExpireAt = 0)
        {
            Entries_.Set(std::string(Credential),
                         std::make_shared<Entry>(MaxConnections, Disabled, ExpireAt));
        }

        /**
         * @brief 注册已有条目（多协议共享同一 Entry → 共享配额）
         * @param Credential 凭证
         * @param existing 已有条目
         */
        void Insert(std::string_view Credential, SharedEntry existing)
        {
            Entries_.Set(std::string(Credential), std::move(existing));
        }

        /**
         * @brief 移除条目
         * @param Credential 凭证
         * @return 存在并移除返回 true
         */
        auto Remove(std::string_view Credential) -> bool
        {
            return Entries_.Remove(std::string(Credential));
        }

        /**
         * @brief 查找条目
         * @param Credential 凭证
         * @return 条目（未找到 nullptr）
         */
        [[nodiscard]] auto Find(std::string_view Credential) const -> SharedEntry
        {
            SharedEntry E;
            if (Entries_.Find(std::string(Credential), E))
            {
                return E;
            }
            return nullptr;
        }

        /**
         * @brief 是否存在
         */
        [[nodiscard]] auto Contains(std::string_view Credential) const -> bool
        {
            return static_cast<bool>(Find(Credential));
        }

        /**
         * @brief 快照遍历
         * @tparam Fn 回调签名 void(string_view, const SharedEntry &)
         * @param fn 回调
         */
        template <typename Fn>
        void ForEach(Fn &&fn) const
        {
            const auto Snap = Entries_.Snapshot();
            for (const auto &[cred, E] : *Snap)
            {
                fn(std::string_view(cred), E);
            }
        }

        /**
         * @brief 条目数
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Entries_.Size();
        }

        /**
         * @brief 清空
         */
        void Clear()
        {
            Entries_.Clear();
        }

    private:
        Preview::Memory::CowMap<std::string, SharedEntry> Entries_; ///< 凭证 → 条目
    };

    /**
     * @brief 尝试获取租约
     * @param dir 账户目录
     * @param Credential 凭证
     * @param now 当前时间戳（0 = 不过期校验）
     * @return 持约 Lease；失败（不存在/禁用/过期/超限）返回空
     */
    [[nodiscard]] inline auto TryAcquire(const Directory &dir, std::string_view Credential,
                                          std::uint64_t Now = 0) -> Lease
    {
        auto E = dir.Find(Credential);
        if (!E || E->Disabled() || (Now != 0 && E->Expired(Now)))
        {
            return Lease{};
        }
        if (!E->TryAddActive())
        {
            return Lease{};
        }
        return Lease(std::move(E));
    }

} // namespace Preview::Account
