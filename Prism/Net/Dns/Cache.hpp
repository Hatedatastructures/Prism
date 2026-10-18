/**
 * @file Cache.hpp
 * @brief DNS结果缓存、唯一LRU节点和到期退休。
 * @details 每个活跃记录只有一个槽内Previous/Next节点；命中与覆盖仅摘除再重连，
 *          最旧记录可直接摘除，不维护失效历史队列，也不执行热路径压实。
 *          正缓存真实零TTL在钳制之前拒绝；负缓存使用独立期限。
 * @note 所有索引及LRU访问必须在所属控制executor；返回结果生命周期由调用者合同管理。
 */
#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/container/small_vector.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "Config.hpp"

namespace Prism::Network::Dns
{

    /**
     * @struct CacheOptions
     * @brief 缓存容量与 TTL 约束
     */
    struct CacheOptions
    {
        std::size_t MaxEntries{10000};            ///< 最大条目数（LRU 淘汰阈值）；0 = 无限
        std::chrono::seconds TtlMin{0};           ///< 存入 TTL 下限钳制
        std::chrono::seconds TtlMax{86400};       ///< 存入 TTL 上限钳制
        std::chrono::seconds NegativeTtl{30};     ///< 负缓存 TTL
        StalePolicy Policy{StalePolicy::Discard}; ///< 过期策略
    };

    /**
     * @struct PutInput
     * @brief 缓存写入参数
     */
    struct PutInput
    {
        std::string Domain;                                              ///< 已规范化域名
        std::uint16_t QType{};                                           ///< 查询类型数值
        boost::container::small_vector<boost::asio::ip::address, 4> Ips; ///< 解析结果（空 = 负缓存语义）
        std::chrono::seconds Ttl{0}; ///< 记录 TTL（会被 TtlMin/TtlMax 钳制）
        bool Failed{false};          ///< true 表示负缓存结果
    };

    /// 缓存条目的地址容器（4 个内联覆盖绝大多数应答）
    using IpList = boost::container::small_vector<boost::asio::ip::address, 4>;

    /**
     * @class Cache
     * @brief DNS 响应内存缓存（非线程安全，单 io_context 内使用）
     * @details 连续存储 + 槽号 LRU 队列：插入/命中/提升/淘汰均摊 O(1)，
     *          查找路径零堆分配
     */
    class Cache
    {
    public:
        static constexpr std::size_t NoSlot = std::numeric_limits<std::size_t>::max();
        /**
         * @struct Entry
         * @brief 缓存条目（连续存放于 Slots_，缓存行友好）
         */
        struct Entry
        {
            std::string Key;                                ///< 自身键（淘汰时反查索引）
            IpList Ips;                                     ///< 解析结果
            std::chrono::steady_clock::time_point Expire;   ///< 过期时刻
            std::chrono::steady_clock::time_point Inserted; ///< 写入时刻（记录用）
            bool Failed{false};                             ///< 负缓存标记
            bool Dead{false};                               ///< 失效标记（已淘汰/被覆盖）
            std::size_t Previous{NoSlot}; ///< 唯一LRU节点的前驱。
            std::size_t Next{NoSlot}; ///< 唯一LRU节点的后继。
            bool Linked{false}; ///< 是否属于当前活跃LRU链。
        };

        /**
         * @brief 构造缓存
         * @param opts 容量与 TTL 配置；MaxEntries==0 视为无限（仅追加、不淘汰）
         */
        explicit Cache(CacheOptions opts) : Options_(opts), Unlimited_(opts.MaxEntries == 0)
        {
            if (!Unlimited_)
            {
                Slots_.reserve(opts.MaxEntries);
            }
        }

        /**
         * @brief 查询缓存（命中即提升 LRU 顺序；查找零堆分配）
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         * @return nullopt=未命中；空 vector=负缓存命中；非空=正命中。
         *         过期时按策略：Serve 返回旧数据（同样提升），Discard 擦除后返回 nullopt
         */
        [[nodiscard]] auto Get(const std::string& Domain, const std::uint16_t QTypeValue)
            -> std::optional<IpList>
        {
            const auto Key = KeyView(Domain, QTypeValue);
            const auto It = Index_.find(Key);
            if (It == Index_.end())
            {
                return std::nullopt;
            }
            Entry& EntryValue = Slots_[It->second];
            if (std::chrono::steady_clock::now() >= EntryValue.Expire)
            {
                if (Options_.Policy == StalePolicy::Discard)
                {
                    Drop(It);
                    return std::nullopt;
                }
                Promote(It->second);
                if (EntryValue.Failed)
                {
                    return IpList{};
                }
                return EntryValue.Ips;
            }
            Promote(It->second);
            if (EntryValue.Failed)
            {
                return IpList{};
            }
            return EntryValue.Ips;
        }

        /**
         * @brief 写入缓存（自动按 TtlMin/TtlMax 钳制 TTL）
         * @param in 写入参数；Failed=true 时写入负缓存语义
         */
        void Put(const PutInput& Input)
        {
            if (!Input.Failed && Input.Ttl <= std::chrono::seconds::zero()) return;
            auto Ttl = Input.Ttl;
            if (Options_.TtlMax > std::chrono::seconds{0})
            {
                Ttl = std::min(Ttl, Options_.TtlMax);
            }
            Ttl = std::max(Ttl, Options_.TtlMin);
            Store(Input, Ttl);
        }

        /**
         * @brief 写入负缓存（固定 NegativeTtl）
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         */
        void PutNegative(const std::string& Domain, const std::uint16_t QTypeValue)
        {
            PutInput Input;
            Input.Domain = Domain;
            Input.QType = QTypeValue;
            Input.Ttl = Options_.NegativeTtl;
            Input.Failed = true;
            Store(Input, Options_.NegativeTtl);
        }

        /**
         * @brief 主动驱逐全部已过期条目（供维护循环周期调用）
         * @return 驱逐数量；serve-stale 模式下同样清理（由 LRU 自然淘汰兜底）
         */
        auto EvictExpired() -> std::size_t
        {
            const auto Now = std::chrono::steady_clock::now();
            std::size_t Evicted = 0;
            for (auto It = Index_.begin(); It != Index_.end();)
            {
                const Entry& EntryValue = Slots_[It->second];
                if (Now >= EntryValue.Expire)
                {
                    It = Drop(It);
                    ++Evicted;
                }
                else
                {
                    ++It;
                }
            }
            return Evicted;
        }

        /**
         * @brief 当前条目数（仅计存活条目，失效项不计入）
         * @return 缓存中的存活条目总数（含负缓存）
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Index_.size();
        }

        /**
         * @brief 清空全部缓存
         */
        void Clear()
        {
            Index_.clear();
            Oldest_ = NoSlot;
            Newest_ = NoSlot;
            Free_.clear();
            Slots_.clear();
            LiveCount_ = 0;
            if (!Unlimited_)
            {
                Slots_.reserve(Options_.MaxEntries);
            }
        }

        /**
         * @brief 构造缓存键（持久化用）
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         * @return "domain:qtype"
         */
        [[nodiscard]] static auto MakeKey(const std::string& Domain, const std::uint16_t QTypeValue)
            -> std::string
        {
            return Domain + ':' + std::to_string(QTypeValue);
        }

    private:
        /// 在栈缓冲中拼出查找键（domain ≤253 字节 + ':' + ≤5 位 qtype）
        [[nodiscard]] auto KeyView(const std::string& Domain, const std::uint16_t QTypeValue)
            -> std::string_view
        {
            if (Domain.size() + 6 <= KeyBuf_.size())
            {
                auto* Cursor = KeyBuf_.data();
                std::memcpy(Cursor, Domain.data(), Domain.size());
                Cursor += Domain.size();
                *Cursor++ = ':';
                const auto End = std::to_chars(Cursor, KeyBuf_.data() + KeyBuf_.size(), QTypeValue);
                return {KeyBuf_.data(), static_cast<std::size_t>(End.ptr - KeyBuf_.data())};
            }
            HeapKey_ = MakeKey(Domain, QTypeValue); // 超长域名退化为堆键（罕见）
            return HeapKey_;
        }

        /** @brief 摘除唯一节点；只更新索引，不分配或追加历史。 */
        auto Unlink(const std::size_t Slot) noexcept -> void
        {
            auto& EntryValue = Slots_[Slot];
            if (!EntryValue.Linked) return;
            if (EntryValue.Previous == NoSlot) Oldest_ = EntryValue.Next;
            else Slots_[EntryValue.Previous].Next = EntryValue.Next;
            if (EntryValue.Next == NoSlot) Newest_ = EntryValue.Previous;
            else Slots_[EntryValue.Next].Previous = EntryValue.Previous;
            EntryValue.Previous = NoSlot;
            EntryValue.Next = NoSlot;
            EntryValue.Linked = false;
        }

        /** @brief 将唯一活跃节点重连到最近使用端；命中不创建历史节点。 */
        auto Promote(const std::size_t Slot) noexcept -> void
        {
            Unlink(Slot);
            auto& EntryValue = Slots_[Slot];
            EntryValue.Previous = Newest_;
            EntryValue.Next = NoSlot;
            EntryValue.Linked = true;
            if (Newest_ == NoSlot) Oldest_ = Slot;
            else Slots_[Newest_].Next = Slot;
            Newest_ = Slot;
        }

        /** @brief 淘汰唯一最旧节点；不扫描失效历史，不执行压实分配。 */
        auto EvictOldest() -> void
        {
            if (Oldest_ == NoSlot) return;
            const auto Found = Index_.find(Slots_[Oldest_].Key);
            if (Found != Index_.end()) (void)Drop(Found);
        }

        /// 惰性删除条目（查询路径过期丢弃时调用），返回下一迭代器
        auto Drop(std::unordered_map<std::string, std::size_t, TransparentStringHash,
            TransparentStringEqual>::iterator It) -> std::unordered_map<std::string, std::size_t,
            TransparentStringHash, TransparentStringEqual>::iterator
        {
            const auto Slot = It->second;
            Unlink(Slot);
            auto Next = std::next(It);
            Index_.erase(It);
            Slots_[Slot].Dead = true;
            --LiveCount_;
            Free_.push_back(Slot);
            return Next;
        }

        /// 统一写入入口（插入 / 覆盖刷新 / 淘汰，均摊 O(1)）
        void Store(const PutInput& Input, const std::chrono::seconds Ttl)
        {
            const auto Key = MakeKey(Input.Domain, Input.QType);
            const auto Now = std::chrono::steady_clock::now();

            // 覆盖已有键：旧槽失效并交还回收站（新项入队尾 = 刷新到最新）
            if (const auto It = Index_.find(Key); It != Index_.end())
            {
                (void)Drop(It);
            }

            if (!Unlimited_ && LiveCount_ >= Options_.MaxEntries)
            {
                EvictOldest();
            }

            // 取槽：优先复用回收站，否则追加到连续存储
            std::size_t Slot;
            if (!Free_.empty())
            {
                Slot = Free_.back();
                Free_.pop_back();
            }
            else
            {
                Slot = Slots_.size();
                Slots_.resize(Slot + 1);
            }

            Entry fresh;
            fresh.Key = Key;
            fresh.Ips = Input.Ips;
            fresh.Expire = Now + Ttl;
            fresh.Inserted = Now;
            fresh.Failed = Input.Failed;
            fresh.Dead = false;
            Slots_[Slot] = std::move(fresh);
            Index_.emplace(Key, Slot);
            ++LiveCount_;
            Promote(Slot);
        }

        CacheOptions Options_;
        bool Unlimited_;           ///< MaxEntries==0 → 无限模式
        std::vector<Entry> Slots_; ///< 连续条目存储（局部性友好）
        std::unordered_map<std::string, std::size_t, TransparentStringHash,
            TransparentStringEqual>
            Index_;                      ///< key → Slots_ 槽位（透明哈希）
        std::size_t Oldest_{NoSlot}; ///< 最旧活跃节点。
        std::size_t Newest_{NoSlot}; ///< 最近活跃节点。
        std::vector<std::size_t> Free_;  ///< 失效槽回收站
        std::size_t LiveCount_{0};       ///< 存活条目数
        std::array<char, 260> KeyBuf_{}; ///< 查找键栈缓冲（命中路径零分配）
        std::string HeapKey_;            ///< 超长域名退化堆键（罕见路径）
    };

} // namespace Prism::Network::Dns
