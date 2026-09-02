/**
 * @file Cache.hpp
 * @brief DNS 响应缓存层
 * @details 对齐主项目 net/dns/detail/cache.hpp 分层：
 *          - 键为 "domain:qtype"（域名已规范化小写）
 *          - LRU：Get 命中/覆盖写入都会把条目刷新为最新（世代号惰性重排），
 *            超额时淘汰最久未使用者，摊还 O(1)
 *          - 查找零分配：键在 260 字节栈缓冲拼出（透明哈希异构查找），
 *            仅插入新条目时才持久化 string 键
 *          - 负缓存：缓存"解析失败/被过滤"结果（空 IP 列表），防重复打上游
 *          - MaxEntries == 0 视为无限（不淘汰），与 Config 注释一致
 *
 *         数据结构与缓存局部性：
 *         - `Slots_`：`std::vector<Entry>` 连续存储全部条目，预取友好
 *         - `Index_`：`unordered_map`（透明哈希，string_view 异构查找）
 *         - `Order_`：`deque<SlotGen>` 槽位 LRU 队列，淘汰弹队头，惰性跳过
 *           已失效/已被提升项（世代号 Gen 判别），摊还 O(1)
 *         - `Free_`：失效槽回收站，新插入优先复用，`Slots_` 大小收敛于容量
 *
 * @note Get 语义与主项目一致：nullopt=未命中、空 vector=负缓存命中、非空=正命中
 */

#pragma once

#include "Config.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/container/small_vector.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @struct CacheOptions
     * @brief 缓存容量与 TTL 约束
     */
    struct CacheOptions
    {
        std::size_t MaxEntries{10000};              ///< 最大条目数（LRU 淘汰阈值）；0 = 无限
        std::chrono::seconds TtlMin{0};             ///< 存入 TTL 下限钳制
        std::chrono::seconds TtlMax{86400};         ///< 存入 TTL 上限钳制
        std::chrono::seconds NegativeTtl{30};       ///< 负缓存 TTL
        StalePolicy Policy{StalePolicy::Discard};   ///< 过期策略
    };

    /**
     * @struct PutInput
     * @brief 缓存写入参数
     */
    struct PutInput
    {
        std::string Domain; ///< 已规范化域名
        std::uint16_t QType{}; ///< 查询类型数值
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
        /**
         * @struct Entry
         * @brief 缓存条目（连续存放于 Slots_，缓存行友好）
         */
        struct Entry
        {
            std::string Key;   ///< 自身键（淘汰时反查索引）
            IpList Ips;        ///< 解析结果
            std::chrono::steady_clock::time_point Expire;   ///< 过期时刻
            std::chrono::steady_clock::time_point Inserted; ///< 写入时刻（记录用）
            bool Failed{false};                             ///< 负缓存标记
            bool Dead{false};                               ///< 失效标记（已淘汰/被覆盖）
            std::uint64_t Gen{0};                           ///< 世代号（区分队列中的新旧项）
        };

        /**
         * @brief 构造缓存
         * @param opts 容量与 TTL 配置；MaxEntries==0 视为无限（仅追加、不淘汰）
         */
        explicit Cache(CacheOptions opts)
            : Options_(opts), Unlimited_(opts.MaxEntries == 0)
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
        [[nodiscard]] auto Get(const std::string &domain, const std::uint16_t qtype)
            -> std::optional<IpList>
        {
            const auto Key = KeyView(domain, qtype);
            const auto It = Index_.find(Key);
            if (It == Index_.end())
            {
                return std::nullopt;
            }
            Entry &entry = Slots_[It->second];
            if (std::chrono::steady_clock::now() >= entry.Expire)
            {
                if (Options_.Policy == StalePolicy::Discard)
                {
                    Drop(It);
                    return std::nullopt;
                }
                Promote(It->second, entry);
                return entry.Failed ? IpList{} : entry.Ips;
            }
            Promote(It->second, entry);
            return entry.Failed ? IpList{} : entry.Ips;
        }

        /**
         * @brief 写入缓存（自动按 TtlMin/TtlMax 钳制 TTL）
         * @param in 写入参数；Failed=true 时写入负缓存语义
         */
        void Put(const PutInput &in)
        {
            auto Ttl = in.Ttl;
            if (Options_.TtlMax > std::chrono::seconds{0})
            {
                Ttl = std::min(Ttl, Options_.TtlMax);
            }
            Ttl = std::max(Ttl, Options_.TtlMin);
            Store(in, Ttl);
        }

        /**
         * @brief 写入负缓存（固定 NegativeTtl）
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         */
        void PutNegative(const std::string &domain, const std::uint16_t qtype)
        {
            PutInput in;
            in.Domain = domain;
            in.QType = qtype;
            in.Ttl = Options_.NegativeTtl;
            in.Failed = true;
            Store(in, Options_.NegativeTtl);
        }

        /**
         * @brief 主动驱逐全部已过期条目（供维护循环周期调用）
         * @return 驱逐数量；serve-stale 模式下同样清理（由 LRU 自然淘汰兜底）
         */
        auto EvictExpired() -> std::size_t
        {
            const auto Now = std::chrono::steady_clock::now();
            std::size_t evicted = 0;
            for (auto It = Index_.begin(); It != Index_.end();)
            {
                const Entry &entry = Slots_[It->second];
                if (Now >= entry.Expire)
                {
                    It = Drop(It);
                    ++evicted;
                }
                else
                {
                    ++It;
                }
            }
            return evicted;
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
            Order_.clear();
            Free_.clear();
            Slots_.clear();
            LiveCount_ = 0;
            GenCounter_ = 0;
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
        [[nodiscard]] static auto MakeKey(const std::string &domain, const std::uint16_t qtype)
            -> std::string
        {
            return domain + ':' + std::to_string(qtype);
        }

    private:
        /// LRU 队列项：槽位 + 写入世代号
        struct SlotGen
        {
            std::size_t Slot;
            std::uint64_t Gen;
        };

        /// 在栈缓冲中拼出查找键（domain ≤253 字节 + ':' + ≤5 位 qtype）
        [[nodiscard]] auto KeyView(const std::string &domain, const std::uint16_t qtype)
            -> std::string_view
        {
            if (domain.size() + 6 <= KeyBuf_.size())
            {
                auto *p = KeyBuf_.data();
                std::memcpy(p, domain.data(), domain.size());
                p += domain.size();
                *p++ = ':';
                const auto End = std::to_chars(p, KeyBuf_.data() + KeyBuf_.size(), qtype);
                return {KeyBuf_.data(), static_cast<std::size_t>(End.ptr - KeyBuf_.data())};
            }
            HeapKey_ = MakeKey(domain, qtype); // 超长域名退化为堆键（罕见）
            return HeapKey_;
        }

        /// LRU 提升：写入新世代号并入队尾，旧队列项由淘汰路径惰性跳过
        void Promote(std::size_t slot, Entry &entry)
        {
            entry.Gen = ++GenCounter_;
            Order_.push_back({slot, entry.Gen});
            // 读多写少的长期运行下，失效队列项只被淘汰路径顺带回收；
            // 积压超过存活条目的有界倍数时主动压实，防止队列无界增长
            if (Order_.size() > LiveCount_ * 2 + 64)
            {
                CompactOrder();
            }
        }

        /// 压实 LRU 队列：按世代号升序重建（队头仍为最久未用），剔除全部旧项
        void CompactOrder()
        {
            std::vector<SlotGen> live;
            live.reserve(LiveCount_);
            // Index_ 恰为存活集合（淘汰/覆盖/过期丢弃时同步移除）
            for (const auto &[key, slot] : Index_)
            {
                live.push_back({slot, Slots_[slot].Gen});
            }
            std::sort(live.begin(), live.end(),
                      [](const SlotGen &a, const SlotGen &b) { return a.Gen < b.Gen; });
            Order_.assign(live.begin(), live.end());
        }

        /// 淘汰最旧有效条目（弹队头，惰性跳过失效/已被提升项），摊还 O(1)
        void EvictOldest()
        {
            while (!Order_.empty())
            {
                const auto [slot, gen] = Order_.front();
                Order_.pop_front();
                Entry &entry = Slots_[slot];
                if (entry.Dead || entry.Gen != gen)
                {
                    continue; // 已失效或已被提升（世代号不符），跳过
                }
                Index_.erase(entry.Key);
                entry.Dead = true;
                --LiveCount_;
                Free_.push_back(slot);
                break;
            }
        }

        /// 惰性删除条目（查询路径过期丢弃时调用），返回下一迭代器
        auto Drop(std::unordered_map<std::string, std::size_t, TransparentStringHash,
                                     TransparentStringEqual>::iterator it)
            -> std::unordered_map<std::string, std::size_t, TransparentStringHash,
                                  TransparentStringEqual>::iterator
        {
            const auto Slot = it->second;
            auto next = std::next(it);
            Index_.erase(it);
            Slots_[Slot].Dead = true;
            --LiveCount_;
            Free_.push_back(Slot);
            return next;
        }

        /// 统一写入入口（插入 / 覆盖刷新 / 淘汰，均摊 O(1)）
        void Store(const PutInput &in, const std::chrono::seconds ttl)
        {
            const auto Key = MakeKey(in.Domain, in.QType);
            const auto Now = std::chrono::steady_clock::now();

            // 覆盖已有键：旧槽失效并交还回收站（新项入队尾 = 刷新到最新）
            if (const auto It = Index_.find(Key); It != Index_.end())
            {
                Slots_[It->second].Dead = true;
                --LiveCount_;
                Free_.push_back(It->second);
                Index_.erase(It);
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
            fresh.Ips = in.Ips;
            fresh.Expire = Now + ttl;
            fresh.Inserted = Now;
            fresh.Failed = in.Failed;
            fresh.Dead = false;
            fresh.Gen = ++GenCounter_;
            Slots_[Slot] = std::move(fresh);
            Index_.emplace(Key, Slot);
            ++LiveCount_;
            Order_.push_back({Slot, Slots_[Slot].Gen});
        }

        CacheOptions Options_;
        bool Unlimited_;   ///< MaxEntries==0 → 无限模式
        std::vector<Entry> Slots_; ///< 连续条目存储（局部性友好）
        std::unordered_map<std::string, std::size_t, TransparentStringHash,
                           TransparentStringEqual>
            Index_;                   ///< key → Slots_ 槽位（透明哈希）
        std::deque<SlotGen> Order_;   ///< LRU 槽位队列（含覆盖刷新/提升项）
        std::vector<std::size_t> Free_; ///< 失效槽回收站
        std::size_t LiveCount_{0};    ///< 存活条目数
        std::uint64_t GenCounter_{0}; ///< 世代计数器
        std::array<char, 260> KeyBuf_{}; ///< 查找键栈缓冲（命中路径零分配）
        std::string HeapKey_;             ///< 超长域名退化堆键（罕见路径）
    };

} // namespace Preview::Network::Dns
