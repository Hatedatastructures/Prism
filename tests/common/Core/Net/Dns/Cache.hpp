/**
 * @file Cache.hpp
 * @brief DNS 响应缓存层
 * @details 对齐主项目 net/dns/detail/cache.hpp 分层：
 *          - 键为 "domain:qtype"（域名已规范化小写）
 *          - FIFO 淘汰：超过 MaxEntries 时删除 inserted 时间最早者
 *          - serve-stale：过期条目可按策略返回旧数据（上游不可达时兜底）
 *          - 负缓存：缓存"解析失败/被过滤"结果（空 IP 列表），防重复打上游
 * @note Get 语义与主项目一致：nullopt=未命中、空 vector=负缓存命中、非空=正命中
 */

#pragma once

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @enum StalePolicy
     * @brief 过期条目处理策略
     */
    enum class StalePolicy : std::uint8_t
    {
        Discard, ///< 过期即丢弃（返回未命中并擦除条目）
        Serve,   ///< 过期仍返回旧数据（serve-stale 兜底）
    };

    /**
     * @struct CacheOptions
     * @brief 缓存容量与 TTL 约束
     */
    struct CacheOptions
    {
        std::size_t MaxEntries{10000};              ///< 最大条目数（FIFO 淘汰阈值）
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
        std::string Domain;                          ///< 已规范化域名
        std::uint16_t QType{};                       ///< 查询类型数值
        std::vector<boost::asio::ip::address> Ips;   ///< 解析结果（空 = 负缓存语义）
        std::chrono::seconds Ttl{0};                 ///< 记录 TTL（会被 TtlMin/TtlMax 钳制）
        bool Failed{false};                          ///< 是否为失败结果（负缓存）
    };

    /**
     * @class Cache
     * @brief DNS 响应内存缓存（非线程安全，单 io_context 内使用）
     */
    class Cache
    {
    public:
        /**
         * @struct Entry
         * @brief 缓存条目
         */
        struct Entry
        {
            std::vector<boost::asio::ip::address> Ips; ///< 解析结果
            std::chrono::steady_clock::time_point Expire; ///< 过期时刻
            std::chrono::steady_clock::time_point Inserted; ///< 插入时刻（FIFO 依据）
            bool Failed{false};                        ///< 负缓存标记
        };

        /**
         * @brief 构造缓存
         * @param opts 容量与 TTL 配置
         */
        explicit Cache(CacheOptions opts)
            : Options_(opts)
        {
        }

        /**
         * @brief 查询缓存
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         * @return nullopt=未命中；空 vector=负缓存命中；非空=正命中。
         *         过期时按策略：Serve 返回旧数据，Discard 擦除后返回 nullopt
         */
        [[nodiscard]] auto Get(const std::string &domain, const std::uint16_t qtype)
            -> std::optional<std::vector<boost::asio::ip::address>>
        {
            const auto It = Entries_.find(MakeKey(domain, qtype));
            if (It == Entries_.end())
            {
                return std::nullopt;
            }
            if (std::chrono::steady_clock::now() >= It->second.Expire)
            {
                if (Options_.Policy == StalePolicy::Discard)
                {
                    Entries_.erase(It);
                    return std::nullopt;
                }
                return It->second.Failed ? std::vector<boost::asio::ip::address>{} : It->second.Ips;
            }
            return It->second.Failed ? std::vector<boost::asio::ip::address>{} : It->second.Ips;
        }

        /**
         * @brief 写入正缓存（自动按 TtlMin/TtlMax 钳制 TTL）
         * @param in 写入参数（Ips 非空）
         */
        void Put(const PutInput &in)
        {
            auto Ttl = in.Ttl;
            if (Options_.TtlMax > std::chrono::seconds{0})
            {
                Ttl = std::min(Ttl, Options_.TtlMax);
            }
            Ttl = std::max(Ttl, Options_.TtlMin);
            Store(in.Domain, in.QType, in.Ips, Ttl, false);
        }

        /**
         * @brief 写入负缓存（固定 NegativeTtl）
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         */
        void PutNegative(const std::string &domain, const std::uint16_t qtype)
        {
            Store(domain, qtype, {}, Options_.NegativeTtl, true);
        }

        /**
         * @brief 当前条目数
         * @return 缓存中的条目总数（含负缓存）
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Entries_.size();
        }

        /**
         * @brief 清空全部缓存
         */
        void Clear()
        {
            Entries_.clear();
        }

        /**
         * @brief 构造缓存键
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
        /// 统一写入入口 + FIFO 淘汰
        void Store(const std::string &domain, const std::uint16_t qtype,
                   const std::vector<boost::asio::ip::address> &ips,
                   const std::chrono::seconds ttl, const bool failed)
        {
            const auto Now = std::chrono::steady_clock::now();
            auto &entry = Entries_[MakeKey(domain, qtype)];
            entry.Ips = ips;
            entry.Expire = Now + ttl;
            entry.Inserted = Now;
            entry.Failed = failed;

            while (Entries_.size() > Options_.MaxEntries)
            {
                auto oldest = Entries_.begin();
                for (auto it = std::next(oldest); it != Entries_.end(); ++it)
                {
                    if (it->second.Inserted < oldest->second.Inserted)
                    {
                        oldest = it;
                    }
                }
                Entries_.erase(oldest);
            }
        }

        CacheOptions Options_;
        std::unordered_map<std::string, Entry> Entries_;
    };

} // namespace Preview::Network::Dns
