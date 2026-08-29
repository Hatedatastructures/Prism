/**
 * @file Resolver.hpp
 * @brief DNS 解析器门面（完整查询管道）
 * @details 对齐主项目 net/dns/resolver 分层，管道顺序与主项目
 *          query_pipeline 一致：
 *          规范化 → IP 字面量快速路径 → 规则检查（Block/Negative/Rewrite/
 *          CNAME 改写）→ 缓存查询（正/负）→ single-flight 合并（等待者挂起
 *          定时器，醒来后重查缓存）→ 上游查询（Servers 为空回退 OS resolver）
 *          → 结果过滤（黑名单 + 地址族匹配）→ 写缓存（TTL 钳制）
 *
 *          兼容旧 API：构造 (ex, CacheSize, Ttl, NegativeTtl)、
 *          AsyncResolve(host, ec)、HitCount/Size/Clear。
 * @note 负缓存命中与正命中同样递增 HitCount；IP 字面量同样入缓存
 */

#pragma once

#include "Cache.hpp"
#include "Coalescer.hpp"
#include "Config.hpp"
#include "Format.hpp"
#include "Rules.hpp"
#include "Upstream.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Network::Dns
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;

    /**
     * @class Resolver
     * @brief DNS 解析器门面（缓存 + 合并 + 规则 + 上游编排）
     */
    class Resolver
    {
    public:
        /**
         * @brief 构造（默认配置）
         * @param ex 执行器
         */
        explicit Resolver(net::any_io_executor ex)
            : Resolver(std::move(ex), Config{})
        {
        }

        /**
         * @brief 构造（兼容旧签名：容量 + TTL）
         * @param ex 执行器
         * @param CacheSize 缓存容量（0 = 禁用缓存）
         * @param ttl 正缓存 TTL
         * @param NegativeTtl 负缓存 TTL
         */
        explicit Resolver(net::any_io_executor ex, const std::size_t CacheSize,
                          std::chrono::seconds ttl = std::chrono::seconds(60),
                          std::chrono::seconds NegativeTtl = std::chrono::seconds(5))
            : Resolver(std::move(ex), MakeCompatConfig(CacheSize, ttl, NegativeTtl))
        {
        }

        /**
         * @brief 构造（完整配置）
         * @param ex 执行器
         * @param cfg 配置（上游列表 / 策略 / 规则 / 缓存参数）
         */
        explicit Resolver(net::any_io_executor ex, const Config &cfg)
            : Ex_(std::move(ex)), Config_(cfg),
              Rules_(cfg.AddressRules, cfg.CnameRules, {}, cfg.AddressBlacklist,
                     cfg.BlacklistV4, cfg.BlacklistV6),
              Cache_(MakeCacheOptions(cfg)),
              Coalescer_(Ex_),
              Upstream_(std::make_shared<Upstream>(Ex_, cfg.Servers, cfg.QueryMode,
                        std::chrono::milliseconds(cfg.TimeoutMs), cfg.MaxConnsPerServer)),
              MaintenanceTimer_(Ex_), Alive_(std::make_shared<std::atomic<bool>>(true))
        {
            net::co_spawn(Ex_, MaintenanceLoop(), net::detached);
        }

        /// 停止维护循环（缓存驱逐 / flight 清理 / 池清扫）
        ~Resolver()
        {
            if (Alive_)
            {
                Alive_->store(false);
            }
            MaintenanceTimer_.cancel();
        }

        Resolver(const Resolver &) = delete;
        auto operator=(const Resolver &) -> Resolver & = delete;

        /**
         * @brief 异步解析域名（完整管道）
         * @param host 域名或 IP 字面量
         * @param ec 错误码输出（成功清零；屏蔽/解析失败置 BadAddress）
         * @return 地址列表；失败或负结果为空
         */
        [[nodiscard]] auto AsyncResolve(std::string_view host, std::error_code &ec)
            -> net::awaitable<std::vector<net::ip::address>>
        {
            // 清理上一轮标记待删的 flight（生产 query_pipeline 同款）：
            // 防止顺序解析加入已完成的陈旧 flight（其唤醒 cancel 已被
            // 消费，等待将永久挂起），同时保证 flight 表不增长
            Coalescer_.FlushCleanup();

            auto name = Message::NormalizeName(host);

            // ── 1. IP 字面量快速路径（仍入缓存，保持旧版行为）──
            boost::system::error_code litEc;
            auto literal = net::ip::make_address(name, litEc);
            if (!litEc)
            {
                if (Rules_.IsBlacklisted(literal))
                {
                    ec = make_error_code(Error::BadAddress);
                    co_return std::vector<net::ip::address>{};
                }
                ec.clear();
                StorePositive(name, QTypeNum(QType::A), {literal}, DefaultTtl());
                co_return std::vector<net::ip::address>{literal};
            }

            // ── 2. 规则检查（CNAME 改写只跳转一跳防循环）──
            if (const auto rule = Rules_.Match(name))
            {
                switch (rule->Action)
                {
                case RuleAction::Block:
                    ec = make_error_code(Error::BadAddress);
                    co_return std::vector<net::ip::address>{};
                case RuleAction::Negative:
                    ec.clear();
                    co_return std::vector<net::ip::address>{};
                case RuleAction::Rewrite:
                    // 规则地址装载期已预解析，直接返回
                    StorePositive(name, QTypeNum(QType::A), rule->Addresses, DefaultTtl());
                    ec.clear();
                    co_return rule->Addresses;
                case RuleAction::Pass:
                    break;
                }
                if (rule->CnameTarget && *rule->CnameTarget != name)
                {
                    name = Message::NormalizeName(*rule->CnameTarget);
                }
            }

            // ── 3. 缓存查询 ──
            if (Config_.CacheEnabled)
            {
                auto cached = Cache_.Get(name, QTypeNum(QType::A));
                if (cached.has_value())
                {
                    ++Hits_;
                    if (cached->empty())
                    {
                        ec = make_error_code(Error::BadAddress);
                        co_return std::vector<net::ip::address>{};
                    }
                    ec.clear();
                    co_return std::vector<net::ip::address>(cached->begin(), cached->end());
                }
            }

            // ── 4. single-flight 合并 ──
            auto [flight, isNew] = Coalescer_.FindCreate(name, QTypeNum(QType::A));
            QueryResult result;
            if (!isNew)
            {
                flight->AddWaiter(+1);
                if (!flight->Ready())
                {
                    // leader 仍在途才挂起等待；已完成（陈旧 flight）的
                    // 唤醒 cancel 已被消费，再等定时器将永久阻塞
                    boost::system::error_code waitEc;
                    co_await flight->Timer().async_wait(
                        net::redirect_error(net::use_awaitable, waitEc));
                }
                flight->AddWaiter(-1);
                Coalescer_.CleanupFlight(flight);

                // leader 可能已写入缓存，优先重查
                if (Config_.CacheEnabled)
                {
                    auto cached = Cache_.Get(name, QTypeNum(QType::A));
                    if (cached.has_value())
                    {
                        ++Hits_;
                        if (cached->empty())
                        {
                            ec = make_error_code(Error::BadAddress);
                            co_return std::vector<net::ip::address>{};
                        }
                        ec.clear();
                        co_return std::vector<net::ip::address>(cached->begin(), cached->end());
                    }
                }
                if (const auto *shared = Coalescer_.GetResult(*flight))
                {
                    result = *shared;
                }
                else
                {
                    ec = make_error_code(Error::BadAddress);
                    co_return std::vector<net::ip::address>{};
                }
            }
            else
            {
                // ── 5. leader：上游查询或 OS 回退（异常兜底折算为失败结果，
                //         保证等待者一定被唤醒而非永久挂起）──
                try
                {
                    result = co_await QueryBothFamilies(name);
                }
                catch (...)
                {
                    QueryResult failed;
                    failed.Error = make_error_code(Error::IoError);
                    result = std::move(failed);
                }
                Coalescer_.SetResult(flight, result);
                Coalescer_.CleanupFlight(flight);
            }

            // ── 6. 过滤 + 写缓存 ──
            auto ips = FilterIps(result.Ips);
            if (!result.Error && !ips.empty())
            {
                StorePositive(name, QTypeNum(QType::A), ips, ResultTtl(result));
                ec.clear();
                co_return ips;
            }

            // 上游失败或全部被过滤 → 负缓存（超时可配置豁免）
            StoreNegative(name, result.Error);
            ec = make_error_code(Error::BadAddress);
            co_return std::vector<net::ip::address>{};
        }

        /**
         * @brief IP 黑名单检查
         * @param addr 待检查地址字符串
         * @return 命中返回 true
         */
        [[nodiscard]] auto IsBlacklisted(std::string_view addr) const -> bool
        {
            return Rules_.IsBlacklisted(addr);
        }

        /**
         * @brief 规范化域名（小写、去末尾点号）
         * @param domain 原始域名
         * @return 规范化结果
         */
        [[nodiscard]] static auto Normalize(std::string_view domain) -> std::string
        {
            return Message::NormalizeName(domain);
        }

        /**
         * @brief 缓存命中数（含负缓存命中）
         * @return 命中次数
         */
        [[nodiscard]] auto HitCount() const noexcept -> std::uint64_t
        {
            return Hits_;
        }

        /**
         * @brief 当前缓存条目数
         * @return 条目数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Cache_.Size();
        }

        /**
         * @brief 清空缓存
         */
        void Clear()
        {
            Cache_.Clear();
        }

    private:
        /// 由旧式三参数构造映射出配置
        [[nodiscard]] static auto MakeCompatConfig(const std::size_t CacheSize,
                                                   const std::chrono::seconds ttl,
                                                   const std::chrono::seconds NegativeTtl)
            -> Config
        {
            Config cfg;
            cfg.CacheEnabled = CacheSize > 0;
            cfg.MaxCacheEntries = CacheSize == 0 ? 1 : CacheSize;
            cfg.CacheTtl = ttl;
            cfg.NegativeTtl = NegativeTtl;
            // 显式传入的小 TTL 不被默认下限抬高（兼容旧版 1s 过期测试语义）
            cfg.TtlMin = std::min<std::uint32_t>(cfg.TtlMin,
                                                 static_cast<std::uint32_t>(ttl.count()));
            return cfg;
        }

        /// 由配置生成缓存选项
        [[nodiscard]] static auto MakeCacheOptions(const Config &cfg) -> CacheOptions
        {
            CacheOptions opts;
            opts.MaxEntries = cfg.MaxCacheEntries;
            opts.TtlMin = std::chrono::seconds(cfg.TtlMin);
            opts.TtlMax = std::chrono::seconds(cfg.TtlMax);
            opts.NegativeTtl = std::chrono::seconds(cfg.NegativeTtl);
            opts.Policy = cfg.CachePolicy;
            return opts;
        }

        /// A 记录类型数值
        [[nodiscard]] static constexpr auto QTypeNum(const QType qt) -> std::uint16_t
        {
            return static_cast<std::uint16_t>(qt);
        }

        /// 默认正缓存 TTL（响应无 TTL 时兜底）
        [[nodiscard]] auto DefaultTtl() const -> std::chrono::seconds
        {
            return std::chrono::seconds(Config_.CacheTtl);
        }

        /// 从查询结果计算缓存 TTL（报文无 TTL 时回退配置默认值）
        [[nodiscard]] auto ResultTtl(const QueryResult &result) const -> std::chrono::seconds
        {
            const auto MinTtl = result.Response.MinTtl;
            return MinTtl > 0 ? std::chrono::seconds(MinTtl) : DefaultTtl();
        }

        /// 写入正缓存
        void StorePositive(const std::string &name, const std::uint16_t qtype,
                           const std::vector<net::ip::address> &ips,
                           const std::chrono::seconds ttl)
        {
            if (!Config_.CacheEnabled)
            {
                return;
            }
            PutInput in;
            in.Domain = name;
            in.QType = qtype;
            in.Ips.assign(ips.begin(), ips.end());
            in.Ttl = ttl;
            in.Failed = false;
            Cache_.Put(in);
        }

        /// 写入负缓存（NegativeOnTimeout=false 时超时不入负缓存，可立即重试）
        void StoreNegative(const std::string &name, const boost::system::error_code &error)
        {
            if (!Config_.CacheEnabled)
            {
                return;
            }
            if (!Config_.NegativeOnTimeout && error == make_error_code(Error::Timeout))
            {
                return;
            }
            Cache_.PutNegative(name, QTypeNum(QType::A));
        }

        /**
         * @brief 查询 A 与 AAAA 并合并（DisableIpv6 时仅 A）
         * @details 两族并发查询（各自独立 single-flight），总延迟取两族
         *          较慢者而非相加；合并结果去重
         * @param name 已规范化域名
         * @return 合并后的查询结果（IP 列表合并去重，错误取首个非成功者）
         */
        [[nodiscard]] auto QueryBothFamilies(const std::string &name)
            -> net::awaitable<QueryResult>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            if (Config_.DisableIpv6)
            {
                co_return co_await QueryOne(name, QType::A);
            }
            auto [primary, secondary] =
                co_await (QueryOne(name, QType::A) && QueryOne(name, QType::Aaaa));

            QueryResult merged;
            merged.Ips = std::move(primary.Ips);
            merged.Ips.reserve(merged.Ips.size() + secondary.Ips.size());
            for (auto &ip : secondary.Ips)
            {
                merged.Ips.push_back(std::move(ip));
            }
            // 去重（上游异常应答可能双族重复返回同址）
            std::sort(merged.Ips.begin(), merged.Ips.end());
            merged.Ips.erase(std::unique(merged.Ips.begin(), merged.Ips.end()),
                             merged.Ips.end());
            merged.Response = primary.Response;
            merged.ServerAddr =
                !primary.ServerAddr.empty() ? primary.ServerAddr : secondary.ServerAddr;
            merged.RttMs = std::max(primary.RttMs, secondary.RttMs);
            // 两族都失败才算失败；任一成功即可用。双空（NXDOMAIN）保持 success+空，
            // 由上层负缓存，避免被误判为错误而在 Fallback 模式重试全部上游
            if (primary.Error && secondary.Error)
            {
                merged.Error = primary.Error;
            }
            co_return merged;
        }

        /**
         * @brief 单类型查询：有上游走 Upstream，否则回退 OS resolver
         * @param name 已规范化域名
         * @param qt 查询类型
         * @return 查询结果
         */
        [[nodiscard]] auto QueryOne(const std::string &name, const QType qt)
            -> net::awaitable<QueryResult>
        {
            if (!Config_.Servers.empty())
            {
                co_return co_await Upstream_->Resolve(name, qt);
            }
            co_return co_await OsResolve(name, qt);
        }

        /**
         * @brief OS resolver 回退（Servers 为空时保持旧行为可解析 localhost）
         * @details tcp::resolver 异步解析并包装为 QueryResult 形状，
         *          受 Config.TimeoutMs 超时约束
         */
        [[nodiscard]] auto OsResolve(const std::string &name, const QType qt)
            -> net::awaitable<QueryResult>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            const auto Start = std::chrono::steady_clock::now();
            auto DoResolve = [this, &name, qt]() -> net::awaitable<QueryResult>
            {
                Tcp::resolver resolver(Ex_);
                boost::system::error_code rec;
                // AAAA 仅保留 v6 结果，A 仅保留 v4
                auto results = co_await resolver.async_resolve(
                    name, "0", net::redirect_error(net::use_awaitable, rec));
                QueryResult out;
                if (rec)
                {
                    out.Error = make_error_code(Error::BadAddress);
                    co_return out;
                }
                for (const auto &res : results)
                {
                    const auto &addr = res.endpoint().address();
                    const bool wantV4 = qt == QType::A;
                    if (addr.is_v4() == wantV4)
                    {
                        out.Ips.push_back(addr);
                    }
                }
                if (out.Ips.empty())
                {
                    out.Error = make_error_code(Error::BadAddress);
                }
                co_return out;
            };

            net::steady_timer timer(Ex_);
            timer.expires_after(std::chrono::milliseconds(Config_.TimeoutMs));
            auto outcome = co_await (DoResolve() || timer.async_wait(net::use_awaitable));
            if (outcome.index() == 1)
            {
                QueryResult timedOut;
                timedOut.Error = make_error_code(Error::Timeout);
                co_return timedOut;
            }
            auto result = std::move(std::get<0>(outcome));
            result.RttMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - Start)
                    .count());
            co_return result;
        }

        /**
         * @brief 过滤结果地址（黑名单剔除，纯地址比较）
         * @param ips 原始地址列表
         * @return 过滤后列表
         */
        [[nodiscard]] auto FilterIps(const std::vector<net::ip::address> &ips) const
            -> std::vector<net::ip::address>
        {
            std::vector<net::ip::address> out;
            out.reserve(ips.size());
            for (const auto &ip : ips)
            {
                if (!Rules_.IsBlacklisted(ip))
                {
                    out.push_back(ip);
                }
            }
            return out;
        }

        /**
         * @brief 维护循环（30s 周期）：缓存过期驱逐 + flight 清理 + 池清扫
         * @details 取代逐查询入口的 FlushCleanup：热路径零额外开销，
         *          内存水位全部有界（LRU 上限 / 池上限 / flight 两阶段清理）
         */
        auto MaintenanceLoop() -> net::awaitable<void>
        {
            while (Alive_->load())
            {
                MaintenanceTimer_.expires_after(std::chrono::seconds(30));
                boost::system::error_code ec;
                co_await MaintenanceTimer_.async_wait(
                    net::redirect_error(net::use_awaitable, ec));
                if (ec == net::error::operation_aborted || !Alive_->load())
                {
                    co_return;
                }
                Cache_.EvictExpired();
                Coalescer_.FlushCleanup();
                Upstream_->ClearIdleConns();
            }
        }

        net::any_io_executor Ex_;
        Config Config_;
        RulesEngine Rules_;                          ///< 规则引擎（地址/CNAME/黑名单）
        Cache Cache_;                                ///< 响应缓存
        Coalescer<QueryResult> Coalescer_;           ///< single-flight 合并器
        std::shared_ptr<Upstream> Upstream_;         ///< 上游查询客户端（共享所有权，保障 detached 任务生命周期）
        net::steady_timer MaintenanceTimer_;         ///< 维护循环定时器（30s 周期）
        std::shared_ptr<std::atomic<bool>> Alive_;   ///< 维护循环存活标记
        std::uint64_t Hits_{0};                      ///< 缓存命中计数
    };

} // namespace Preview::Network::Dns
