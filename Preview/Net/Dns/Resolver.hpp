/**
 * @file Resolver.hpp
 * @brief DNS 解析器门面（完整查询管道）
 * @details 对齐主项目 net/dns/resolver 分层，管道顺序与主项目
 *          query_pipeline 一致：
 *          规范化 → IP 字面量快速路径 → 规则检查（Block/Negative/Rewrite/
 *          CNAME 改写）→ 缓存查询（正/负）→ single-flight 合并（等待者挂起
 *          定时器，醒来后重查缓存）→ 上游查询（Servers 为空回退 OS resolver）
 *          → 结果过滤（黑名单 + 地址族匹配）→ 写缓存（TTL 钳制）。
 *          查询资源由共享状态管理，后台维护协程不依赖 Resolver 裸指针。
 * @note 负缓存命中与正命中同样递增 HitCount；IP 字面量同样入缓存
 */

#pragma once

#include "Cache.hpp"
#include "Coalescer.hpp"
#include "Config.hpp"
#include "Detail/ConfigOptions.hpp"
#include "Detail/Maintenance.hpp"
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
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    /**
     * @class Resolver
     * @brief DNS 解析器门面（缓存 + 合并 + 规则 + 上游编排）
     */
    class Resolver
    {
    private:
        /**
         * @struct State
         * @brief Resolver 后台任务共享状态
         * @details 维护定时器和其使用的资源由状态对象共同持有，
         *          使 detached 维护协程不依赖 Resolver 对象存活。
         */
        struct State
        {
            State(Net::any_io_executor Executor, CacheOptions CacheOptionsValue,
                  std::shared_ptr<Upstream> UpstreamObject)
                : Cache_(std::move(CacheOptionsValue)), Coalescer_(Executor),
                  Upstream_(std::move(UpstreamObject)), MaintenanceTimer_(Executor),
                  Alive_(std::make_shared<std::atomic<bool>>(true))
            {
            }

            Cache Cache_;
            Coalescer<QueryResult> Coalescer_;
            std::shared_ptr<Upstream> Upstream_;
            Net::steady_timer MaintenanceTimer_;
            std::shared_ptr<std::atomic<bool>> Alive_;
        };

        using FlightPtr = Coalescer<QueryResult>::FlightPtr;

    public:
        /**
         * @brief 构造（默认配置）
         * @param ex 执行器
         */
        explicit Resolver(Net::any_io_executor Executor)
            : Resolver(std::move(Executor), Config{})
        {
        }

        /**
         * @brief 构造（完整配置）
         * @param ex 执行器
         * @param cfg 配置（上游列表 / 策略 / 规则 / 缓存参数）
         */
        explicit Resolver(Net::any_io_executor Executor, const Config &ConfigValue)
            : Ex_(std::move(Executor)), Config_(ConfigValue), Rules_(Detail::MakeRulesOptions(ConfigValue)),
              State_(std::make_shared<State>(
                  Ex_, Detail::MakeCacheOptions(ConfigValue),
                  std::make_shared<Upstream>(Ex_, Detail::MakeUpstreamOptions(ConfigValue))))
        {
            Net::co_spawn(Ex_, Detail::MaintenanceLoop(State_), Net::detached);
        }

        /// 停止维护循环（缓存驱逐 / flight 清理 / 池清扫）
        ~Resolver()
        {
            if (State_ && State_->Alive_)
            {
                State_->Alive_->store(false, std::memory_order_release);
                State_->MaintenanceTimer_.cancel();
            }
        }

        Resolver(const Resolver &) = delete;
        auto operator=(const Resolver &) -> Resolver & = delete;

        /**
         * @brief 异步解析域名（完整管道）
         * @param host 域名或 IP 字面量
         * @param ec 错误码输出（成功清零；屏蔽/解析失败置 BadAddress）
         * @return 地址列表；失败或负结果为空
         */
        [[nodiscard]] auto AsyncResolve(std::string_view Host, std::error_code &ErrorCode)
            -> Net::awaitable<std::vector<Net::ip::address>>
        {
            State_->Coalescer_.FlushCleanup();

            auto Name = Message::NormalizeName(Host);

            // IP 字面量快速路径。
            boost::system::error_code litEc;
            auto Literal = Net::ip::make_address(Name, litEc);
            if (!litEc)
            {
                if ((Config_.DisableIpv6 && Literal.is_v6()) || Rules_.IsBlacklisted(Literal))
                {
                    ErrorCode = make_error_code(Error::BadAddress);
                    co_return std::vector<Net::ip::address>{};
                }
                ErrorCode.clear();
                StorePositive(Name, std::vector<Net::ip::address>{Literal}, DefaultTtl());
                co_return std::vector<Net::ip::address>{Literal};
            }

            // 规则检查，CNAME 改写只跳转一跳以防循环。
            if (const auto Rule = Rules_.Match(Name))
            {
                switch (Rule->Action)
                {
                case RuleAction::Block:
                    ErrorCode = make_error_code(Error::BadAddress);
                    co_return std::vector<Net::ip::address>{};
                case RuleAction::Negative:
                    ErrorCode.clear();
                    co_return std::vector<Net::ip::address>{};
                case RuleAction::Rewrite:
                {
                    auto Addresses = FilterIps(Rule->Addresses);
                    if (Addresses.empty())
                    {
                        ErrorCode = make_error_code(Error::BadAddress);
                        co_return std::vector<Net::ip::address>{};
                    }
                    StorePositive(Name, Addresses, DefaultTtl());
                    ErrorCode.clear();
                    co_return Addresses;
                }
                case RuleAction::Pass:
                    break;
                }
                if (Rule->CnameTarget && *Rule->CnameTarget != Name)
                {
                    Name = Message::NormalizeName(*Rule->CnameTarget);
                }
            }

            if (auto Cached = ReadCache(Name, ErrorCode))
            {
                co_return std::move(*Cached);
            }

            auto [Flight, IsNew] = State_->Coalescer_.FindCreate(Name, QTypeNum(QType::A));
            QueryResult Result;
            if (!IsNew)
            {
                co_await WaitForFlight(Flight);

                if (auto Cached = ReadCache(Name, ErrorCode))
                {
                    co_return std::move(*Cached);
                }
                if (const auto *Shared = State_->Coalescer_.GetResult(*Flight))
                {
                    Result = *Shared;
                }
                else
                {
                    ErrorCode = make_error_code(Error::BadAddress);
                    co_return std::vector<Net::ip::address>{};
                }
            }
            else
            {
                Result = co_await RunLeader(Flight, Name);
            }

            co_return FinalizeResult(Name, Result, ErrorCode);
        }

        /**
         * @brief IP 黑名单检查
         * @param addr 待检查地址字符串
         * @return 命中返回 true
         */
        [[nodiscard]] auto IsBlacklisted(std::string_view Address) const -> bool
        {
            return Rules_.IsBlacklisted(Address);
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
            return State_->Cache_.Size();
        }

        /**
         * @brief 清空缓存
         */
        void Clear()
        {
            State_->Cache_.Clear();
        }

    private:
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
        [[nodiscard]] auto ResultTtl(const QueryResult &Result) const -> std::chrono::seconds
        {
            const auto MinTtl = Result.Response.MinTtl;
            if (MinTtl > 0)
            {
                return std::chrono::seconds(MinTtl);
            }
            return DefaultTtl();
        }

        /**
         * @brief 查询缓存并转换为 Resolver 返回值
         * @param name 已规范化域名
         * @param ec 错误码输出
         * @return 命中返回地址列表；未命中返回空值
         */
        [[nodiscard]] auto ReadCache(const std::string &Name, std::error_code &ErrorCode)
            -> std::optional<std::vector<Net::ip::address>>
        {
            if (!Config_.CacheEnabled)
            {
                return std::nullopt;
            }
            auto Cached = State_->Cache_.Get(Name, QTypeNum(QType::A));
            if (!Cached)
            {
                return std::nullopt;
            }
            ++Hits_;
            if (Cached->empty())
            {
                ErrorCode = make_error_code(Error::BadAddress);
            }
            else
            {
                ErrorCode.clear();
            }
            return std::vector<Net::ip::address>(Cached->begin(), Cached->end());
        }

        /// 写入正缓存
        void StorePositive(const std::string &Name, const std::vector<Net::ip::address> &Addresses,
                           const std::chrono::seconds ttl)
        {
            if (!Config_.CacheEnabled)
            {
                return;
            }
            PutInput Input;
            Input.Domain = Name;
            Input.QType = QTypeNum(QType::A);
            Input.Ips.assign(Addresses.begin(), Addresses.end());
            Input.Ttl = ttl;
            Input.Failed = false;
            State_->Cache_.Put(Input);
        }

        /// 写入负缓存（NegativeOnTimeout=false 时超时不入负缓存，可立即重试）
        void StoreNegative(const std::string &Name, const boost::system::error_code &ErrorCode)
        {
            if (!Config_.CacheEnabled)
            {
                return;
            }
            if (!Config_.NegativeOnTimeout && ErrorCode == make_error_code(Error::Timeout))
            {
                return;
            }
            State_->Cache_.PutNegative(Name, QTypeNum(QType::A));
        }

        /**
         * @brief 等待 single-flight leader 完成
         * @param flight 共享查询记录
         */
        auto WaitForFlight(FlightPtr flight) -> Net::awaitable<void>
        {
            flight->AcquireWaiter();
            if (!flight->Ready())
            {
                boost::system::error_code waitEc;
                co_await flight->Timer().async_wait(
                    Net::redirect_error(Net::use_awaitable, waitEc));
            }
            flight->ReleaseWaiter();
            State_->Coalescer_.CleanupFlight(flight);
        }

        /**
         * @brief 执行 single-flight leader 查询并发布结果
         * @param flight 共享查询记录
         * @param name 已规范化域名
         * @return 上游或操作系统解析结果
         */
        auto RunLeader(FlightPtr Flight, const std::string &Name)
            -> Net::awaitable<QueryResult>
        {
            QueryResult Result;
            try
            {
                Result = co_await QueryBothFamilies(Name);
            }
            catch (...)
            {
                Result.Error = make_error_code(Error::IoError);
            }
            State_->Coalescer_.SetResult(Flight, Result);
            State_->Coalescer_.CleanupFlight(Flight);
            co_return Result;
        }

        /**
         * @brief 过滤、缓存并转换最终解析结果
         * @param name 已规范化域名
         * @param result 上游查询结果
         * @param ec 错误码输出
         * @return 最终允许返回的地址列表
         */
        [[nodiscard]] auto FinalizeResult(const std::string &Name, const QueryResult &Result,
                                          std::error_code &ErrorCode)
            -> std::vector<Net::ip::address>
        {
            auto Addresses = FilterIps(Result.Ips);
            if (!Result.Error && !Addresses.empty())
            {
                StorePositive(Name, Addresses, ResultTtl(Result));
                ErrorCode.clear();
                return Addresses;
            }
            StoreNegative(Name, Result.Error);
            if (Result.Error)
            {
                ErrorCode = Result.Error;
            }
            else
            {
                ErrorCode = make_error_code(Error::BadAddress);
            }
            return {};
        }

        /**
         * @brief 查询 A 与 AAAA 并合并（DisableIpv6 时仅 A）
         * @details 两族并发查询（各自独立 single-flight），总延迟取两族
         *          较慢者而非相加；合并结果去重
         * @param name 已规范化域名
         * @return 合并后的查询结果（IP 列表合并去重，错误取首个非成功者）
         */
        [[nodiscard]] auto QueryBothFamilies(const std::string &Name)
            -> Net::awaitable<QueryResult>
        {
            using Net::experimental::awaitable_operators::operator&&;

            if (Config_.DisableIpv6)
            {
                co_return co_await QueryOne(Name, QType::A);
            }
            auto [Primary, Secondary] =
                co_await (QueryOne(Name, QType::A) && QueryOne(Name, QType::Aaaa));

            QueryResult Merged;
            Merged.Ips = std::move(Primary.Ips);
            Merged.Ips.reserve(Merged.Ips.size() + Secondary.Ips.size());
            for (auto &Address : Secondary.Ips)
            {
                Merged.Ips.push_back(std::move(Address));
            }
            // 去重（上游异常应答可能双族重复返回同址）
            std::sort(Merged.Ips.begin(), Merged.Ips.end());
            Merged.Ips.erase(std::unique(Merged.Ips.begin(), Merged.Ips.end()),
                             Merged.Ips.end());
            Merged.Response = Primary.Response;
            if (Secondary.Response.MinTtl > 0 &&
                (Merged.Response.MinTtl == 0 ||
                 Secondary.Response.MinTtl < Merged.Response.MinTtl))
            {
                Merged.Response.MinTtl = Secondary.Response.MinTtl;
            }
            Merged.ServerAddr = Primary.ServerAddr;
            if (Merged.ServerAddr.empty())
            {
                Merged.ServerAddr = Secondary.ServerAddr;
            }
            Merged.RttMs = std::max(Primary.RttMs, Secondary.RttMs);
            // 两族都失败才算失败；任一成功即可用。双空（NXDOMAIN）保持 success+空，
            // 由上层负缓存，避免被误判为错误而在 Fallback 模式重试全部上游
            if (Primary.Error && Secondary.Error)
            {
                Merged.Error = Primary.Error;
            }
            co_return Merged;
        }

        /**
         * @brief 单类型查询：有上游走 Upstream，否则回退 OS resolver
         * @param name 已规范化域名
         * @param qt 查询类型
         * @return 查询结果
         */
        [[nodiscard]] auto QueryOne(const std::string &Name, const QType QueryType)
            -> Net::awaitable<QueryResult>
        {
            if (!Config_.Servers.empty())
            {
                co_return co_await State_->Upstream_->Resolve(Name, QueryType);
            }
            co_return co_await OsResolve(Name, QueryType);
        }

        /**
         * @brief OS resolver 回退（Servers 为空时保持旧行为可解析 localhost）
         * @details tcp::resolver 异步解析并包装为 QueryResult 形状，
         *          受 Config.TimeoutMs 超时约束
         */
        [[nodiscard]] auto OsResolve(const std::string &Name, const QType QueryType)
            -> Net::awaitable<QueryResult>
        {
            using Net::experimental::awaitable_operators::operator||;

            const auto Start = std::chrono::steady_clock::now();
            const auto Executor = Ex_;
            const auto Timeout = std::chrono::milliseconds(Config_.TimeoutMs);
            if (Timeout.count() == 0)
            {
                QueryResult timedOut;
                timedOut.Error = make_error_code(Error::Timeout);
                co_return timedOut;
            }
            auto ResolveOperation = [Executor, Name, QueryType]()
                -> Net::awaitable<QueryResult>
            {
                Tcp::resolver Resolver(Executor);
                boost::system::error_code ErrorCode;
                // AAAA 仅保留 v6 结果，A 仅保留 v4
                auto Results = co_await Resolver.async_resolve(
                    Name, "0", Net::redirect_error(Net::use_awaitable, ErrorCode));
                QueryResult out;
                if (ErrorCode)
                {
                    out.Error = make_error_code(Error::BadAddress);
                    co_return out;
                }
                for (const auto &Result : Results)
                {
                    const auto &Address = Result.endpoint().address();
                    const bool WantV4 = QueryType == QType::A;
                    if (Address.is_v4() == WantV4)
                    {
                        out.Ips.push_back(Address);
                    }
                }
                if (out.Ips.empty())
                {
                    out.Error = make_error_code(Error::BadAddress);
                }
                co_return out;
            };

            Net::steady_timer Timer(Executor);
            Timer.expires_after(Timeout);
            auto Outcome = co_await (ResolveOperation() || Timer.async_wait(Net::use_awaitable));
            if (Outcome.index() == 1)
            {
                QueryResult timedOut;
                timedOut.Error = make_error_code(Error::Timeout);
                co_return timedOut;
            }
            auto Result = std::move(std::get<0>(Outcome));
            Result.RttMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - Start)
                    .count());
            co_return Result;
        }

        /**
         * @brief 过滤结果地址（黑名单剔除，纯地址比较）
         * @param ips 原始地址列表
         * @return 过滤后列表
         */
        [[nodiscard]] auto FilterIps(const std::vector<Net::ip::address> &Addresses) const
            -> std::vector<Net::ip::address>
        {
            std::vector<Net::ip::address> Result;
            Result.reserve(Addresses.size());
            for (const auto &Address : Addresses)
            {
                if (!Rules_.IsBlacklisted(Address) && !(Config_.DisableIpv6 && Address.is_v6()))
                {
                    Result.push_back(Address);
                }
            }
            return Result;
        }

        Net::any_io_executor Ex_;
        Config Config_;
        RulesEngine Rules_;                          ///< 规则引擎（地址/CNAME/黑名单）
        std::shared_ptr<State> State_;               ///< 查询资源与维护协程共享状态
        std::uint64_t Hits_{0};                      ///< 缓存命中计数
    };

} // namespace Preview::Network::Dns
