/**
 * @file ResolverState.hpp
 * @brief DNS 解析状态与查询管道共享 owner
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

#include <Preview/Net/Dns/Cache.hpp>
#include <Preview/Net/Dns/Coalescer.hpp>
#include <Preview/Net/Dns/Config.hpp>
#include <Preview/Net/Dns/Detail/ConfigOptions.hpp>
#include <Preview/Net/Dns/Detail/FamilyMerge.hpp>
#include <Preview/Net/Dns/Detail/Maintenance.hpp>
#include <Preview/Net/Dns/Detail/ResolverFailure.hpp>
#include <Preview/Net/Dns/Detail/ResolverCacheResults.hpp>
#include <Preview/Net/Dns/Detail/ResolverSharedState.hpp>
#include <Preview/Net/Dns/Format.hpp>
#include <Preview/Net/Dns/Rules.hpp>
#include <Preview/Net/Dns/Upstream.hpp>

#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>

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

namespace Preview::Network::Dns::Detail
{
    /**
     * @class ResolverState
     * @brief 拥有 DNS 查询状态、规则快照和后台维护资源。
     * @details State 由 Resolver 门面和每个在途查询共享；查询协程不借用门面裸指针。
     *          ContextPin_ 仅在 executor 已注册 ContextOwner 时固定该 context；未注册 executor
     *          仍由调用方保持运行至 Shutdown 完成。MaintenanceOwner 持有共享 DNS 状态并等待维护任务退栈。
     */
    class ResolverState final
    {
        using FlightPtr = Coalescer<QueryResult>::FlightPtr;

    public:
        /**
         * @brief 构造（默认配置）
         * @param Executor 执行器
         */
        explicit ResolverState(Net::any_io_executor Executor)
            : ResolverState(std::move(Executor), Config{})
        {
        }

        /**
         * @brief 构造（完整配置）
         * @param Executor 执行器
         * @param ConfigValue 配置（上游列表 / 策略 / 规则 / 缓存参数）
         */
        explicit ResolverState(Net::any_io_executor Executor, const Config &ConfigValue)
            : ContextPin_(Preview::Executor::ContextOwner::Find(Executor)), Ex_(std::move(Executor)),
              Config_(ConfigValue),
              Rules_(Detail::MakeRulesOptions(ConfigValue)),
              Serial_(Net::make_strand(Ex_)),
              State_(std::make_shared<ResolverSharedState>(
                  Serial_, Detail::MakeResolverOptions(ConfigValue))),
              CacheResults_(ResolverCacheView{State_->Cache_, Pool_, Config_.CacheEnabled,
                                              Config_.NegativeOnTimeout, Hits_}),
              Maintenance_(Serial_, State_)
        {
        }

        /**
         * @brief 由强状态 owner 等待维护协程真实完成并保留 typed 失败。
         * @param Owner 在整个等待期间共享持有的解析状态。
         * @return 维护停止结果；未完成或调度失败不伪造成功。
         */
        [[nodiscard]] static auto ShutdownOwned(std::shared_ptr<ResolverState> Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await Owner->Maintenance_.Shutdown();
        }
        ResolverState(const ResolverState &) = delete;
        auto operator=(const ResolverState &) -> ResolverState & = delete;

        /**
         * @brief 在强状态 owner 内执行完整解析管道。
         * @param Owner 共享解析状态与维护 owner；保活到本次查询完成。
         * @param Host 调用前复制的自有输入域名。
         * @return 调用方拥有的 typed 地址列表；规则 Negative 为成功空表。
         * @details 查询只在线程串行 executor 执行，结果保留 Failure 的 Native 原因。
         */
        [[nodiscard]] static auto ResolveOwned(
            std::shared_ptr<ResolverState> Owner,
            std::string Host)
            -> Net::awaitable<std::expected<AddressList, Preview::Fault::Failure>>
        {
            const auto Caller = co_await Net::this_coro::executor;
            auto Addresses = std::expected<AddressList, Preview::Fault::Failure>{
                std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::GenericError, {}})};
            try
            {
                Addresses = co_await Net::co_spawn(
                    Owner->Serial_, Owner->ResolveOnSerial(std::move(Host)), Net::use_awaitable);
            }
            catch (const boost::system::system_error &Error)
            {
                Addresses = std::unexpected(Detail::ResolverFailureFromBoost(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                Addresses = std::unexpected(Detail::ResolverFailureFromNative(Error.code()));
            }
            catch (...)
            {
                Addresses = std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::IoError, {}});
            }
            co_await Net::dispatch(Caller, Net::use_awaitable);
            co_return std::move(Addresses);
        }
    private:
        /** @brief 应用一条已规范化名称规则；nullopt 表示继续缓存/flight 查询。 */
        [[nodiscard]] auto ResolveRule(std::string &Name, Preview::Network::DomainName &Domain)
            -> std::optional<std::expected<AddressList, Preview::Fault::Failure>>
        {
            const auto Rule = Rules_.Match(Domain);
            if (!Rule)
            {
                return std::nullopt;
            }
            switch (Rule->Action)
            {
            case RuleAction::Block:
                return std::expected<AddressList, Preview::Fault::Failure>{
                    std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Blocked, {}})};
            case RuleAction::Negative:
                return std::expected<AddressList, Preview::Fault::Failure>{AddressList{}};
            case RuleAction::Rewrite:
            {
                auto Addresses = FilterIps(Rule->Addresses);
                if (Addresses.empty())
                {
                    const bool HasBlockedAddress = std::any_of(
                        Rule->Addresses.begin(), Rule->Addresses.end(),
                        [this](const auto &Address) { return Rules_.IsBlacklisted(Address); });
                    const bool DisabledIpv6Only = Config_.DisableIpv6 &&
                        !Rule->Addresses.empty() &&
                        std::all_of(Rule->Addresses.begin(), Rule->Addresses.end(),
                                    [](const auto &Address) { return Address.is_v6(); });
                    const auto Code = HasBlockedAddress ? Preview::Fault::Code::Blocked
                        : DisabledIpv6Only ? Preview::Fault::Code::Ipv6Disabled
                                           : Preview::Fault::Code::UnsupportedAddress;
                    return std::expected<AddressList, Preview::Fault::Failure>{
                        std::unexpected(Preview::Fault::Failure{Code, {}})};
                }
                CacheResults_.StorePositive(Name, Addresses, DefaultTtl());
                return CacheResults_.MakeAddressList(Addresses);
            }
            case RuleAction::Pass:
                break;
            }
            if (Rule->CnameTarget && Rule->CnameTarget->View() != Name)
            {
                Domain = *Rule->CnameTarget;
                Name.assign(Domain.View());
            }
            return std::nullopt;
        }

        [[nodiscard]] auto ResolveOnSerial(std::string Host)
            -> Net::awaitable<std::expected<AddressList, Preview::Fault::Failure>>
        {
            if (!State_->Alive_->load(std::memory_order_acquire))
            {
                co_return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::Canceled,
                    std::make_error_code(std::errc::operation_canceled)});
            }
            State_->Coalescer_.FlushCleanup();

            auto Name = std::move(Host);

            // IP 字面量快速路径。
            boost::system::error_code LiteralError;
            auto Literal = Net::ip::make_address(Name, LiteralError);
            if (!LiteralError)
            {
                if (Config_.DisableIpv6 && Literal.is_v6())
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Ipv6Disabled, {}});
                }
                if (Rules_.IsBlacklisted(Literal))
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Blocked, {}});
                }
                CacheResults_.StorePositive(Name, std::vector<Net::ip::address>{Literal}, DefaultTtl());
                co_return CacheResults_.MakeAddressList(std::vector<Net::ip::address>{Literal});
            }

            auto Domain = Preview::Network::DomainName::Parse(Name);
            if (!Domain)
            {
                const auto Failure = Domain.error().Native
                                         ? Detail::ResolverFailureFromNative(Domain.error().Native)
                                         : Preview::Fault::Failure{Domain.error().Code, {}};
                co_return std::unexpected(Failure);
            }
            Name.assign(Domain->View());

            // 冻结规则只借用当前查询拥有的规范化名称；CNAME 规则只转移一次。
            if (auto RuleResult = ResolveRule(Name, *Domain))
            {
                co_return std::move(*RuleResult);
            }

            if (auto Cached = CacheResults_.Read(Name))
            {
                co_return std::move(*Cached);
            }

            const auto Lookup = State_->Coalescer_.FindCreate(Name, QTypeNum(QType::A));
            if (!Lookup)
            {
                co_return std::unexpected(Lookup.error());
            }
            const auto &Flight = Lookup->Flight;
            std::shared_ptr<const QueryResult> Result;
            if (!Lookup->IsNew)
            {
                if (!co_await WaitForFlight(Flight))
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::ResourceUnavailable, {}});
                }

                if (auto Cached = CacheResults_.Read(Name))
                {
                    co_return std::move(*Cached);
                }
                if (auto Shared = State_->Coalescer_.GetResult(*Flight))
                {
                    Result = std::move(Shared);
                }
                else
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::DnsFailed, {}});
                }
            }
            else
            {
                Result = co_await RunLeader(Flight, Name);
            }

            co_return FinalizeResult(Name, *Result);
        }

    public:

        /**
         * @brief IP 黑名单检查
         * @param Address 已解析的数值地址，同步借用至返回。
         * @return 命中返回 true
         */
        [[nodiscard]] auto IsBlacklisted(const Net::ip::address& Address) const -> bool
        {
            return Rules_.IsBlacklisted(Address);
        }

        /**
         * @brief 规范化域名（小写、去末尾点号）
         * @param Domain 原始域名
         * @return 规范化结果
         */
        [[nodiscard]] static auto Normalize(std::string_view Domain) -> std::string
        {
            return Message::NormalizeName(Domain);
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
        [[nodiscard]] static constexpr auto QTypeNum(const QType QueryTypeValue) -> std::uint16_t
        {
            return static_cast<std::uint16_t>(QueryTypeValue);
        }

        /// 默认正缓存 TTL（响应无 TTL 时兜底）
        [[nodiscard]] auto DefaultTtl() const -> std::chrono::seconds
        {
            return std::chrono::seconds(Config_.CacheTtl);
        }

        /// 从查询结果计算缓存 TTL（报文无 TTL 时回退配置默认值）
        [[nodiscard]] auto ResultTtl(const QueryResult &Result) const -> std::chrono::seconds
        {
            if (Result.Response.HasTtl)
            {
                return std::chrono::seconds(Result.Response.MinTtl);
            }
            return DefaultTtl();
        }

        /**
         * @brief 等待 single-flight leader 完成
         * @param Flight 共享查询记录
         * @return true = 已登记并等到 leader 发布结果；false = 等待者额度不足，未登记
         */
        [[nodiscard]] auto WaitForFlight(FlightPtr Flight) -> Net::awaitable<bool>
        {
            if (!Flight->TryAcquireWaiter())
            {
                co_return false;
            }
            if (!Flight->Ready())
            {
                boost::system::error_code WaitError;
                co_await Flight->Timer().async_wait(
                    Net::redirect_error(Net::use_awaitable, WaitError));
            }
            Flight->ReleaseWaiter();
            State_->Coalescer_.CleanupFlight(Flight);
            co_return true;
        }

        /**
         * @brief 执行 single-flight leader 查询并发布结果
         * @param Flight 共享查询记录
         * @param Name 已规范化域名
         * @return 上游或操作系统解析结果
         */
        auto RunLeader(FlightPtr Flight, const std::string &Name)
            -> Net::awaitable<std::shared_ptr<const QueryResult>>
        {
            QueryResult Result;
            try
            {
                Result = co_await QueryBothFamilies(Name);
            }
            catch (const boost::system::system_error &Error)
            {
                Result.Error = Detail::ResolverFailureFromBoost(Error.code());
            }
            catch (const std::system_error &Error)
            {
                Result.Error = Detail::ResolverFailureFromNative(Error.code());
            }
            catch (...)
            {
                Result.Error = Preview::Fault::Failure{Preview::Fault::Code::IoError, {}};
            }
            State_->Coalescer_.SetResult(Flight, std::move(Result));
            State_->Coalescer_.CleanupFlight(Flight);
            co_return State_->Coalescer_.GetResult(*Flight);
        }

        /**
         * @brief 过滤、缓存并转换最终解析结果
         * @param Name 已规范化域名
         * @param Result 上游查询结果
         * @return 成功返回有界、独占地址列表；失败保留唯一领域类别与原生 cause。
         */
        [[nodiscard]] auto FinalizeResult(const std::string &Name, const QueryResult &Result)
            -> std::expected<AddressList, Preview::Fault::Failure>
        {
            auto Addresses = FilterIps(Result.Response.Ips);
            if (Result.Error.Succeeded() && !Addresses.empty())
            {
                CacheResults_.StorePositive(Name, Addresses, ResultTtl(Result));
                return CacheResults_.MakeAddressList(Addresses);
            }
            if (Detail::IsResolverCancellation(Result.Error))
            {
                return std::unexpected(Result.Error);
            }
            CacheResults_.StoreNegative(Name, Result.Error);
            if (Result.Error.Failed())
            {
                return std::unexpected(Result.Error);
            }
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::DnsFailed, {}});
        }

        /**
         * @brief 查询 A 与 AAAA 并合并（DisableIpv6 时仅 A）
         * @details 两族并发查询（各自独立 single-flight），总延迟取较慢者而非相加；
         *          合并与顺序去重由 Detail::MergeFamilies 在唯一地址列表上完成
         * @param Name 已规范化域名
         * @return 合并后的查询结果（错误取首个非成功者）
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
            co_return Detail::MergeFamilies(Detail::FamilyMergeRequest{
                std::move(Primary), std::move(Secondary), Pool_});
        }

        /**
         * @brief 单类型查询：有上游走 Upstream，否则回退 OS resolver
         * @param Name 已规范化域名
         * @param QueryType 查询类型
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
                QueryResult TimedOut;
                TimedOut.Error = Preview::Fault::Failure{Preview::Fault::Code::Timeout, {}};
                co_return TimedOut;
            }
            Net::steady_timer Timer(Executor);
            Timer.expires_after(Timeout);
            auto Outcome = co_await (Detail::ResolveOsHost(
                                         Detail::OsResolveRequest{Executor, Name, QueryType, Pool_}) ||
                                      Timer.async_wait(Net::use_awaitable));
            if (Outcome.index() == 1)
            {
                QueryResult TimedOut;
                TimedOut.Error = Preview::Fault::Failure{Preview::Fault::Code::Timeout, {}};
                co_return TimedOut;
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
         * @tparam AddressRange 只读地址范围；规则地址与唯一应答地址列表共用
         * @param Addresses 原始地址列表
         * @return 过滤后列表
         */
        template <class AddressRange>
        [[nodiscard]] auto FilterIps(const AddressRange &Addresses) const
            -> std::vector<Net::ip::address>
        {
            std::vector<Net::ip::address> Result;
            for (const auto &Address : Addresses)
            {
                if (!Rules_.IsBlacklisted(Address) && !(Config_.DisableIpv6 && Address.is_v6()))
                {
                    Result.push_back(Address);
                }
            }
            return Result;
        }

        std::shared_ptr<Preview::Executor::ContextOwner> ContextPin_;
        Net::any_io_executor Ex_;
        Config Config_;
        RulesEngine Rules_;                          ///< 规则引擎（地址/CNAME/黑名单）
        Net::strand<Net::any_io_executor> Serial_;   ///< 查询、缓存与维护的单一执行序列
        std::shared_ptr<ResolverSharedState> State_; ///< 查询资源与维护协程共享状态
        Memory::BytePool Pool_{Memory::BytePoolOptions{.BlockCount = 4}}; ///< 合并与OS回退地址列表的冷池
        std::uint64_t Hits_{0};                      ///< 缓存命中计数
        ResolverCacheResults CacheResults_; ///< 缓存与独占 typed 返回值转换 owner。
        MaintenanceOwner<ResolverSharedState> Maintenance_;
    };

} // namespace Preview::Network::Dns::Detail
