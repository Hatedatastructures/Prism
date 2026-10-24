/**
 * @file ConfigOptions.hpp
 * @brief DNS Resolver 配置到子模块选项的纯转换
 * @details 该文件只负责配置映射，不持有 Resolver 状态，也不启动协程。
 */

#pragma once

#include <Prism/Net/Dns/Cache.hpp>
#include <Prism/Net/Dns/Coalescer.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/Dns/Rules.hpp>
#include <Prism/Net/Dns/Upstream.hpp>

namespace Prism::Network::Dns::Detail
{

    /**
     * @brief 生成缓存选项
     * @param ConfigValue Resolver 配置
     * @return Cache 配置
     */
    [[nodiscard]] inline auto MakeCacheOptions(const Config &ConfigValue) -> CacheOptions
    {
        CacheOptions Options;
        Options.MaxEntries = ConfigValue.MaxCacheEntries;
        Options.TtlMin = std::chrono::seconds(ConfigValue.TtlMin);
        Options.TtlMax = std::chrono::seconds(ConfigValue.TtlMax);
        Options.NegativeTtl = std::chrono::seconds(ConfigValue.NegativeTtl);
        Options.Policy = ConfigValue.CachePolicy;
        return Options;
    }

    /**
     * @brief 生成规则引擎选项
     * @param ConfigValue Resolver 配置
     * @return Rules 配置
     */
    [[nodiscard]] inline auto MakeRulesOptions(const Config &ConfigValue) -> RulesOptions
    {
        RulesOptions Options;
        Options.AddressRules = ConfigValue.AddressRules;
        Options.CnameRules = ConfigValue.CnameRules;
        Options.BlacklistAddrs = ConfigValue.AddressBlacklist;
        Options.BlacklistV4 = ConfigValue.BlacklistV4;
        Options.BlacklistV6 = ConfigValue.BlacklistV6;
        return Options;
    }

    /**
     * @brief 生成上游查询选项
     * @param ConfigValue Resolver 配置
     * @return Upstream 配置
     */
    [[nodiscard]] inline auto MakeUpstreamOptions(const Config &ConfigValue) -> UpstreamOptions
    {
        UpstreamOptions Options;
        Options.Servers = ConfigValue.Servers;
        Options.QueryMode = ConfigValue.QueryMode;
        Options.DefaultTimeout = std::chrono::milliseconds(ConfigValue.TimeoutMs);
        Options.MaxConnsPerServer = ConfigValue.MaxConnsPerServer;
        Options.MaxIdleConnsPerPool = ConfigValue.MaxIdleConnsPerPool;
        return Options;
    }

    /**
     * @brief 生成 single-flight 预算
     * @param ConfigValue Resolver 配置
     * @return Coalescer 配置
     */
    [[nodiscard]] inline auto MakeCoalescerOptions(const Config &ConfigValue) -> CoalescerOptions
    {
        CoalescerOptions Options;
        Options.MaxFlights = ConfigValue.MaxFlights;
        Options.MaxWaitersPerFlight = ConfigValue.MaxWaitersPerFlight;
        return Options;
    }

    /**
     * @struct ResolverOptions
     * @brief Resolver 子模块冻结选项：缓存、single-flight 与上游查询
     */
    struct ResolverOptions
    {
        CacheOptions Cache;      ///< 缓存容量与 TTL 策略
        CoalescerOptions Flight; ///< flight 与等待者预算
        UpstreamOptions Upstream;///< 上游列表、策略、超时与连接池预算
    };

    /**
     * @brief 生成 Resolver 子模块完整冻结选项
     * @param ConfigValue Resolver 配置
     * @return 缓存、flight 与上游查询选项
     */
    [[nodiscard]] inline auto MakeResolverOptions(const Config &ConfigValue) -> ResolverOptions
    {
        ResolverOptions Options;
        Options.Cache = MakeCacheOptions(ConfigValue);
        Options.Flight = MakeCoalescerOptions(ConfigValue);
        Options.Upstream = MakeUpstreamOptions(ConfigValue);
        return Options;
    }

} // namespace Prism::Network::Dns::Detail
