/**
 * @file ConfigOptions.hpp
 * @brief DNS Resolver 配置到子模块选项的纯转换
 * @details 该文件只负责配置映射，不持有 Resolver 状态，也不启动协程。
 */

#pragma once

#include <preview/Net/Dns/Cache.hpp>
#include <preview/Net/Dns/Config.hpp>
#include <preview/Net/Dns/Rules.hpp>
#include <preview/Net/Dns/Upstream.hpp>

namespace Preview::Network::Dns::Detail
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
        return Options;
    }

} // namespace Preview::Network::Dns::Detail
