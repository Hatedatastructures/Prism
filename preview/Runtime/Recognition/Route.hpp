/**
 * @file Route.hpp
 * @brief SNI 路由表（域名 → 伪装方案）
 * @details 供 stealth 方案识别：TLS ClientHello 的 SNI 域名查表
 *          决定执行哪个伪装方案。支持精确匹配与通配子域。
 */

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <optional>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Runtime/Recognition/Protocol.hpp>

namespace Preview::Recognition
{

    /**
     * @struct RouteEntry
     * @brief SNI 路由目标
     * @details scheme 负责外层伪装包装；Protocol 为包装后的内层协议。
     *          AllowFallback 仅表示显式允许未命中方案时走回退路径。
     */
    struct RouteEntry
    {
        std::string Scheme;
        ProtocolType Protocol{ProtocolType::Unknown};
        bool AllowFallback{false};
    };

    struct RouteOptions
    {
        ProtocolType Protocol{ProtocolType::Unknown};
        bool AllowFallback{false};
    };

    /**
     * @class SniRouteTable
     * @brief SNI 路由表
     * @details 域名 → 方案名映射。支持：
     *          - 精确匹配："example.com"
     *          - 通配匹配："*.example.com"（子域）
     */
    class SniRouteTable
    {
    public:
        /**
         * @brief 添加路由
         * @param Domain 域名（支持 *. 前缀通配）
         * @param Scheme 方案名
         */
        void Add(std::string_view Domain, std::string_view Scheme)
        {
            Add(Domain, Scheme, RouteOptions{});
        }

        /**
         * @brief 添加指定内层协议的路由
         * @param Domain 域名（支持 *. 前缀通配）
         * @param Scheme 方案名
         * @param Protocol 包装后的内层协议
         * @details 三参数形式默认不允许显式回退。
         */
        void Add(std::string_view Domain, std::string_view Scheme, ProtocolType Protocol)
        {
            Add(Domain, Scheme, RouteOptions{Protocol, false});
        }

        /**
         * @brief 添加带内层协议的路由
         * @param Domain 域名（支持 *. 前缀通配）
         * @param Scheme 方案名
         * @param Options 路由附加选项
         */
        void Add(std::string_view Domain, std::string_view Scheme, RouteOptions Options)
        {
            const auto NormalizedDomain = Normalize(Domain);
            if (NormalizedDomain.empty())
            {
                return;
            }
            const RouteEntry Entry{Normalize(Scheme), Options.Protocol, Options.AllowFallback};
            auto Update = [Entry, NormalizedDomain = std::string(NormalizedDomain)](
                              RouteSnapshot &Snapshot) -> void
            {
                if (NormalizedDomain.size() > 2 && NormalizedDomain[0] == '*' &&
                    NormalizedDomain[1] == '.')
                {
                    Snapshot.Wildcards[NormalizedDomain.substr(1)] = Entry;
                }
                else
                {
                    Snapshot.Exact[NormalizedDomain] = Entry;
                }
            };
            UpdateSnapshot(std::move(Update));
        }

        /**
         * @brief 受约束的旧式四参数路由适配器
         * @param Domain 域名
         * @param Scheme 方案名
         * @param LegacyArgs 仅接受 ProtocolType 与 bool
         * @details 适配旧调用语法，但不恢复普通四参数函数签名。
         */
        template <typename... LegacyArgs>
            requires (sizeof...(LegacyArgs) == 2 &&
                      std::is_same_v<std::tuple<std::remove_cvref_t<LegacyArgs>...>,
                                             std::tuple<ProtocolType, bool>>)
        void Add(std::string_view Domain, std::string_view Scheme, LegacyArgs &&...LegacyArgsValues)
        {
            auto Values = std::tuple<LegacyArgs &&...>(std::forward<LegacyArgs>(LegacyArgsValues)...);
            Add(Domain, Scheme, RouteOptions{std::get<0>(Values), std::get<1>(Values)});
        }

        /**
         * @brief 查询 SNI 对应方案
         * @param Sni SNI 域名
         * @return 方案名；未命中返回空
         * @details 先精确匹配，再选择最长的单标签通配项。
         */
        [[nodiscard]] auto Lookup(std::string_view Sni) const -> std::string
        {
            const auto Entry = LookupValue(Sni);
            if (Entry)
            {
                return Entry->Scheme;
            }
            return {};
        }

        /**
         * @brief 设置显式 default 路由
         * @param Scheme 方案名
         * @param Protocol 包装后的内层协议
         * @param AllowFallback 是否允许显式回退
         */
        void SetDefault(std::string_view Scheme, ProtocolType Protocol = ProtocolType::Unknown,
                        bool AllowFallback = false)
        {
            const RouteEntry Entry{Normalize(Scheme), Protocol, AllowFallback};
            auto Update = [Entry](RouteSnapshot &Snapshot) -> void { Snapshot.Default = Entry; };
            UpdateSnapshot(std::move(Update));
        }

        /**
         * @brief 清除显式 default 路由
         */
        void ClearDefault() noexcept
        {
            auto Update = [](RouteSnapshot &Snapshot) -> void { Snapshot.Default.reset(); };
            UpdateSnapshot(std::move(Update));
        }

        /**
         * @brief 按值查询 SNI 路由
         * @param Sni SNI 域名
         * @return 稳定的路由副本；未命中且无 default 时为空
         * @details 返回值不暴露底层 unordered_map 节点，表更新不会使结果悬空。
         */
        [[nodiscard]] auto LookupValue(std::string_view Sni) const -> std::optional<RouteEntry>
        {
            const auto Snapshot = Snapshot_.load(std::memory_order_acquire);
            const auto Normalized = Normalize(Sni);
            const auto *Entry = FindEntry(*Snapshot, Normalized);
            if (Entry)
            {
                return *Entry;
            }
            return std::nullopt;
        }

        /**
         * @brief 查询完整 SNI 路由
         * @param Sni SNI 域名
         * @return 路由条目；未命中返回 nullptr
         */
        [[nodiscard]] auto LookupEntry(std::string_view Sni) const -> std::optional<RouteEntry>
        {
            return LookupValue(Sni);
        }

        /**
         * @brief 路由表大小
         * @return 条目数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            const auto Snapshot = Snapshot_.load(std::memory_order_acquire);
            return Snapshot->Exact.size() + Snapshot->Wildcards.size();
        }

        /**
         * @brief 清空路由表
         */
        void Clear()
        {
            Snapshot_.store(std::make_shared<const RouteSnapshot>(), std::memory_order_release);
        }

    private:
        struct RouteSnapshot
        {
            std::unordered_map<std::string, RouteEntry> Exact;
            std::unordered_map<std::string, RouteEntry> Wildcards;
            std::optional<RouteEntry> Default;
        };

        template <typename Mutator>
        void UpdateSnapshot(Mutator &&Mutate)
        {
            auto Current = Snapshot_.load(std::memory_order_acquire);
            while (true)
            {
                auto Next = std::make_shared<RouteSnapshot>(*Current);
                Mutate(*Next);
                std::shared_ptr<const RouteSnapshot> Published(std::move(Next));
                if (Snapshot_.compare_exchange_weak(Current, Published,
                                                     std::memory_order_acq_rel,
                                                     std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        [[nodiscard]] static auto FindEntry(const RouteSnapshot &Snapshot,
                                             std::string_view Normalized) -> const RouteEntry *
        {
            if (const auto It = Snapshot.Exact.find(std::string(Normalized)); It != Snapshot.Exact.end())
            {
                return &It->second;
            }

            // 通配只允许一个非空标签；首个点后的后缀索引使查询保持 O(1)。
            const auto Dot = Normalized.find('.');
            if (Dot > 0 && Dot != std::string_view::npos)
            {
                if (const auto It = Snapshot.Wildcards.find(std::string(Normalized.substr(Dot)));
                    It != Snapshot.Wildcards.end())
                {
                    return &It->second;
                }
            }
            if (Snapshot.Default)
            {
                return &*Snapshot.Default;
            }
            return nullptr;
        }

        [[nodiscard]] static auto Normalize(std::string_view Domain) -> std::string
        {
            std::string Result;
            Result.reserve(Domain.size());
            for (const auto Character : Domain)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                auto NormalizedByte = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    NormalizedByte = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(NormalizedByte));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        std::atomic<std::shared_ptr<const RouteSnapshot>> Snapshot_{
            std::make_shared<const RouteSnapshot>()};
    };

} // namespace Preview::Recognition
