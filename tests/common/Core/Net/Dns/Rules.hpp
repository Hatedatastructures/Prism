/**
 * @file Rules.hpp
 * @brief DNS 域名规则引擎层
 * @details 对齐主项目 net/dns/detail/rules.hpp 分层：
 *          - DomainTrie：按标签反转存储的域名前缀树（com → example → www），
 *            支持通配符节点（*.example.com 在 example.com 节点标记 wildcard）
 *          - RulesEngine：地址规则（改写/屏蔽）+ CNAME 静态映射 + 黑名单，
 *            按"精确 > 通配符、深 > 浅"优先级匹配
 *
 *          通配符语义：至少消耗一级子域。即 *.example.com 匹配
 *          www.example.com 与 a.www.example.com，但不匹配 example.com 本身。
 */

#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @enum RuleAction
     * @brief 地址规则动作
     */
    enum class RuleAction : std::uint8_t
    {
        Pass,     ///< 放行：正常走上游解析
        Block,    ///< 屏蔽：直接返回失败（对应主项目 blocked）
        Negative, ///< 置空：返回成功 + 空 IP 列表（NXDOMAIN 语义）
        Rewrite,  ///< 改写：直接返回规则配置的固定地址列表
    };

    /**
     * @struct RuleResult
     * @brief 规则匹配结果
     */
    struct RuleResult
    {
        RuleAction Action{RuleAction::Pass};             ///< 命中的动作
        std::vector<boost::asio::ip::address> Addresses; ///< Rewrite 固定地址（装载时预解析）
        std::optional<std::string> CnameTarget;          ///< CNAME 静态映射目标
    };

    /**
     * @struct RulesOptions
     * @brief 规则引擎装载选项
     * @details 将地址规则、CNAME 规则和三类黑名单收敛为一个
     *          配置对象，避免构造函数参数过多。
     */
    struct RulesOptions
    {
        std::vector<AddressRule> AddressRules; ///< 地址映射与屏蔽规则
        std::vector<CnameRule> CnameRules;     ///< CNAME 重定向规则
        std::vector<std::string> Blacklist;   ///< 字符串形式的精确黑名单
        std::vector<boost::asio::ip::address> BlacklistAddrs; ///< 地址形式的精确黑名单
        std::vector<boost::asio::ip::network_v4> BlacklistV4; ///< IPv4 黑名单网段
        std::vector<boost::asio::ip::network_v6> BlacklistV6; ///< IPv6 黑名单网段
    };

    /**
     * @class DomainTrie
     * @brief 反转标签域名前缀树
     * @details "www.example.com" 存储为 com → example → www 三级节点；
     *          通配符规则 "*.example.com" 的 wildcard 标记与值都挂在
     *          "example.com" 节点上。节点值用 std::any 承载。
     */
    class DomainTrie
    {
    public:
        /**
         * @struct Node
         * @brief trie 节点
         */
        struct Node
        {
            std::map<std::string, std::unique_ptr<Node>, std::less<>> Children; ///< 子标签
            bool Wildcard{false};   ///< 是否存在通配符子域（*.本节点域名）
            std::shared_ptr<RuleResult> Value_; ///< 精确终结节点数据（可空）
            bool HasValue{false};   ///< Value_ 是否有效（插入精确规则后置位）
            std::shared_ptr<RuleResult> WildValue_; ///< 通配符数据（可空，仅经通配符路径可达）
        };

        /**
         * @brief 插入完整域名
         * @param domain 已规范化小写域名（无末尾点号）
         * @return 终结节点引用（可写入 Value）
         */
        auto Insert(std::string_view domain) -> Node &
        {
            Node *cur = &Root_;
            ForEachReversed(domain, [&cur](std::string_view label)
                            { cur = &EnsureChild(*cur, label); });
            cur->HasValue = true;
            return *cur;
        }

        /**
         * @brief 标记通配符规则（*.domain）
         * @details 去掉 "*." 前缀后沿剩余基域路径定位锚点节点并置 Wildcard：
         *          "*.www.example.com" 锚定在 "www.example.com" 节点；
         *          "*.com" 锚定在 "com" 节点；裸 "*" 则锚定根节点
         * @param domain 以 "*." 开头的完整通配域名
         * @return 被标记的锚点节点引用（可写入 WildValue）
         */
        auto InsertWildcard(std::string_view domain) -> Node &
        {
            const auto Dot = domain.find('.');
            const auto ParentPath =
                Dot == std::string_view::npos ? std::string_view{} : domain.substr(Dot + 1);
            Node *cur = &Root_;
            if (!ParentPath.empty())
            {
                ForEachReversed(ParentPath, [&cur](std::string_view label)
                                { cur = &EnsureChild(*cur, label); });
            }
            cur->Wildcard = true;
            return *cur;
        }

        /**
         * @brief 查找域名（支持通配符）
         * @details 收集标签后倒序行走（TLD 优先）：沿后缀路径下探，全量消费
         *          到达的节点为精确命中；途中遇到携带 WildValue 的节点且前端
         *          尚有未消费标签（保证通配符至少吃一级子域）则为通配符命中，
         *          行走越深通配符命中越深、自然覆盖浅层规则。
         *          取值优先级：精确命中 > 通配符命中
         * @param domain 已规范化小写域名
         * @return 精确/通配符两条命中的最佳节点（可为 nullptr）
         */
        struct Hit
        {
            const Node *Exact{nullptr}; ///< 精确路径最佳命中
            const Node *Wild{nullptr};  ///< 通配符路径最佳命中（最深者）
        };

        [[nodiscard]] auto Search(std::string_view domain) const -> Hit
        {
            // 栈上固定 labels 数组（>16 级标签的罕见域名退化为堆）
            std::array<std::string_view, 16> buf{};
            std::size_t count = 0;
            std::vector<std::string_view> overflow;
            SplitForEach(domain, [&](std::string_view label)
                         {
                             if (count < buf.size())
                             {
                                 buf[count++] = label;
                             }
                             else
                             {
                                 overflow.push_back(label);
                             } });
            const std::span<const std::string_view> labels =
                overflow.empty() ? std::span<const std::string_view>(buf.data(), count)
                                 : std::span<const std::string_view>(overflow);

            Hit hit;
            const Node *cur = &Root_;
            for (std::size_t i = labels.size(); i > 0; --i)
            {
                const auto child = cur->Children.find(labels[i - 1]);
                if (child == cur->Children.end())
                {
                    break;
                }
                cur = child->second.get();
                const auto Remaining = i - 1; ///< 前端尚未消费的标签数
                if (Remaining == 0)
                {
                    if (cur->HasValue)
                    {
                        hit.Exact = cur;
                    }
                }
                else if (cur->WildValue_ != nullptr)
                {
                    hit.Wild = cur;
                }
            }
            return hit;
        }

        /**
         * @brief 清空整棵树
         */
        void Clear()
        {
            Root_ = Node{};
        }

    private:
        /// 按标签从左到右遍历域名（自动忽略空标签）
        template <typename Fn>
        static void SplitForEach(std::string_view domain, Fn &&fn)
        {
            std::size_t start = 0;
            while (start <= domain.size())
            {
                const auto Dot = domain.find('.', start);
                const auto End = Dot == std::string_view::npos ? domain.size() : Dot;
                if (End > start)
                {
                    fn(domain.substr(start, End - start));
                }
                if (Dot == std::string_view::npos)
                {
                    break;
                }
                start = Dot + 1;
            }
        }

        /// 按标签从右到左遍历域名（TLD 优先，与反转存储序一致）
        template <typename Fn>
        static void ForEachReversed(std::string_view domain, Fn &&fn)
        {
            std::vector<std::string_view> labels;
            SplitForEach(domain, [&labels](std::string_view label)
                         { labels.push_back(label); });
            for (std::size_t i = labels.size(); i > 0; --i)
            {
                fn(labels[i - 1]);
            }
        }

        [[nodiscard]] static auto EnsureChild(Node &node, std::string_view label) -> Node &
        {
            if (const auto it = node.Children.find(label); it != node.Children.end())
            {
                return *it->second;
            }
            auto child = std::make_unique<Node>();
            return *node.Children.emplace(std::string(label), std::move(child)).first->second;
        }

        Node Root_;
    };

    /**
     * @class RulesEngine
     * @brief 规则引擎：地址规则 + CNAME 映射 + 黑名单
     */
    class RulesEngine
    {
    public:
        /**
         * @brief 构造规则引擎并装载规则
         * @param options 地址、CNAME 与黑名单配置
         */
        explicit RulesEngine(RulesOptions options = {})
            : NetsV4_(std::move(options.BlacklistV4)),
              NetsV6_(std::move(options.BlacklistV6))
        {
            for (const auto &rule : options.AddressRules)
            {
                auto result = LocateSlot(NormalizeDomain(rule.Domain));
                if (rule.Negative)
                {
                    result->Action = RuleAction::Negative;
                }
                else
                {
                    result->Action =
                        rule.Addresses.empty() ? RuleAction::Block : RuleAction::Rewrite;
                }
                // AddressRule.Addresses 装载期已是 address：直接持有，查询期零解析
                for (const auto &addr : rule.Addresses)
                {
                    result->Addresses.push_back(addr);
                }
            }
            for (const auto &rule : options.CnameRules)
            {
                LocateSlot(NormalizeDomain(rule.Domain))->CnameTarget = NormalizeDomain(rule.Target);
            }
            // 字符串黑名单装载期解析为地址（无效字面量忽略）
            for (const auto &item : options.Blacklist)
            {
                boost::system::error_code ec;
                if (auto addr = boost::asio::ip::make_address(item, ec); !ec)
                {
                    Blacklist_.push_back(addr);
                }
            }
            Blacklist_.insert(Blacklist_.end(),
                              std::make_move_iterator(options.BlacklistAddrs.begin()),
                              std::make_move_iterator(options.BlacklistAddrs.end()));
        }

        /**
         * @brief 匹配域名规则
         * @param qname 已规范化查询域名
         * @return 命中返回 RuleResult；未命中返回 nullopt（默认放行）
         */
        [[nodiscard]] auto Match(std::string_view qname) const -> std::optional<RuleResult>
        {
            const auto hit = Trie_.Search(qname);
            if (hit.Exact != nullptr && hit.Exact->Value_ != nullptr)
            {
                return *hit.Exact->Value_;
            }
            if (hit.Wild != nullptr && hit.Wild->WildValue_ != nullptr)
            {
                return *hit.Wild->WildValue_;
            }
            return std::nullopt;
        }

        /**
         * @brief IP 黑名单检查（精确地址 + CIDR 网段，纯整数比较无字符串分配）
         * @param addr 待检查地址
         * @return 命中黑名单返回 true
         */
        [[nodiscard]] auto IsBlacklisted(const boost::asio::ip::address &addr) const -> bool
        {
            if (addr.is_v4())
            {
                const auto Raw = addr.to_v4().to_uint();
                for (const auto &item : Blacklist_)
                {
                    if (item.is_v4() && item.to_v4().to_uint() == Raw)
                    {
                        return true;
                    }
                }
                for (const auto &net : NetsV4_)
                {
                    if ((Raw & net.netmask().to_uint()) == net.address().to_uint())
                    {
                        return true;
                    }
                }
                return false;
            }
            if (addr.is_v6())
            {
                const auto Bytes = addr.to_v6().to_bytes();
                for (const auto &item : Blacklist_)
                {
                    if (item.is_v6() && item.to_v6().to_bytes() == Bytes)
                    {
                        return true;
                    }
                }
                for (const auto &net : NetsV6_)
                {
                    if (MatchesV6(net, Bytes))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
         * @brief IP 黑名单检查（字符串字面量便捷重载，装载后解析路径）
         * @param addr 待检查地址字符串（IP 字面量）
         * @return 命中黑名单返回 true；非法字面量返回 false
         */
        [[nodiscard]] auto IsBlacklisted(std::string_view addr) const -> bool
        {
            boost::system::error_code ec;
            const auto parsed = boost::asio::ip::make_address(addr, ec);
            return !ec && IsBlacklisted(parsed);
        }

        /**
         * @brief 黑名单条目数（精确地址 + CIDR 网段合计）
         * @return 条目数
         */
        [[nodiscard]] auto BlacklistSize() const -> std::size_t
        {
            return Blacklist_.size() + NetsV4_.size() + NetsV6_.size();
        }

    private:
        /// 规则装载期统一域名大小写并去除末尾点号
        [[nodiscard]] static auto NormalizeDomain(const std::string &domain) -> std::string
        {
            std::string normalized = domain;
            while (normalized.size() > 1 && normalized.back() == '.')
            {
                normalized.pop_back();
            }
            for (auto &ch : normalized)
            {
                if (ch >= 'A' && ch <= 'Z')
                {
                    ch = static_cast<char>(ch - 'A' + 'a');
                }
            }
            return normalized;
        }

        /// IPv6 CIDR 前缀匹配（按字节掩码比较）
        [[nodiscard]] static auto MatchesV6(const boost::asio::ip::network_v6 &net,
                                            const std::array<unsigned char, 16> &bytes) -> bool
        {
            const auto NetBytes = net.address().to_bytes();
            const auto Prefix = net.prefix_length();
            for (std::size_t i = 0; i < 16 && i * 8 < Prefix; ++i)
            {
                const auto Bits = static_cast<unsigned char>(
                    i * 8 + 8 <= Prefix ? 0xFF : 0xFF << (8 - (Prefix - i * 8)));
                if ((bytes[i] & Bits) != (NetBytes[i] & Bits))
                {
                    return false;
                }
            }
            return true;
        }
        /// 按域名定位规则槽位：通配符域挂 WildValue，精确域挂 Value
        [[nodiscard]] auto LocateSlot(const std::string &domain) -> std::shared_ptr<RuleResult>
        {
            if (!domain.empty() && domain.front() == '*')
            {
                return GetOrCreateWild(Trie_.InsertWildcard(domain));
            }
            return GetOrCreate(Trie_.Insert(domain));
        }

        /// 取或建节点上的共享 RuleResult（同域多规则合并到同一结果对象）
        [[nodiscard]] static auto GetOrCreate(DomainTrie::Node &node)
            -> std::shared_ptr<RuleResult>
        {
            if (node.Value_ != nullptr)
            {
                return node.Value_;
            }
            auto result = std::make_shared<RuleResult>();
            node.Value_ = result;
            node.HasValue = true;
            return result;
        }

        /// 取或建通配符节点上的共享 RuleResult
        [[nodiscard]] static auto GetOrCreateWild(DomainTrie::Node &node)
            -> std::shared_ptr<RuleResult>
        {
            if (node.WildValue_ != nullptr)
            {
                return node.WildValue_;
            }
            auto result = std::make_shared<RuleResult>();
            node.WildValue_ = result;
            return result;
        }

        DomainTrie Trie_;
        std::vector<boost::asio::ip::address> Blacklist_; ///< 精确地址黑名单（装载期解析）
        std::vector<boost::asio::ip::network_v4> NetsV4_; ///< IPv4 网段黑名单
        std::vector<boost::asio::ip::network_v6> NetsV6_; ///< IPv6 网段黑名单
    };

} // namespace Preview::Network::Dns
