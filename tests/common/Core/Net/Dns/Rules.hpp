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

#include <any>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
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
        RuleAction Action{RuleAction::Pass};    ///< 命中的动作
        std::vector<std::string> Addresses;     ///< Rewrite 动作的固定地址
        std::optional<std::string> CnameTarget; ///< CNAME 静态映射目标
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
            std::any Value;         ///< 精确终结节点携带的数据
            bool HasValue{false};   ///< Value 是否有效
            std::any WildValue;     ///< 通配符规则挂在本节点的数据（仅经通配符路径可达）
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
            std::vector<std::string_view> labels;
            SplitForEach(domain, [&labels](std::string_view label)
                         { labels.push_back(label); });

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
                else if (cur->WildValue.has_value())
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
         * @param addressRules 地址规则（Addresses 为空视为 Block，否则 Rewrite）
         * @param cnameRules CNAME 静态映射（可与地址规则同域合并）
         * @param blacklist IP 字面量黑名单
         */
        explicit RulesEngine(const std::vector<AddressRule> &addressRules = {},
                             const std::vector<CnameRule> &cnameRules = {},
                             std::vector<std::string> blacklist = {})
            : Blacklist_(std::move(blacklist))
        {
            for (const auto &rule : addressRules)
            {
                auto result = LocateSlot(rule.Domain);
                if (rule.Negative)
                {
                    result->Action = RuleAction::Negative;
                }
                else
                {
                    result->Action =
                        rule.Addresses.empty() ? RuleAction::Block : RuleAction::Rewrite;
                }
                if (!rule.Addresses.empty())
                {
                    for (const auto &addr : rule.Addresses)
                    {
                        result->Addresses.push_back(addr.to_string());
                    }
                }
            }
            for (const auto &rule : cnameRules)
            {
                LocateSlot(rule.Domain)->CnameTarget = rule.Target;
            }
        }

        /**
         * @brief 匹配域名规则
         * @param qname 已规范化查询域名
         * @return 命中返回 RuleResult；未命中返回 nullopt（默认放行）
         */
        [[nodiscard]] auto Match(const std::string &qname) const -> std::optional<RuleResult>
        {
            const auto hit = Trie_.Search(qname);
            if (hit.Exact != nullptr && hit.Exact->Value.has_value())
            {
                return *std::any_cast<std::shared_ptr<RuleResult>>(hit.Exact->Value);
            }
            if (hit.Wild != nullptr && hit.Wild->WildValue.has_value())
            {
                return *std::any_cast<std::shared_ptr<RuleResult>>(hit.Wild->WildValue);
            }
            return std::nullopt;
        }

        /**
         * @brief IP 字面量黑名单检查
         * @param addr 待检查地址字符串
         * @return 命中黑名单返回 true
         */
        [[nodiscard]] auto IsBlacklisted(std::string_view addr) const -> bool
        {
            for (const auto &item : Blacklist_)
            {
                if (item == addr)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief 黑名单条目数
         * @return 条目数
         */
        [[nodiscard]] auto BlacklistSize() const -> std::size_t
        {
            return Blacklist_.size();
        }

    private:
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
            if (node.Value.has_value())
            {
                return std::any_cast<std::shared_ptr<RuleResult>>(node.Value);
            }
            auto result = std::make_shared<RuleResult>();
            node.Value = result;
            node.HasValue = true;
            return result;
        }

        /// 取或建通配符节点上的共享 RuleResult
        [[nodiscard]] static auto GetOrCreateWild(DomainTrie::Node &node)
            -> std::shared_ptr<RuleResult>
        {
            if (node.WildValue.has_value())
            {
                return std::any_cast<std::shared_ptr<RuleResult>>(node.WildValue);
            }
            auto result = std::make_shared<RuleResult>();
            node.WildValue = result;
            return result;
        }

        DomainTrie Trie_;
        std::vector<std::string> Blacklist_;
    };

} // namespace Preview::Network::Dns
