/**
 * @file Rules.hpp
 * @brief 冷构造的 DNS 规则索引与无分配标签查询。
 */
#pragma once

#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/DomainName.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Network::Dns
{
    /** @brief 域名规则的独立业务终态。 */
    enum class RuleAction : std::uint8_t { Pass, Block, Negative, Rewrite };

    /** @brief 冷装载拥有的规则值；查询只借用，不复制地址或名字。 */
    struct RuleResult final
    {
        RuleAction Action{RuleAction::Pass};
        std::vector<boost::asio::ip::address> Addresses;
        std::optional<DomainName> CnameTarget;
    };

    /** @brief 冷构造输入；所有容器在构造后归规则引擎拥有。 */
    struct RulesOptions final
    {
        std::vector<AddressRule> AddressRules;
        std::vector<CnameRule> CnameRules;
        std::vector<std::string> Blacklist;
        std::vector<boost::asio::ip::address> BlacklistAddrs;
        std::vector<boost::asio::ip::network_v4> BlacklistV4;
        std::vector<boost::asio::ip::network_v6> BlacklistV6;
    };

    namespace Detail
    {
        /** @brief 冷装载阶段拒绝非法域名或 IP 规则。 */
        class RuleConfigurationError final : public Exception::Deviant
        {
        public:
            RuleConfigurationError()
                : Exception::Deviant(Fault::make_error_code(Fault::Code::ConfigErr),
                                     "DNS 规则包含非法域名、通配符或 IP") {}
        protected:
            [[nodiscard]] auto TypeName() const noexcept -> std::string_view override { return "DNS"; }
        };
    }

    /**
     * @brief TLD 优先的域名索引；装载可分配，Search 只遍历原有节点。
     * @details 输入 DomainName 拥有全部标签，查询无标签数组或溢出分支。
     */
    class DomainTrie final
    {
    public:
        /** @brief 一个标签 owner；精确与通配规则各自拥有唯一值。 */
        struct Node final
        {
            std::map<std::string, std::unique_ptr<Node>, std::less<>> Children;
            std::optional<RuleResult> Exact;
            std::optional<RuleResult> Wildcard;
        };

        /** @brief 查找结果借用树节点，只在冷冻结索引存活且不再修改期间有效。 */
        struct Hit final
        {
            const RuleResult *Exact{nullptr};
            const RuleResult *Wild{nullptr};
        };

        /** @brief 冷插入已校验完整名称；没有查询期新增节点的路径。 */
        auto Insert(const DomainName &Domain) -> Node& { return Locate(Domain.View()); }

        /** @brief 冷插入通配锚点；空名称仅表示根通配符 *。 */
        auto InsertWildcard(const std::optional<DomainName> &Parent) -> Node&
        {
            if (!Parent) return Root_;
            return Locate(Parent->View());
        }

        /**
         * @brief 逆序消费全部标签，精确优先、通配符至少消费一个子域。
         * @param Domain 借用固定容量拥有值，仅同步读取；不保存引用。
         * @return 借用精确和最深通配结果；无 executor、取消或关闭行为。
         */
        [[nodiscard]] auto Search(const DomainName &Domain) const noexcept -> Hit
        {
            const auto Text = Domain.View();
            const Node *Current = &Root_;
            Hit Result;
            if (Root_.Wildcard) Result.Wild = &*Root_.Wildcard;
            auto End = Text.size();
            while (End != 0)
            {
                const auto Dot = Text.rfind('.', End - 1);
                std::size_t Start = 0;
                if (Dot != std::string_view::npos) Start = Dot + 1;
                const auto Child = Current->Children.find(Text.substr(Start, End - Start));
                if (Child == Current->Children.end()) break;
                Current = Child->second.get();
                if (Start == 0)
                {
                    if (Current->Exact) Result.Exact = &*Current->Exact;
                    break;
                }
                if (Current->Wildcard) Result.Wild = &*Current->Wildcard;
                End = Start - 1;
            }
            return Result;
        }

    private:
        auto Locate(const std::string_view Text) -> Node&
        {
            auto *Current = &Root_;
            auto End = Text.size();
            while (End != 0)
            {
                const auto Dot = Text.rfind('.', End - 1);
                std::size_t Start = 0;
                if (Dot != std::string_view::npos) Start = Dot + 1;
                Current = &EnsureChild(*Current, Text.substr(Start, End - Start));
                if (Start == 0) break;
                End = Start - 1;
            }
            return *Current;
        }

        [[nodiscard]] static auto EnsureChild(Node &Parent, const std::string_view Label) -> Node&
        {
            const auto Found = Parent.Children.find(Label);
            if (Found != Parent.Children.end()) return *Found->second;
            auto Child = std::make_unique<Node>();
            return *Parent.Children.emplace(std::string(Label), std::move(Child)).first->second;
        }

        Node Root_;
    };

    /**
     * @brief 一个冻结 generation 拥有的规则、CNAME 和 IP 黑名单。
     * @details 冷构造完成后不修改索引；外部 owner 必须保持引擎存活至所有借用结束。
     */
    class RulesEngine final
    {
    public:
        /** @brief 冷装载与校验输入；非法规则抛项目配置异常，分配失败由启动边界处理。 */
        explicit RulesEngine(RulesOptions Options = {})
            : Blacklist_(std::move(Options.BlacklistAddrs)),
              NetsV4_(std::move(Options.BlacklistV4)), NetsV6_(std::move(Options.BlacklistV6))
        {
            for (auto &Rule : Options.AddressRules)
            {
                auto &Result = LocateSlot(Rule.Domain);
                if (Rule.Negative) Result.Action = RuleAction::Negative;
                else if (Rule.Addresses.empty()) Result.Action = RuleAction::Block;
                else Result.Action = RuleAction::Rewrite;
                Result.Addresses.insert(Result.Addresses.end(),
                    std::make_move_iterator(Rule.Addresses.begin()),
                    std::make_move_iterator(Rule.Addresses.end()));
            }
            for (const auto &Rule : Options.CnameRules)
            {
                auto Target = DomainName::Parse(Rule.Target);
                if (!Target) throw Detail::RuleConfigurationError();
                LocateSlot(Rule.Domain).CnameTarget = std::move(*Target);
            }
            for (const auto &Item : Options.Blacklist)
            {
                boost::system::error_code ErrorCode;
                const auto Address = boost::asio::ip::make_address(Item, ErrorCode);
                if (ErrorCode) throw Detail::RuleConfigurationError();
                Blacklist_.push_back(Address);
            }
        }

        /**
         * @brief 同步匹配规则；返回引擎拥有值的只读借用，没有请求期复制或分配。
         * @param Domain 借用完整规范化域名，不跨异步保存输入。
         * @return nullptr 表示默认放行；返回值在冻结 generation 存活期间有效。
         */
        [[nodiscard]] auto Match(const DomainName &Domain) const noexcept -> const RuleResult*
        {
            const auto Found = Trie_.Search(Domain);
            if (Found.Exact) return Found.Exact;
            return Found.Wild;
        }

        /** @brief 同步整数检查地址黑名单；输入仅借用，不解析文本或分配。 */
        [[nodiscard]] auto IsBlacklisted(const boost::asio::ip::address &Address) const noexcept -> bool
        {
            if (Address.is_v4())
            {
                const auto Raw = Address.to_v4().to_uint();
                for (const auto &Item : Blacklist_)
                    if (Item.is_v4() && Item.to_v4().to_uint() == Raw) return true;
                for (const auto &Network : NetsV4_)
                    if ((Raw & Network.netmask().to_uint()) == Network.network().to_uint()) return true;
                return false;
            }
            const auto Bytes = Address.to_v6().to_bytes();
            for (const auto &Item : Blacklist_)
                if (Item.is_v6() && Item.to_v6().to_bytes() == Bytes) return true;
            for (const auto &Network : NetsV6_)
                if (MatchesV6(Network, Bytes)) return true;
            return false;
        }

        /** @brief 返回冷装载条目数，不包含任何查询历史。 */
        [[nodiscard]] auto BlacklistSize() const noexcept -> std::size_t
        { return Blacklist_.size() + NetsV4_.size() + NetsV6_.size(); }

    private:
        [[nodiscard]] auto LocateSlot(std::string_view Pattern) -> RuleResult&
        {
            bool Wildcard = false;
            if (Pattern == "*") return EnsureRule(Trie_.InsertWildcard(std::nullopt).Wildcard);
            if (Pattern.starts_with("*.")) { Pattern.remove_prefix(2); Wildcard = true; }
            auto Domain = DomainName::Parse(Pattern);
            if (!Domain) throw Detail::RuleConfigurationError();
            if (Wildcard) return EnsureRule(Trie_.InsertWildcard(std::optional<DomainName>(*Domain)).Wildcard);
            return EnsureRule(Trie_.Insert(*Domain).Exact);
        }

        [[nodiscard]] static auto EnsureRule(std::optional<RuleResult> &Rule) -> RuleResult&
        {
            if (!Rule) Rule.emplace();
            return *Rule;
        }

        [[nodiscard]] static auto MatchesV6(const boost::asio::ip::network_v6 &Network,
                                            const std::array<unsigned char, 16> &Bytes) noexcept -> bool
        {
            const auto NetworkBytes = Network.network().to_bytes();
            const auto Prefix = Network.prefix_length();
            for (std::size_t Index = 0; Index < 16 && Index * 8 < Prefix; ++Index)
            {
                unsigned char Mask = 0xFF;
                if (Index * 8 + 8 > Prefix)
                    Mask = static_cast<unsigned char>(0xFF << (8 - (Prefix - Index * 8)));
                if ((Bytes[Index] & Mask) != (NetworkBytes[Index] & Mask)) return false;
            }
            return true;
        }

        DomainTrie Trie_;
        std::vector<boost::asio::ip::address> Blacklist_;
        std::vector<boost::asio::ip::network_v4> NetsV4_;
        std::vector<boost::asio::ip::network_v6> NetsV6_;
    };
}
