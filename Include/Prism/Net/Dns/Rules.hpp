/** @file Rules.hpp @brief DNS 域名规则与黑名单引擎接口。 */
#pragma once

#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/DomainName.hpp>

#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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
            RuleConfigurationError();

        protected:
            [[nodiscard]] auto TypeName() const noexcept -> std::string_view override;
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
        auto Insert(const DomainName &Domain) -> Node &;

        /** @brief 冷插入通配锚点；空名称仅表示根通配符 *。 */
        auto InsertWildcard(const std::optional<DomainName> &Parent) -> Node &;

        /** @brief 逆序消费标签并返回精确优先、最深的匹配借用。 */
        [[nodiscard]] auto Search(const DomainName &Domain) const noexcept -> Hit;

    private:
        auto Locate(std::string_view Text) -> Node &;
        [[nodiscard]] static auto EnsureChild(Node &Parent, std::string_view Label) -> Node &;

        Node Root_;
    };

    /**
     * @brief 一个冻结 generation 拥有的规则、CNAME 和 IP 黑名单。
     * @details 冷构造完成后不修改索引；外部 owner 必须保持引擎存活至所有借用结束。
     */
    class RulesEngine final
    {
    public:
        /** @brief 冷装载与校验输入；非法规则抛项目配置异常。 */
        explicit RulesEngine(RulesOptions Options = {});

        /** @brief 同步匹配规则；返回引擎拥有值的只读借用。 */
        [[nodiscard]] auto Match(const DomainName &Domain) const noexcept
            -> const RuleResult *;

        /** @brief 同步整数检查地址黑名单。 */
        [[nodiscard]] auto IsBlacklisted(const boost::asio::ip::address &Address) const noexcept
            -> bool;

        /** @brief 返回冷装载的黑名单条目数。 */
        [[nodiscard]] auto BlacklistSize() const noexcept -> std::size_t;

    private:
        [[nodiscard]] auto LocateSlot(std::string_view Pattern) -> RuleResult &;
        [[nodiscard]] static auto EnsureRule(std::optional<RuleResult> &Rule) -> RuleResult &;
        [[nodiscard]] static auto MatchesV6(const boost::asio::ip::network_v6 &Network,
            const std::array<unsigned char, 16> &Bytes) noexcept -> bool;

        DomainTrie Trie_;
        std::vector<boost::asio::ip::address> Blacklist_;
        std::vector<boost::asio::ip::network_v4> NetsV4_;
        std::vector<boost::asio::ip::network_v6> NetsV6_;
    };
} // namespace Prism::Network::Dns
