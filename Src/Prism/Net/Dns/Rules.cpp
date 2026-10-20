/** @file Rules.cpp @brief DNS 域名规则与黑名单实现。 */
#include <Prism/Net/Dns/Rules.hpp>

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <iterator>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    RuleConfigurationError::RuleConfigurationError()
        : Exception::Deviant(Fault::make_error_code(Fault::Code::ConfigErr),
              "DNS 规则包含非法域名、通配符或 IP")
    {
    }

    auto RuleConfigurationError::TypeName() const noexcept -> std::string_view
    {
        return "DNS";
    }
}

namespace Prism::Network::Dns
{
    auto DomainTrie::Insert(const DomainName &Domain) -> Node &
    {
        return Locate(Domain.View());
    }

    auto DomainTrie::InsertWildcard(const std::optional<DomainName> &Parent) -> Node &
    {
        if (!Parent)
        {
            return Root_;
        }
        return Locate(Parent->View());
    }

    auto DomainTrie::Search(const DomainName &Domain) const noexcept -> Hit
    {
        const auto Text = Domain.View();
        const Node *Current = &Root_;
        Hit Result;
        if (Root_.Wildcard)
        {
            Result.Wild = &*Root_.Wildcard;
        }
        auto End = Text.size();
        while (End != 0)
        {
            const auto Dot = Text.rfind('.', End - 1);
            std::size_t Start = 0;
            if (Dot != std::string_view::npos)
            {
                Start = Dot + 1;
            }
            const auto Child = Current->Children.find(Text.substr(Start, End - Start));
            if (Child == Current->Children.end())
            {
                break;
            }
            Current = Child->second.get();
            if (Start == 0)
            {
                if (Current->Exact)
                {
                    Result.Exact = &*Current->Exact;
                }
                break;
            }
            if (Current->Wildcard)
            {
                Result.Wild = &*Current->Wildcard;
            }
            End = Start - 1;
        }
        return Result;
    }

    auto DomainTrie::Locate(const std::string_view Text) -> Node &
    {
        auto *Current = &Root_;
        auto End = Text.size();
        while (End != 0)
        {
            const auto Dot = Text.rfind('.', End - 1);
            std::size_t Start = 0;
            if (Dot != std::string_view::npos)
            {
                Start = Dot + 1;
            }
            Current = &EnsureChild(*Current, Text.substr(Start, End - Start));
            if (Start == 0)
            {
                break;
            }
            End = Start - 1;
        }
        return *Current;
    }

    auto DomainTrie::EnsureChild(Node &Parent, const std::string_view Label) -> Node &
    {
        const auto Found = Parent.Children.find(Label);
        if (Found != Parent.Children.end())
        {
            return *Found->second;
        }
        auto Child = std::make_unique<Node>();
        return *Parent.Children.emplace(std::string(Label), std::move(Child)).first->second;
    }

    RulesEngine::RulesEngine(RulesOptions Options)
        : Blacklist_(std::move(Options.BlacklistAddrs)),
          NetsV4_(std::move(Options.BlacklistV4)), NetsV6_(std::move(Options.BlacklistV6))
    {
        for (auto &Rule : Options.AddressRules)
        {
            auto &Result = LocateSlot(Rule.Domain);
            if (Rule.Negative)
            {
                Result.Action = RuleAction::Negative;
            }
            else if (Rule.Addresses.empty())
            {
                Result.Action = RuleAction::Block;
            }
            else
            {
                Result.Action = RuleAction::Rewrite;
            }
            Result.Addresses.insert(Result.Addresses.end(),
                std::make_move_iterator(Rule.Addresses.begin()),
                std::make_move_iterator(Rule.Addresses.end()));
        }
        for (const auto &Rule : Options.CnameRules)
        {
            auto Target = DomainName::Parse(Rule.Target);
            if (!Target)
            {
                throw Detail::RuleConfigurationError();
            }
            LocateSlot(Rule.Domain).CnameTarget = std::move(*Target);
        }
        for (const auto &Item : Options.Blacklist)
        {
            boost::system::error_code ErrorCode;
            const auto Address = boost::asio::ip::make_address(Item, ErrorCode);
            if (ErrorCode)
            {
                throw Detail::RuleConfigurationError();
            }
            Blacklist_.push_back(Address);
        }
    }

    auto RulesEngine::Match(const DomainName &Domain) const noexcept -> const RuleResult *
    {
        const auto Found = Trie_.Search(Domain);
        if (Found.Exact)
        {
            return Found.Exact;
        }
        return Found.Wild;
    }

    auto RulesEngine::IsBlacklisted(const boost::asio::ip::address &Address) const noexcept -> bool
    {
        if (Address.is_v4())
        {
            const auto Raw = Address.to_v4().to_uint();
            for (const auto &Item : Blacklist_)
            {
                if (Item.is_v4() && Item.to_v4().to_uint() == Raw)
                {
                    return true;
                }
            }
            for (const auto &Network : NetsV4_)
            {
                if ((Raw & Network.netmask().to_uint()) == Network.network().to_uint())
                {
                    return true;
                }
            }
            return false;
        }
        const auto Bytes = Address.to_v6().to_bytes();
        for (const auto &Item : Blacklist_)
        {
            if (Item.is_v6() && Item.to_v6().to_bytes() == Bytes)
            {
                return true;
            }
        }
        for (const auto &Network : NetsV6_)
        {
            if (MatchesV6(Network, Bytes))
            {
                return true;
            }
        }
        return false;
    }

    auto RulesEngine::BlacklistSize() const noexcept -> std::size_t
    {
        return Blacklist_.size() + NetsV4_.size() + NetsV6_.size();
    }

    auto RulesEngine::LocateSlot(const std::string_view Pattern) -> RuleResult &
    {
        bool Wildcard = false;
        if (Pattern == "*")
        {
            return EnsureRule(Trie_.InsertWildcard(std::nullopt).Wildcard);
        }
        auto DomainText = Pattern;
        if (DomainText.starts_with("*."))
        {
            DomainText.remove_prefix(2);
            Wildcard = true;
        }
        auto Domain = DomainName::Parse(DomainText);
        if (!Domain)
        {
            throw Detail::RuleConfigurationError();
        }
        if (Wildcard)
        {
            return EnsureRule(Trie_.InsertWildcard(
                std::optional<DomainName>(*Domain)).Wildcard);
        }
        return EnsureRule(Trie_.Insert(*Domain).Exact);
    }

    auto RulesEngine::EnsureRule(std::optional<RuleResult> &Rule) -> RuleResult &
    {
        if (!Rule)
        {
            Rule.emplace();
        }
        return *Rule;
    }

    auto RulesEngine::MatchesV6(const boost::asio::ip::network_v6 &Network,
        const std::array<unsigned char, 16> &Bytes) noexcept -> bool
    {
        const auto NetworkBytes = Network.network().to_bytes();
        const auto Prefix = Network.prefix_length();
        for (std::size_t Index = 0; Index < 16 && Index * 8 < Prefix; ++Index)
        {
            unsigned char Mask = 0xFF;
            if (Index * 8 + 8 > Prefix)
            {
                Mask = static_cast<unsigned char>(0xFF << (8 - (Prefix - Index * 8)));
            }
            if ((Bytes[Index] & Mask) != (NetworkBytes[Index] & Mask))
            {
                return false;
            }
        }
        return true;
    }
} // namespace Prism::Network::Dns
