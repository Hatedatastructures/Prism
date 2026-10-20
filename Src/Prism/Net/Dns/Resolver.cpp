/** @file Resolver.cpp @brief DNS resolver 公开门面的非模板实现。 */
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Dns/Detail/ResolverOwner.hpp>

namespace Prism::Network::Dns
{
    Resolver::Resolver(Net::any_io_executor Executor)
        : Resolver(std::move(Executor), Config{})
    {
    }

    Resolver::Resolver(Net::any_io_executor Executor, const Config &ConfigValue)
        : State_(Detail::MakeResolverState(std::move(Executor), ConfigValue))
    {
    }

    Resolver::~Resolver() = default;

    auto Resolver::IsBlacklisted(const Net::ip::address &Address) const -> bool
    {
        return Detail::IsResolverBlacklisted(*State_, Address);
    }

    auto Resolver::Normalize(const std::string_view Domain) -> std::string
    {
        return Detail::NormalizeResolverDomain(Domain);
    }

    auto Resolver::HitCount() const noexcept -> std::uint64_t
    {
        return Detail::ResolverHitCount(*State_);
    }

    auto Resolver::Size() const noexcept -> std::size_t
    {
        return Detail::ResolverSize(*State_);
    }

    auto Resolver::Clear() -> void
    {
        Detail::ClearResolverCache(*State_);
    }
}
