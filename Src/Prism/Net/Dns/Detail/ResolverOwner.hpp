/** @file ResolverOwner.hpp @brief DNS Resolver 门面到私有状态 owner 的窄调用契约。 */
#pragma once

#include <Prism/Net/Dns/Config.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/address.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace Prism::Network::Dns::Detail
{
    class ResolverState;

    [[nodiscard]] auto MakeResolverState(boost::asio::any_io_executor Executor,
                                         const Config &ConfigValue)
        -> std::shared_ptr<ResolverState>;

    [[nodiscard]] auto IsResolverBlacklisted(
        const ResolverState &Owner, const boost::asio::ip::address &Address) -> bool;

    [[nodiscard]] auto NormalizeResolverDomain(std::string_view Domain) -> std::string;
    [[nodiscard]] auto ResolverHitCount(const ResolverState &Owner) noexcept -> std::uint64_t;
    [[nodiscard]] auto ResolverSize(const ResolverState &Owner) noexcept -> std::size_t;
    auto ClearResolverCache(ResolverState &Owner) -> void;
}
