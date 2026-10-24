/** @file QueryExecutor.cpp @brief DNS 上游端点解析 owner 的非模板实现。 */
#include <Prism/Net/Dns/Detail/QueryExecutor.hpp>

namespace Prism::Network::Dns::Detail
{
    auto EndpointResolver::Resolve(const std::string_view Host, const std::uint16_t Port,
                                  boost::system::error_code &Error)
        -> Net::awaitable<Net::ip::tcp::endpoint>
    {
        const auto CacheKey = std::string(Host) + ':' + std::to_string(Port);
        if (const auto It = EndpointCache_.find(CacheKey); It != EndpointCache_.end())
        {
            co_return It->second;
        }

        Net::ip::tcp::resolver ResolverObject(Ex_);
        auto Results = co_await ResolverObject.async_resolve(
            std::string(Host), std::to_string(Port),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Results.begin() == Results.end())
        {
            co_return Net::ip::tcp::endpoint{};
        }

        const auto EndpointValue = Results.begin()->endpoint();
        EndpointCache_.emplace(CacheKey, EndpointValue);
        co_return EndpointValue;
    }
}
