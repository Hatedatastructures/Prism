/** @file Upstream.cpp @brief 多上游 DNS 门面的非模板实现。 */
#include <Prism/Net/Dns/Upstream.hpp>
#include <Prism/Net/Dns/Detail/UpstreamState.hpp>

namespace Prism::Network::Dns
{
    Upstream::Upstream(Net::any_io_executor Executor, UpstreamOptions Options)
        : State_(std::make_shared<Detail::UpstreamState>(
              std::move(Executor), std::move(Options)))
    {
    }

    Upstream::~Upstream() = default;

    auto Upstream::SetServers(const std::vector<Server> &Servers) -> void
    {
        State_->SetServers(Servers);
    }

    auto Upstream::SetMode(const Mode QueryMode) -> void
    {
        State_->SetMode(QueryMode);
    }

    auto Upstream::SetTimeout(const std::chrono::milliseconds Timeout) -> void
    {
        State_->SetTimeout(Timeout);
    }

    auto Upstream::ServerCount() const -> std::size_t
    {
        return State_->ServerCount();
    }

    auto Upstream::IdleConnCount() const -> std::size_t
    {
        return State_->IdleConnCount();
    }

    auto Upstream::ClearIdleConns() -> std::size_t
    {
        return State_->ClearIdleConns();
    }

    auto Upstream::Resolve(const std::string_view Domain, const QType QueryType)
        -> Net::awaitable<QueryResult>
    {
        return Detail::UpstreamState::ResolveOwned(
            State_, Detail::UpstreamResolveRequest{
                        std::string(Domain), QueryType, weak_from_this().lock()});
    }
}
