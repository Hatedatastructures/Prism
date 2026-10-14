/**
 * @file ResolverSharedState.hpp
 * @brief DNS 查询与维护协程共享的资源状态。
 */
#pragma once

#include <Preview/Net/Dns/Cache.hpp>
#include <Preview/Net/Dns/Coalescer.hpp>
#include <Preview/Net/Dns/Detail/ConfigOptions.hpp>
#include <Preview/Net/Dns/Upstream.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <memory>

namespace Preview::Network::Dns::Detail
{
    /**
     * @brief 维护 cache、single-flight、上游池和维护 timer 的唯一共享 owner。
     * @details ResolverState、每个在途查询和 MaintenanceOwner 通过 shared_ptr 共同保活；
     *          timer 仅由注入 executor 上的维护协程等待及取消。
     */
    struct ResolverSharedState final
    {
        ResolverSharedState(boost::asio::any_io_executor Executor,
                            const ResolverOptions &Options)
            : Cache_(Options.Cache), Coalescer_(Executor, Options.Flight),
              Upstream_(std::make_shared<Upstream>(Executor, Options.Upstream)),
              MaintenanceTimer_(Executor), Alive_(std::make_shared<std::atomic<bool>>(true))
        {
        }

        Cache Cache_;
        Coalescer<QueryResult> Coalescer_;
        std::shared_ptr<Upstream> Upstream_;
        boost::asio::steady_timer MaintenanceTimer_;
        std::shared_ptr<std::atomic<bool>> Alive_;
    };
} // namespace Preview::Network::Dns::Detail
