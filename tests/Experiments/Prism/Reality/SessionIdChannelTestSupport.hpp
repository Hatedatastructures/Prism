/**
 * @file SessionIdChannelTestSupport.hpp
 * @brief SessionIdChannel 实验测试的有主 transport 与完整清理驱动。
 */
#pragma once

#include "../../../Prism/Transport/TransportResources.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Reality::Detail::Experiments::TestSupport
{
    namespace Net = boost::asio;
    using Pair = Prism::Testing::OwnedTransportPair;

    [[nodiscard]] inline auto MakePair(Net::any_io_executor Executor) -> Pair
    {
        return Prism::Testing::MakeOwnedTransportPair(std::move(Executor));
    }

    template <typename Awaitable>
    inline auto Run(Net::io_context &Context, Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Context, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    template <typename Awaitable>
    inline auto RunAndClose(Net::io_context &Context, const Pair &Endpoints, Awaitable Operation)
        -> void
    {
        std::exception_ptr Failure;
        try
        {
            Run(Context, std::move(Operation));
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        std::exception_ptr CleanupFailure;
        struct EndpointCleanup final
        {
            Net::io_context &Context;
            std::exception_ptr &Failure;

            auto Close(const std::shared_ptr<Prism::MemoryStream> &Owner) const -> void
            {
                try
                {
                    Prism::Testing::ExpectFixtureCloseReceipt(
                        Prism::Testing::DriveClose(Context, Owner));
                }
                catch (...)
                {
                    if (!Failure) Failure = std::current_exception();
                }
            }
        };
        const EndpointCleanup Cleanup{Context, CleanupFailure};
        Cleanup.Close(Endpoints.FirstOwner);
        Cleanup.Close(Endpoints.SecondOwner);
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        if (CleanupFailure)
        {
            std::rethrow_exception(CleanupFailure);
        }
    }
}
