/**
 * @file ReadDeadlineOwner.hpp
 * @brief HTTP listener 对 request-read deadline 失败的最终 owner。
 */
#pragma once

#include <Prism/Operations/Http/Detail/ReadDeadline.hpp>
#include <Prism/Operations/Http/Detail/Lifecycle.hpp>
#include <Prism/Operations/HttpServer.hpp>

#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <system_error>

namespace Prism::Operations::HttpConnection
{

    template <typename StateValue>
    inline auto FailReadDeadlineOnStateStrand(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<Detail::ReadDeadlineTask> &Task,
        const boost::system::error_code &Failure) noexcept -> void
    {
        if (!State->DrainFailure)
        {
            State->DrainFailure = Prism::Fault::FromNative(
                static_cast<std::error_code>(Failure));
        }
        State->StopRequested.store(true, std::memory_order_release);
        CloseOnStateStrand(State);
        State->StateOperationFailed.store(true, std::memory_order_release);
        boost::system::error_code Error;
        try
        {
            static_cast<void>(State->DrainTimer.cancel());
        }
        catch (const boost::system::system_error &FailureValue)
        {
            Error = FailureValue.code();
        }
        catch (...)
        {
            Error = boost::system::errc::make_error_code(boost::system::errc::io_error);
        }
        if (Error && !State->DrainFailure)
        {
            State->DrainFailure = Prism::Fault::FromNative(
                static_cast<std::error_code>(Error));
        }
        Task->FailureOwnerPublished.store(true, std::memory_order_release);
        if (!Task->FailureOwnerPublication.try_send(boost::system::error_code{}))
        {
            Task->FailureOwnerNotificationFailed.store(true, std::memory_order_release);
        }
    }

    template <typename StateValue>
    inline auto NotifyReadDeadlineFailure(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<Detail::ReadDeadlineTask> &Task,
        const boost::system::error_code &Failure) noexcept -> void
    {
        try
        {
            Net::post(State->StateStrand, [State, Task, Failure]
            {
                FailReadDeadlineOnStateStrand(State, Task, Failure);
            });
        }
        catch (...)
        {
            Task->FailureOwnerNotificationFailed.store(true, std::memory_order_release);
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto MakeStateFailureDrainResult(
        const std::shared_ptr<StateValue> &State,
        const std::size_t RemainingConnections) -> HttpServer::DrainResult
    {
        auto Failure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        if (State->DrainFailure)
        {
            Failure = *State->DrainFailure;
        }
        return {Failure, RemainingConnections};
    }

} // namespace Prism::Operations::HttpConnection
