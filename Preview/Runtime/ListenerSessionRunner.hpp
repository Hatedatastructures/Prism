/**
 * @file ListenerSessionRunner.hpp
 * @brief listener 已准入 Session 的执行、终态投递与最终流量退休 owner。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Runtime/ListenerConnectionDrain.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>

#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Runtime::Detail
{

    namespace Net = boost::asio;

    struct ListenerSessionRunRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> SessionOwner;
        Preview::SharedTransmission Transport;
        std::shared_ptr<ListenerConnectionDrain> Drain;
    };

    /** @brief 等待 Session 与 control delivery 真实终态后退休统计键。 */
    [[nodiscard]] inline auto RunListenerSession(ListenerSessionRunRequest Input)
        -> Net::awaitable<Preview::Fault::Failure>
    {
        const auto Control = Input.SessionOwner->Control();
        try
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            if (Input.Drain)
            {
                Input.Drain->RetainSession(Input.SessionOwner);
                Input.Drain->MarkSessionStarted();
            }
            const auto Result = co_await Input.SessionOwner->Run(Input.Transport);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Delivered = co_await Control->AwaitDelivery();
            if (!Delivered)
            {
                if (Input.Drain)
                {
                    Input.Drain->MarkSessionTerminalFailure(Delivered.error());
                }
                co_return Delivered.error();
            }
            if (!Input.SessionOwner->IsDrained())
            {
                auto Failure = Result;
                if (!Failure.Failed())
                {
                    Failure = Preview::Fault::Failure{Preview::Fault::Code::Blocked};
                }
                if (Input.Drain)
                {
                    Input.Drain->MarkSessionTerminalFailure(Failure);
                }
                co_return Failure;
            }
            if (Input.Drain)
            {
                Input.Drain->MarkSessionDrained();
            }
            const auto Identity = Control->CurrentIdentity();
            const auto Services = Input.SessionOwner->Services();
            if (Services && Services->Traffic && Identity.SessionId.Value() != 0U)
            {
                const auto Retired = co_await Preview::Foundation::RetireTraffic(
                    Services->Traffic,
                    Preview::Foundation::TrafficRetirement{Preview::Foundation::SessionTrafficOwner{
                        Identity.WorkerId, Identity.SessionId}});
                (void)Retired;
            }
            co_return Result;
        }
        catch (const std::system_error &Error)
        {
            const auto Failure = Preview::Fault::FromNative(Error.code());
            if (Input.Drain)
            {
                Input.Drain->MarkSessionTerminalFailure(Failure);
            }
            co_return Failure;
        }
        catch (...)
        {
            const Preview::Fault::Failure Failure{Preview::Fault::Code::IoError};
            if (Input.Drain)
            {
                Input.Drain->MarkSessionTerminalFailure(Failure);
            }
            co_return Failure;
        }
    }

} // namespace Preview::Runtime::Detail
