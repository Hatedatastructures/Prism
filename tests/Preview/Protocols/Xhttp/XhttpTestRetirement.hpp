/**
 * @file XhttpTestRetirement.hpp
 * @brief XHTTP 集成测试 accepted carrier 的真实关闭与退栈辅助。
 */
#pragma once

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace XhttpTest
{
    namespace Net = boost::asio;

    [[nodiscard]] inline auto CloseAndDrainXhttp(Preview::SharedTransmission Transport)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (!Transport)
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        Preview::Fault::Failure FirstFailure;
        const auto Closed = Transport->Close();
        if (!Closed) FirstFailure = Closed.error();
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained && FirstFailure.Succeeded()) FirstFailure = Drained.error();
        if (!Activity->IsRetired() && FirstFailure.Succeeded())
            FirstFailure = {Preview::Fault::Code::Blocked};
        if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
        co_return std::expected<void, Preview::Fault::Failure>{};
    }
}
