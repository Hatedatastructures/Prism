/**
 * @file Common.hpp
 * @brief XHTTP 私有子模块共享类型与执行器别名。
 */

#pragma once

#include <Preview/Protocols/Http2/Session.hpp>

#include <Preview/Protocols/Xhttp/Types.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <memory>
#include <expected>
#include <exception>

namespace Preview::Xhttp::Detail
{

    namespace Net = boost::asio;
    namespace h2 = Preview::Http2;

    /// h2 会话共享指针。
    using SharedH2Session = std::shared_ptr<h2::Session>;

    /// 客户端响应通道同时交付 h2 接收状态与首个 typed I/O failure。
    using ResponseChannel = Net::experimental::channel<
        void(boost::system::error_code, Preview::Fault::Failure, bool)>;
    using DriverCompletionChannel = Net::experimental::channel<
        void(boost::system::error_code, Preview::Fault::Failure)>;
[[nodiscard]] inline auto WaitDriverCompletion(
        const std::shared_ptr<DriverCompletionChannel> &Completed)
        -> Net::awaitable<Preview::Fault::Failure>
    {
        boost::system::error_code WaitError;
        const auto Failure = co_await Completed->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
            co_return Preview::Fault::FromNative(static_cast<std::error_code>(WaitError));
        co_return Failure;
    }

    /** @brief 在 XHTTP 工厂边界保留异常携带的标准/native cause。 */
    [[nodiscard]] inline auto FailureFromException(std::exception_ptr Exception) noexcept
        -> Preview::Fault::Failure
    {
        return Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Exception));
    }

    /** @brief 失败前门按其原 executor Cancel、Close 并等待所有载体活动排空。 */
    [[nodiscard]] inline auto RetireFactoryInput(
        SharedTransmission Inbound,
        Preview::Fault::Failure Cause) -> Net::awaitable<Preview::Fault::Failure>
    {
        if (!Inbound) co_return Cause;
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Inbound);
        if (!Prepared)
        {
            if (Cause.Failed()) co_return Cause;
            co_return Prepared.error();
        }
        auto Admission = std::move(*Prepared);
        co_return co_await Admission.Retire(Cause);
    }

    using boost::asio::experimental::awaitable_operators::operator||;

} // namespace Preview::Xhttp::Detail
