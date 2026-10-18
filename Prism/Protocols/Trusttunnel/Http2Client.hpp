/**
 * @file Http2Client.hpp
 * @brief TrustTunnel HTTP/2 客户端公开连接工厂。
 */
#pragma once

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Client.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ClientTypes.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <exception>
#include <utility>

namespace Prism::Trusttunnel
{

    namespace Net = boost::asio;

    /**
     * @brief 建立经 HTTP/2 CONNECT 的客户端传输。
     * @param Parameters 按值接管上游、目标和 byte pool；TLS/config 借用至返回。
     * @return 唯一 shared Transmission owner，或保留首个 Code/Native 的 typed failure。
     * @details I/O 前准备同一 admission ticket；失败由本 factory 取消、关闭并 drain，
     *          成功保留 HTTP/2 双向半关闭并将最终 Close 责任移交给结果。
     */
    [[nodiscard]] inline auto ConnectHttp2(Http2ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedTransmission, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
            Parameters.Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        std::expected<SharedTransmission, Prism::Fault::Failure> Result{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        try
        {
            Result = co_await Detail::ConnectHttp2Core(std::move(Parameters), Admission);
        }
        catch (...)
        {
            Fatal = std::current_exception();
        }
        if (Fatal)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Fatal));
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        co_return Result;
    }

} // namespace Prism::Trusttunnel
