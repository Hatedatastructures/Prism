/**
 * @file Client.cpp
 * @brief TrustTunnel HTTP/2 客户端连接工厂实现。
 */
#include <Prism/Protocols/Trusttunnel/Http2/Client.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/Client.hpp>

#include <exception>
#include <expected>
#include <utility>

namespace Prism::Trusttunnel
{
    auto ConnectHttp2(Http2ConnectParameters Parameters)
        -> boost::asio::awaitable<
            std::expected<SharedTransmission, Prism::Fault::Failure>>
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
            Result = co_await Detail::ConnectHttp2Core(
                std::move(Parameters), Admission);
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
}
