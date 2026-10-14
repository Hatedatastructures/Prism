/**
 * @file Http2Server.hpp
 * @brief TrustTunnel HTTP/2 CONNECT 服务端公开工厂与 typed 结果。
 */
#pragma once

#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Http2Accept.hpp>
#include <Preview/Protocols/Trusttunnel/Http2ServerTypes.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <utility>

namespace Preview::Trusttunnel
{

    namespace Net = boost::asio;

    /**
     * @brief 接管 raw carrier 并完成 TLS、HTTP/2 CONNECT 与 wire authentication。
     * @param Request 按值移交 raw、immutable binding、byte pool；TLS context 借用到返回。
     * @return 已认证目标及唯一 Transmission owner，或保留 Code/Native 的 typed failure。
     * @details 首个 I/O 前准备 admission；失败由同一 ticket 负责 Close 与 Activity drain，
     *          成功 carrier 保留双向 half-close，并将最终关闭责任移交返回值。
     */
    [[nodiscard]] inline auto AcceptHttp2(Http2AcceptRequest Request)
        -> Net::awaitable<std::expected<Http2Accepted, Preview::Fault::Failure>>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::optional<std::expected<Http2Accepted, Preview::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            auto Handler = std::make_shared<Detail::Http2Accept>(std::move(Request));
            Result.emplace(co_await Handler->Run(Admission));
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        co_return std::move(*Result);
    }

} // namespace Preview::Trusttunnel
