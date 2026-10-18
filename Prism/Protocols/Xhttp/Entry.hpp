/**
 * @file Entry.hpp
 * @brief XHTTP 客户端与服务端统一入口。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitClient.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServerAccept.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamClient.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamServer.hpp>
#include <Prism/Protocols/Xhttp/Types.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/ssl.hpp>

#include <exception>
#include <memory>
#include <new>
#include <string_view>
#include <utility>

namespace Prism::Xhttp
{

    /** @brief 按值拥有 raw、配置和 byte pool；调用者保活 TLS context 至 factory awaitable 完成。 */
    struct AcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /**
     * @brief 创建 XHTTP 客户端连接并返回 typed 握手/接收失败。
     * @param Request 按值拥有 Raw、Config、Host 和 BytePool；SSL context 由调用者保活至返回。
     * @return 唯一 expected 结果；成功值是唯一 Transmission owner，失败包含完整 Code/Native。
     * @details executor 固定为 Raw 原 executor；失败 factory Cancel、Close、Drain，成功 half-close
     *          保持反向读取，最终 Close 与 Activity Drain 归成功 Transmission 调用者。
     */
    [[nodiscard]] inline auto Connect(
        ClientConnectRequest Request) -> Net::awaitable<FactoryResult>
    {
        if (!Request.SslContext)
        {
            co_return std::unexpected(co_await Detail::RetireFactoryInput(
                std::move(Request.Raw),
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        if (!Request.Configuration.Enabled())
            co_return std::unexpected(co_await Detail::RetireFactoryInput(
                std::move(Request.Raw),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));
        if (Request.Configuration.IsSplit())
        {
            co_return co_await Detail::ConnectSplit(
                Detail::SplitClientConnectRequest{
                    std::move(Request.Raw), *Request.SslContext, std::move(Request.Configuration),
                    std::move(Request.Host), std::move(Request.Bytes)});
        }
        co_return co_await Detail::ConnectStream(std::move(Request));
    }

    /**
     * @brief 创建 XHTTP 服务端连接并返回 typed TLS/HTTP2 接收失败。
     * @param Request 按值拥有 Raw、Config 和 BytePool；调用者保活 SslContext 至返回。
     * @return 成功值拥有唯一 Transmission 并保留真实 TLS SNI/ALPN/版本/ECH 快照；失败保留 Code/Native。
     * @details executor 固定为 Raw 原 executor；失败 factory Cancel、Close、Drain，成功 half-close
     *          保持反向读取，最终 Close 与 Activity Drain 归成功 Transmission 调用者。
     */
    [[nodiscard]] inline auto Accept(AcceptRequest Request) -> Net::awaitable<ServerAcceptResult>
    {
        if (!Request.Raw)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        if (!Request.Bytes)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        if (!Request.Configuration.Enabled())
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));
        }
        std::exception_ptr Fatal;
        try
        {
            if (Request.Configuration.IsSplit())
            {
                auto Handler = std::make_shared<Detail::XhttpSplitAccept>(
                    Detail::XhttpSplitAcceptRequest{std::move(Request.Raw), Request.SslContext,
                                            std::move(Request.Configuration), std::move(Request.Bytes)});
                co_return co_await Handler->Run(Admission);
            }
            auto Handler = std::make_shared<Detail::XhttpAccept>(
                Detail::XhttpAcceptRequest{std::move(Request.Raw), Request.SslContext,
                                   std::move(Request.Configuration), std::move(Request.Bytes)});
            co_return co_await Handler->Run(Admission);
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

} // namespace Prism::Xhttp
