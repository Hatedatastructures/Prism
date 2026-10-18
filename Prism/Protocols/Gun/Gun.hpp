/**
 * @file Gun.hpp
 * @brief Gun 客户端与服务端 CONNECT factory。
 * @details factory 按值接管传输和握手配置；成功结果唯一拥有已握手 Conn，
 *          失败返回 typed Failure，factory 负责 Cancel、Close 与 Activity Drain。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Gun/Conn.hpp>
#include <Prism/Protocols/Gun/Types.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <utility>

namespace Prism::Gun
{
    struct ConnectRequest final
    {
        SharedTransmission Upstream;
        std::string Host;
        Config Configuration;
    };

    struct AcceptResult final
    {
        std::string Host;
        SharedConn Connection;
    };

    /**
     * @brief 建立 Gun CONNECT 客户端并保留完整 typed 握手失败。
     * @param Request 按值接管上游与 owning Host/Config，协程挂起期间不借用调用方数据。
     * @return 唯一的 expected 结果；失败包含 Code/Native，工厂已 Cancel、Close 并 Drain。
     * @details executor 固定为 Upstream 的原 executor；成功 Conn 持有唯一上游所有权，
     *          WriteShutdown 只半关闭本端写方向，最终 Close 由 Conn 调用者发起并等待 Activity Drain。
     */
    [[nodiscard]] inline auto Connect(ConnectRequest Request)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);

        std::exception_ptr Fatal;
        try
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Request.Upstream), std::move(Request.Configuration));
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));

            const auto Handshake = co_await Connection->WriteHandshake(Request.Host);
            if (!Handshake)
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            Admission.Release();
            co_return SharedConn(std::move(Connection));
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    /**
     * @brief 接收 Gun CONNECT 服务端流并保留完整 typed 握手失败。
     * @param Upstream 按值接管的单一上游传输；其 executor 是握手和清理执行域。
     * @param Configuration 按值拥有的 wire path/service 约束。
     * @return 唯一 expected 结果；成功值同时拥有 Host 与 Conn，失败时工厂完成 Cancel/Close/Drain。
     * @details 成功 Conn 的 WriteShutdown 仅半关闭本端写方向；最终 Close 与后续 Activity Drain 归调用者。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        Config Configuration)
        -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);

        std::exception_ptr Fatal;
        try
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Upstream), std::move(Configuration));
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));

            std::string Host;
            const auto Handshake = co_await Connection->ReadHandshake(Host);
            if (!Handshake)
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            Admission.Release();
            co_return AcceptResult{std::move(Host), SharedConn(std::move(Connection))};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }
} // namespace Prism::Gun
