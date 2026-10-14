/**
 * @file Reply.hpp
 * @brief SOCKS5 延迟 CONNECT 应答的协议拥有者
 * @details Fault 错误到 SOCKS5 wire 应答的映射，以及拨号完成后的
 *          CONNECT 应答写入和关闭语义均由协议模块拥有。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    /**
     * @brief 将运行时拨号错误转换为 SOCKS5 CONNECT 响应码
     * @param Status 运行时拨号状态
     * @return RFC 1928 BND 响应码
     */
    [[nodiscard]] inline auto ToReplyCode(Preview::Fault::Code Status) -> ReplyCode
    {
        if (!Preview::Fault::Failed(Status))
        {
            return ReplyCode::Success;
        }
        switch (Status)
        {
        case Preview::Fault::Code::ConnectionRefused:
            return ReplyCode::ConnectionRefused;
        case Preview::Fault::Code::Unreachable:
        case Preview::Fault::Code::NetNoreply:
            return ReplyCode::NetworkUnreachable;
        case Preview::Fault::Code::HostNoreply:
            return ReplyCode::HostUnreachable;
        default:
            return ReplyCode::GeneralFailure;
        }
    }

    /**
     * @brief 发送延迟 CONNECT 应答并完成失败收口
     * @param Connection 协议连接共享所有权；协程完成前保持有效
     * @param Trace 在请求接入时捕获并随回复协程固定的诊断上下文
     * @param Status 拨号首因及 Native；仅 Code 决定 wire 响应。
     * @return 回复写入或必要关闭的首个完整失败；拨号首因由 PostDial 调用者保留。
     * @details 写成功且 Status 为 Success 时保留连接供 relay 使用；其余
     *          状态或写失败均由协议 Conn 关闭。关闭失败只在回复操作成功时返回，
     *          不覆盖更早的回复写入失败。
     */
    [[nodiscard]] inline auto SendConnectDeferredReply(
        std::shared_ptr<Conn<>> Connection,
        Preview::Diagnose::ContextState Trace,
        Preview::Fault::Failure Status) -> Net::awaitable<Preview::Fault::Failure>
    {
        if (!Connection)
        {
            if (Status.Failed()) co_return Status;
            co_return Preview::Protocol::Common::FailureFromProtocolError(Error::NotOpen);
        }

        const auto Reply = co_await Connection->SendConnectReply(ToReplyCode(Status.Code));
        auto Failure = Preview::Fault::Failure{};
        if (!Reply)
        {
            (void)Preview::Diagnose::Warn(Trace, "Socks5ConnectReplyWriteFailed Action=Close");
            if (Reply.error().Transport.Failed())
            {
                Failure = Reply.error().Transport;
            }
            else if (Reply.error().Protocol != Error::None)
            {
                Failure = Preview::Protocol::Common::FailureFromProtocolError(
                    Reply.error().Protocol);
            }
            else
            {
                Failure = {Preview::Fault::Code::IoError};
            }
        }
        if (Status.Failed() || Failure.Failed())
        {
            const auto Closed = Connection->Close();
            if (!Failure.Failed() && !Closed)
            {
                Failure = Closed.error();
            }
        }
        co_return Failure;
    }

} // namespace Preview::Socks5
