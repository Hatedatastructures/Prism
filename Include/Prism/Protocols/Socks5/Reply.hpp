/**
 * @file Reply.hpp
 * @brief SOCKS5 延迟 CONNECT 应答的协议拥有者
 * @details Fault 错误到 SOCKS5 wire 应答的映射，以及拨号完成后的
 *          CONNECT 应答写入和关闭语义均由协议模块拥有。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>

namespace Prism::Socks5
{

    namespace Net = boost::asio;

    /**
     * @brief 将运行时拨号错误转换为 SOCKS5 CONNECT 响应码
     * @param Status 运行时拨号状态
     * @return RFC 1928 BND 响应码
     */
    [[nodiscard]] auto ToReplyCode(Prism::Fault::Code Status) -> ReplyCode;

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
    [[nodiscard]] auto SendConnectDeferredReply(
        std::shared_ptr<Conn<>> Connection,
        Prism::Diagnose::ContextState Trace,
        Prism::Fault::Failure Status) -> Net::awaitable<Prism::Fault::Failure>;

} // namespace Prism::Socks5
