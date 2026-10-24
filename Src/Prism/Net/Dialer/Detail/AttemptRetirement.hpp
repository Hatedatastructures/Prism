/**
 * @file AttemptRetirement.hpp
 * @brief 提供等待拨号候选退栈的内部接收操作。
 */
#pragma once

#include <boost/asio/compose.hpp>
#include <boost/system/error_code.hpp>

#include <utility>

namespace Prism::Network::Dialer::Detail
{

    namespace Net = boost::asio;

    template <typename EventChannel>
    struct WaitUntilAttemptRetiredOperation final
    {
        EventChannel &Events;

        template <typename Self>
        auto operator()(Self &Handler) const -> void
        {
            Events.async_receive(std::move(Handler));
        }

        template <typename Self, typename Event>
        auto operator()(Self &Handler,
                        boost::system::error_code Error,
                        Event Received) const -> void
        {
            if (Error || Received.Retired)
            {
                Handler.complete(Error);
                return;
            }
            Events.async_receive(std::move(Handler));
        }
    };

    /**
     * @brief 读取竞速事件直到全部候选真实退栈。
     * @details 普通连接结果和总期限事件由竞速所有者处理；这里忽略它们并继续接收。
     *          取消错误直接完成操作，由竞速所有者取消候选，并在禁用取消后再次等待。
     * @param Events 拨号竞速唯一事件通道；结果、总期限和最终退栈都由该所有者排序。
     * @param Token 接收 `void(boost::system::error_code)` 完成结果的令牌；错误交还竞速所有者处理。
     * @return 仅当 `Retired` 事件到达或接收被取消时完成；执行器、分配器与取消槽关联
     *         由 `async_compose` 从调用令牌传播到通道接收。
     */
    template <typename EventChannel, typename CompletionToken>
    [[nodiscard]] auto WaitUntilAttemptRetired(
        EventChannel &Events, CompletionToken &&Token)
    {
        return Net::async_compose<CompletionToken, void(boost::system::error_code)>(
            WaitUntilAttemptRetiredOperation<EventChannel>{Events},
            Token, Events);
    }

} // namespace Prism::Network::Dialer::Detail
