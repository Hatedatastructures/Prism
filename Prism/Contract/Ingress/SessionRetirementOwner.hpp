/**
 * @file SessionRetirementOwner.hpp
 * @brief 成功接入后仍持有握手传输链的 session 退休 owner。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Contract::Ingress
{
    /**
     * @brief 为 root 数据面之外的 provider 接入资源提供 session 级最终关闭和 drain。
     * @details Runtime 在 root Run 结束并释放数据面 view 后调用 Drain，再退休共享 inbound。
     *          Drain 必须请求关闭并等待所有额外 carrier 的真实 Activity 退休；未完成时，
     *          实现保留 owner 与其原 executor，返回完整 typed failure，并允许并发 binding drain。
     */
    class SessionRetirementOwner
    {
    public:
        virtual ~SessionRetirementOwner() = default;

        /** @brief 请求关闭并 drain 此 session 独占的额外接入资源。 */
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
    };
}
