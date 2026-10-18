/**
 * @file CarrierBenchmarkWsFactory.hpp
 * @brief Layering 基准共享的 WebSocket carrier fixture owner。
 * @details 只提供 benchmark 的 client/server 正式 WS factory 绑定，不拥有测试用例、
 *          传输或 BytePool；BytePool 由 WsFactorySupport 在测试进程显式创建。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Transport/Transmission.hpp>
#include "CarrierBenchmarkTransportResult.hpp"

namespace Prism::Tests::Integration::Layering
{
    namespace Net = boost::asio;

    /**
     * @class CarrierBenchmarkWsFactory
     * @brief 三个 Layering benchmark 共用的 WebSocket 连接/接入 fixture。
     * @details 每次操作按值接管上游传输，并把其 executor 与测试 BytePool 交给正式 WS 工厂；
     *          返回的 Transmission 负责后续操作，取消、半关闭和 Close 仍由 WS ConnClose 转交。
     */
    class CarrierBenchmarkWsFactory final
    {
    public:
        /**
         * @brief 建立 benchmark 客户端 WS carrier。
         * @param Upstream 按值移交的上游传输 owner。
         * @return 唯一 expected 传输 owner；失败保留 Fault cause。
         * @details executor 继承 Upstream；连接取消、写半关闭和最终 Close 沿 WS Conn owner 转交。
         */
        [[nodiscard]] auto ClientConnect(Prism::SharedTransmission Upstream) const
            -> Net::awaitable<TransportResult>;

        /**
         * @brief 接受 benchmark 服务端 WS carrier。
         * @param Upstream 按值移交的上游传输 owner。
         * @return 唯一 expected 传输 owner；失败保留 Fault cause。
         * @details executor 继承 Upstream；连接取消、写半关闭和最终 Close 沿 WS Conn owner 转交。
         */
        [[nodiscard]] auto ServerAccept(Prism::SharedTransmission Upstream) const
            -> Net::awaitable<TransportResult>;
    };
} // namespace Prism::Tests::Integration::Layering
