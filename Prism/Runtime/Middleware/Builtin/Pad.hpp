/**
 * @file Pad.hpp
 * @brief 填充中间件
 * @details 当配置启用填充且协议不自带帧语义时，将 Inbound
 * 包装为 PadTransport（流量填充）。对应生产库 forward_pipeline
 * 的 pad 注入分支。
 * @note 完整 PadTransport 实现见 Prism/Transport/Pad.hpp。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Transport/Pad.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Middleware::Builtin
{

    namespace Net = boost::asio;

    /**
     * @class PadMiddleware
     * @brief 填充中间件
     * @details 根据 Operation.Pad 配置决定是否包装 PadTransport。
     */
    class PadMiddleware final : public Middleware
    {
    public:
        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "pad";
        }

        /**
         * @brief 按配置包装填充传输
         * @param Inbound 借用至完成的入站传输；启用时由 PadTransport 接收原传输所有权。
         * @param Operation 借用至完成的管线上下文；只读消费已编译 pad 配置与 worker byte pool。
         * @return 正式失败值；配置或资源错误保留其领域码。
         * @note 在调用方 executor 执行；不独立取消或关闭传输，最终关闭由 Session relay owner 负责。
         */
        auto Handle(Prism::SharedTransmission &Inbound, Context &Operation)
            -> Net::awaitable<Prism::Fault::Failure> override
        {
            if (Operation.Pad && Operation.Pad->Enabled && Inbound)
            {
                if (!Operation.Pad->Policy || !Operation.Bytes)
                    co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
                Inbound = std::make_shared<Prism::Transport::PadTransport>(std::move(Inbound),
                    Prism::Transport::PadOptions{Operation.Pad->Policy, Operation.Bytes, {}});
            }
            co_return Prism::Fault::Failure{};
        }
    };

} // namespace Prism::Middleware::Builtin
