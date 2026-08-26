/**
 * @file Pad.hpp
 * @brief 填充中间件
 * @details 当配置启用填充且协议不自带帧语义时，将 Inbound
 * 包装为 PadTransport（流量填充）。对应生产库 forward_pipeline
 * 的 pad 注入分支。
 * @note 完整 PadTransport 实现见 common/Core/Transport/Pad.hpp。
 */

#pragma once

#include <string_view>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>
#include <common/Core/Transport/Pad.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Middleware::Builtin
{

    /**
     * @class PadMiddleware
     * @brief 填充中间件
     * @details 根据 ctx.pad 配置决定是否包装 PadTransport。
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
         * @param Inbound 入站传输（可能被 pad 包装）
         * @param ctx 管线上下文（消费 pad 配置）
         * @return success 恒（pad 是可选装饰）
         */
        auto Handle(Preview::SharedTransmission &Inbound, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            if (ctx.pad && ctx.pad->Enabled && Inbound)
            {
                Preview::Transport::PadConfig cfg;
                cfg.PadTargets = "17,30-50,30-50,80-150";
                Inbound = std::make_shared<Preview::Transport::PadTransport>(Inbound, cfg);
            }
            co_return Preview::Fault::Code::Success;
        }
    };

} // namespace Preview::Middleware::Builtin
