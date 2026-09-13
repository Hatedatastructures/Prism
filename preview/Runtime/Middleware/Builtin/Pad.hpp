/**
 * @file Pad.hpp
 * @brief 填充中间件
 * @details 当配置启用填充且协议不自带帧语义时，将 Inbound
 * 包装为 PadTransport（流量填充）。对应生产库 forward_pipeline
 * 的 pad 注入分支。
 * @note 完整 PadTransport 实现见 preview/Transport/Pad.hpp。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Transport/Pad.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Middleware::Builtin
{

    namespace Net = boost::asio;

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
            -> Net::awaitable<Preview::Fault::Code> override
        {
            if (ctx.pad && ctx.pad->Enabled && Inbound)
            {
                Preview::Transport::PadConfig cfg;
                constexpr auto MaxTarget = static_cast<std::size_t>((std::numeric_limits<std::uint16_t>::max)());
                const auto MinSize = (std::min)(ctx.pad->MinSize, MaxTarget);
                const auto MaxSize = (std::min)((std::max)(MinSize, ctx.pad->MaxSize), MaxTarget);
                cfg.PadTargets = std::to_string(MinSize);
                if (MinSize != MaxSize)
                {
                    cfg.PadTargets += '-';
                    cfg.PadTargets += std::to_string(MaxSize);
                }
                cfg.MaxPadBytes = static_cast<std::uint16_t>(MaxSize);
                Inbound = std::make_shared<Preview::Transport::PadTransport>(Inbound, cfg);
            }
            co_return Preview::Fault::Code::Success;
        }
    };

} // namespace Preview::Middleware::Builtin
