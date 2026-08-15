/**
 * @file pad.hpp
 * @brief 填充中间件
 * @details 当配置启用填充且协议不自带帧语义时，将 inbound
 * 包装为 pad_transport（流量填充）。对应生产库 forward_pipeline
 * 的 pad 注入分支。
 * @note 完整 pad_transport 实现见 common/core/transport/pad.hpp。
 */

#pragma once

#include <string_view>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transport/pad.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::middleware::builtin
{

    /**
     * @class pad_middleware
     * @brief 填充中间件
     * @details 根据 ctx.pad 配置决定是否包装 pad_transport。
     */
    class pad_middleware final : public middleware
    {
    public:
        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "pad";
        }

        /**
         * @brief 按配置包装填充传输
         * @param inbound 入站传输（可能被 pad 包装）
         * @param ctx 管线上下文（消费 pad 配置）
         * @return success 恒（pad 是可选装饰）
         */
        auto handle(psmtest::shared_transmission &inbound, context &ctx)
            -> net::awaitable<psmtest::fault::code> override
        {
            if (ctx.pad && ctx.pad->enabled && inbound)
            {
                psmtest::transport::pad_config cfg;
                cfg.pad_targets = "17,30-50,30-50,80-150";
                inbound = std::make_shared<psmtest::transport::pad_transport>(inbound, cfg);
            }
            co_return psmtest::fault::code::success;
        }
    };

} // namespace psmtest::middleware::builtin
