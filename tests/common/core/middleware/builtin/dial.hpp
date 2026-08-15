/**
 * @file dial.hpp
 * @brief 拨号中间件
 * @details 消费 ctx.target，拨号建立上游传输并注入管线上下文。
 * 支持注入自定义拨号函数（测试用内存实现 / 生产用 outbound::dial）。
 * 对应生产库 net/connection/outbound/dial 的中间件化。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <string_view>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/protocol/target.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::middleware::builtin
{

    namespace net = boost::asio;

    /**
     * @class dial_middleware
     * @brief 拨号中间件
     * @details 调用拨号函数（可注入）建立上游传输，将结果写入
     * ctx 供后续 relay 中间件消费。
     */
    class dial_middleware final : public middleware
    {
    public:
        /// 拨号函数签名（host:port → 传输）
        using dial_fn =
            std::function<net::awaitable<std::pair<psmtest::fault::code, psmtest::shared_transmission>>(
                const psmtest::connect::target &)>;

        /**
         * @brief 构造函数
         * @param dial 拨号函数（默认返回 not_supported，需注入）
         */
        explicit dial_middleware(dial_fn dial = {}) : dial_(std::move(dial))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "dial";
        }

        /**
         * @brief 拨号上游
         * @param inbound 入站传输（本中间件不改动）
         * @param ctx 管线上下文（消费 target）
         * @return 拨号结果码
         */
        auto handle(psmtest::shared_transmission & /*inbound*/, context &ctx)
            -> net::awaitable<psmtest::fault::code> override
        {
            if (!dial_)
            {
                co_return psmtest::fault::code::not_supported;
            }
            auto [ec, outbound] = co_await dial_(ctx.target);
            if (psmtest::fault::failed(ec) || !outbound)
            {
                co_return ec;
            }
            ctx.outbound = std::move(outbound);
            co_return psmtest::fault::code::success;
        }

    private:
        dial_fn dial_; ///< 拨号函数（可注入）
    };

} // namespace psmtest::middleware::builtin
