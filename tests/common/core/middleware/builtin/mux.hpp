/**
 * @file mux.hpp
 * @brief 多路复用引导中间件
 * @details 当目标命中 mux 配置时，将 inbound 包装为多路复用
 * 会话（smux/yamux/h2mux）。对应生产库 forward_pipeline 的
 * spawn_mux_session 分支的中间件化。
 * @note 完整 mux 引导（multiplex::bootstrap）依赖协议 multiplexer，
 *       本文件先定义中间件骨架，注入引导函数。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <string_view>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::middleware::builtin
{

    namespace net = boost::asio;

    /**
     * @class mux_middleware
     * @brief 多路复用引导中间件
     * @details 调用注入的 mux 引导函数（可注入测试实现），
     * 将 inbound 包装为 mux 会话。
     */
    class mux_middleware final : public middleware
    {
    public:
        /// mux 引导函数签名（inbound → 是否成功）
        using mux_fn =
            std::function<net::awaitable<bool>(psmtest::shared_transmission &, context &)>;

        /**
         * @brief 构造函数
         * @param mux 引导函数（默认不启用 mux）
         */
        explicit mux_middleware(mux_fn mux = {}) : mux_(std::move(mux))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "mux";
        }

        /**
         * @brief 尝试 mux 引导
         * @param inbound 入站传输（可被包装）
         * @param ctx 管线上下文
         * @return success = mux 已接管（管线终止）；not_supported = 未启用
         */
        auto handle(psmtest::shared_transmission &inbound, context &ctx)
            -> net::awaitable<psmtest::fault::code> override
        {
            if (!mux_)
            {
                co_return psmtest::fault::code::not_supported;
            }
            const auto ok = co_await mux_(inbound, ctx);
            co_return ok ? psmtest::fault::code::success : psmtest::fault::code::bad_gateway;
        }

    private:
        mux_fn mux_; ///< mux 引导函数（可注入）
    };

} // namespace psmtest::middleware::builtin
