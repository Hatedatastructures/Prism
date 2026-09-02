/**
 * @file Mux.hpp
 * @brief 多路复用引导中间件
 * @details 当目标命中 mux 配置时，将 Inbound 包装为多路复用
 * 会话（smux/yamux/h2mux）。对应生产库 forward_pipeline 的
 * spawn_mux_session 分支的中间件化。
 * @note 完整 mux 引导（multiplex::bootstrap）依赖协议 multiplexer，
 *       本文件先定义中间件骨架，注入引导函数。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <string_view>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Middleware::Builtin
{

    namespace net = boost::asio;

    /**
     * @class MuxMiddleware
     * @brief 多路复用引导中间件
     * @details 调用注入的 mux 引导函数（可注入测试实现），
     * 将 Inbound 包装为 mux 会话。
     */
    class MuxMiddleware final : public Middleware
    {
    public:
        /// mux 引导函数签名（Inbound → 是否成功）
        using MuxFn =
            std::function<net::awaitable<bool>(Preview::SharedTransmission &, Context &)>;

        /**
         * @brief 构造函数
         * @param mux 引导函数（默认不启用 mux）
         */
        explicit MuxMiddleware(MuxFn mux = {}) : Mux_(std::move(mux))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "mux";
        }

        /**
         * @brief 尝试 mux 引导
         * @param Inbound 入站传输（可被包装）
         * @param ctx 管线上下文
         * @return success = mux 已接管（管线终止）；not_supported = 未启用
         */
        auto Handle(Preview::SharedTransmission &Inbound, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            if (!Mux_)
            {
                co_return Preview::Fault::Code::Success;
            }
            const auto Ok = co_await Mux_(Inbound, ctx);
            if (Ok)
            {
                co_return Preview::Fault::Code::Success;
            }
            co_return Preview::Fault::Code::BadGateway;
        }

    private:
        MuxFn Mux_; ///< mux 引导函数（可注入）
    };

} // namespace Preview::Middleware::Builtin
