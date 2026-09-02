/**
 * @file Dial.hpp
 * @brief 拨号中间件
 * @details 消费 ctx.Target，拨号建立上游传输并注入管线上下文。
 * 支持注入自定义拨号函数（测试用内存实现 / 生产用 Preview::Network::Outbound::Dial）。
 * 对应生产库 net/connection/Outbound/Dial 的中间件化。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <string_view>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Net/Target.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Middleware::Builtin
{

    namespace net = boost::asio;

    /**
     * @class DialMiddleware
     * @brief 拨号中间件
     * @details 调用拨号函数（可注入）建立上游传输，将结果写入
     * ctx 供后续 relay 中间件消费。
     */
    class DialMiddleware final : public Middleware
    {
    public:
        /// 拨号函数签名（host:port → 传输）
        using DialFn =
            std::function<net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>(
                const Preview::Network::Target &)>;

        /**
         * @brief 构造函数
         * @param Dial 拨号函数（默认返回 not_supported，需注入）
         */
        explicit DialMiddleware(DialFn Dial = {}) : Dial_(std::move(Dial))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "Dial";
        }

        /**
         * @brief 拨号上游
         * @param Inbound 入站传输（本中间件不改动）
         * @param ctx 管线上下文（消费 Target）
         * @return 拨号结果码
         */
        auto Handle(Preview::SharedTransmission & /*Inbound*/, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            if (!Dial_)
            {
                co_return Preview::Fault::Code::NotSupported;
            }
            auto [ec, Outbound] = co_await Dial_(ctx.Target);
            if (Preview::Fault::Failed(ec) || !Outbound)
            {
                co_return ec;
            }
            ctx.Outbound = std::move(Outbound);
            co_return Preview::Fault::Code::Success;
        }

    private:
        DialFn Dial_; ///< 拨号函数（可注入）
    };

} // namespace Preview::Middleware::Builtin
