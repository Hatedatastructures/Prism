/**
 * @file Dial.hpp
 * @brief 拨号中间件
 * @details 消费 ctx.Target()，拨号建立上游传输并注入管线上下文。
 * 支持注入自定义拨号函数（测试用内存实现 / 生产用已编译拨号绑定）。
 * 对应生产库 net/connection/Outbound/Dial 的中间件化。
 */

#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <functional>
#include <string_view>

namespace Prism::Middleware::Builtin
{

    namespace Net = boost::asio;

    /**
     * @class DialMiddleware
     * @brief 拨号中间件
     * @details 调用拨号函数（可注入）建立上游传输，将结果写入
     * ctx 供后续 relay 中间件消费。
     */
    class DialMiddleware final : public Middleware
    {
    public:
        /// 拨号函数签名（typed 目标 → owning 传输；失败保留领域码与原生 cause）
        using DialFn =
            std::function<Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>(
                const Prism::Network::Target&)>;

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
         * @return 正式失败值；拨号错误的领域码和原生 cause 原样保留。
         * @note 拨号协程在调用 executor 执行；取消沿 awaitable 传递。成功的 owning 传输移交 Context，最终关闭由 Session relay owner 负责。
         */
        auto Handle(Prism::SharedTransmission& /*Inbound*/, Context& ctx)
            -> Net::awaitable<Prism::Fault::Failure> override
        {
            if (!Dial_)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
            }
            auto Result = co_await Dial_(ctx.Target());
            if (!Result)
            {
                co_return Result.error();
            }
            if (!*Result)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::BadGateway};
            }
            ctx.Outbound = std::move(*Result);
            co_return Prism::Fault::Failure{};
        }

    private:
        DialFn Dial_; ///< 拨号函数（可注入）
    };

} // namespace Prism::Middleware::Builtin
