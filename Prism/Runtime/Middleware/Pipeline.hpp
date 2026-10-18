/**
 * @file Pipeline.hpp
 * @brief 中间件管线编排
 * @details 按顺序执行中间件链，每个中间件可包装/替换/拒绝
 * 入站传输。对应生产库 forward_pipeline 的显式化：
 *   forward_pipeline 硬编码：Dial → mux → pad → relay
 *   本管线：Pipeline.Add<X>().Add<Y>().run(Inbound, ctx)
 * @note 中间件实现 transport 的"装饰器"语义：输入 Inbound，
 *       输出（可能包装后的）Inbound。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Middleware
{

    namespace Net = boost::asio;

    /**
     * @class Middleware
     * @brief 中间件基类
     * @details 每个中间件一个职责：
     * - Dial：拨号上游（消费 ctx.Target()，产出 Outbound）
     * - mux：多路复用引导（包装 Inbound）
     * - pad：填充包装（包装 Inbound）
     * - relay：双向转发（消费 Inbound+Outbound）
     */
    class Middleware
    {
    public:
        virtual ~Middleware() = default;

        /**
         * @brief 获取中间件名称（诊断用）
         * @return 名称
         */
        [[nodiscard]] virtual auto Name() const -> std::string_view = 0;

        /**
         * @brief 处理入站传输
         * @param Inbound 借用至 awaitable 完成的可变入站传输；装饰器可原地替换它。
         * @param ctx 借用至 awaitable 完成的会话上下文；不转移上下文或最终关闭权。
         * @return 正式失败值；Succeeded() 才继续，失败保留领域码与原生 cause。
         * @note 在调用方 executor 执行；取消由调用方协程传递，具体传输关闭和半关闭由实际 relay owner 完成。
         */
        virtual auto Handle(Prism::SharedTransmission& Inbound, Context& ctx)
            -> Net::awaitable<Prism::Fault::Failure> = 0;
    };

    /// 中间件共享指针
    using SharedMiddleware = std::shared_ptr<Middleware>;

    /**
     * @class Pipeline
     * @brief 中间件管线
     * @details 按添加顺序执行中间件。任一中间件返回非 success
     * 即终止管线（拒绝连接）。
     */
    class Pipeline
    {
    public:
        /**
         * @brief 追加中间件
         * @param mw 中间件（所有权移交）
         * @return 管线自身（链式调用）；Pipeline 持有已添加的中间件至自身销毁。
         */
        auto Add(SharedMiddleware mw) -> Pipeline&
        {
            Chain_.push_back(std::move(mw));
            return *this;
        }

        /**
         * @brief 执行管线
         * @param ctx 借用至完成的会话上下文，含唯一入站及出站传输事实。
         * @return 第一个失败值；全链通过时返回空 Failure。
         * @note 顺序在调用方 executor 上执行；取消沿当前 awaitable 传递；最终关闭和半关闭由 Session relay owner 负责。
         */
        auto Run(Context& ctx) -> Net::awaitable<Prism::Fault::Failure>
        {
            for (const auto& mw : Chain_)
            {
                const auto Failure = co_await mw->Handle(ctx.Inbound(), ctx);
                if (Failure.Failed())
                {
                    co_return Failure;
                }
            }
            co_return Prism::Fault::Failure{};
        }

    private:
        std::vector<SharedMiddleware> Chain_; ///< 中间件链
    };

} // namespace Prism::Middleware
