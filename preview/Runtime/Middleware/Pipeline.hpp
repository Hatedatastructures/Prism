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

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Middleware
{

    namespace net = boost::asio;

    /**
     * @class Middleware
     * @brief 中间件基类
     * @details 每个中间件一个职责：
     * - Dial：拨号上游（消费 ctx.Target，产出 Outbound）
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
         * @param Inbound 入站传输（可包装/替换/拒绝）
         * @param ctx 管线上下文
         * @return 处理后的错误码（success = 继续下一中间件）
         */
        virtual auto Handle(Preview::SharedTransmission &Inbound, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> = 0;
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
         * @return 管线自身（链式调用）
         */
        auto Add(SharedMiddleware mw) -> Pipeline &
        {
            Chain_.push_back(std::move(mw));
            return *this;
        }

        /**
         * @brief 执行管线
         * @param Inbound 入站传输（可被中间件包装）
         * @param ctx 管线上下文
         * @return 最终错误码（success = 全部通过）
         */
        auto Run(Preview::SharedTransmission Inbound, Context &ctx)
            -> net::awaitable<Preview::Fault::Code>
        {
            for (const auto &mw : Chain_)
            {
                const auto Ec = co_await mw->Handle(Inbound, ctx);
                if (Preview::Fault::Failed(Ec))
                {
                    co_return Ec;
                }
            }
            ctx.Inbound = std::move(Inbound);
            co_return Preview::Fault::Code::Success;
        }

    private:
        std::vector<SharedMiddleware> Chain_; ///< 中间件链
    };

} // namespace Preview::Middleware
