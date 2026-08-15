/**
 * @file pipeline.hpp
 * @brief 中间件管线编排
 * @details 按顺序执行中间件链，每个中间件可包装/替换/拒绝
 * 入站传输。对应生产库 forward_pipeline 的显式化：
 *   forward_pipeline 硬编码：dial → mux → pad → relay
 *   本管线：pipeline.add<X>().add<Y>().run(inbound, ctx)
 * @note 中间件实现 transport 的"装饰器"语义：输入 inbound，
 *       输出（可能包装后的）inbound。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/transport/transmission.hpp>

namespace psm::middleware
{

    namespace net = boost::asio;

    /**
     * @class middleware
     * @brief 中间件基类
     * @details 每个中间件一个职责：
     * - dial：拨号上游（消费 ctx.target，产出 outbound）
     * - mux：多路复用引导（包装 inbound）
     * - pad：填充包装（包装 inbound）
     * - relay：双向转发（消费 inbound+outbound）
     */
    class middleware
    {
    public:
        virtual ~middleware() = default;

        /**
         * @brief 获取中间件名称（诊断用）
         * @return 名称
         */
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;

        /**
         * @brief 处理入站传输
         * @param inbound 入站传输（可包装/替换/拒绝）
         * @param ctx 管线上下文
         * @return 处理后的错误码（success = 继续下一中间件）
         */
        virtual auto handle(psm::transport::shared_transmission &inbound, context &ctx)
            -> net::awaitable<psm::fault::code> = 0;
    };

    /// 中间件共享指针
    using shared_middleware = std::shared_ptr<middleware>;

    /**
     * @class pipeline
     * @brief 中间件管线
     * @details 按添加顺序执行中间件。任一中间件返回非 success
     * 即终止管线（拒绝连接）。
     */
    class pipeline
    {
    public:
        /**
         * @brief 追加中间件
         * @param mw 中间件（所有权移交）
         * @return 管线自身（链式调用）
         */
        auto add(shared_middleware mw) -> pipeline &
        {
            chain_.push_back(std::move(mw));
            return *this;
        }

        /**
         * @brief 执行管线
         * @param inbound 入站传输（可被中间件包装）
         * @param ctx 管线上下文
         * @return 最终错误码（success = 全部通过）
         */
        auto run(psm::transport::shared_transmission inbound, context &ctx)
            -> net::awaitable<psm::fault::code>
        {
            for (const auto &mw : chain_)
            {
                const auto ec = co_await mw->handle(inbound, ctx);
                if (psm::fault::failed(ec))
                {
                    co_return ec;
                }
            }
            ctx.inbound = std::move(inbound);
            co_return psm::fault::code::success;
        }

    private:
        std::vector<shared_middleware> chain_; ///< 中间件链
    };

} // namespace psm::middleware
