/**
 * @file session.hpp
 * @brief 会话编排（T4-2）
 * @details 把协议识别 → 上下文装配 → 中间件管线串成完整会话：
 *          1. recognition::pipeline 探测协议类型（预读回注）
 *          2. prepare 回调按识别结果装配 target / 凭据
 *          3. middleware 管线：auth（可选）→ dial → relay
 *          - 识别失败 / 未知协议 → protocol_error
 *          - 认证失败 → auth_failed（管线终止）
 *          - relay 结束点自动上报流量（traffic sink）
 * @note 对应生产 session::diversion；协议握手由各协议 conn 承担
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

#include <common/core/authenticator.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/builtin/auth.hpp>
#include <common/core/middleware/builtin/dial.hpp>
#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/recognition/recognition.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::runtime
{

    namespace net = boost::asio;

    /**
     * @struct session_options
     * @brief 会话编排选项
     */
    struct session_options
    {
        /// SNI 路由表（可选，TLS 分流）
        psmtest::recognition::route_table *routes{nullptr};
        /// 认证器（可选；缺省跳过认证）
        psmtest::shared_authenticator auth{};
        /// 中继空闲超时（0 = 禁用）
        std::chrono::milliseconds relay_idle_timeout{std::chrono::seconds(60)};
        /// 装配回调：按识别结果填充 ctx（target/凭据）；返回非 success 终止
        std::function<net::awaitable<psmtest::fault::code>(
            const psmtest::recognition::recognize_result &, psmtest::middleware::context &)>
            prepare{};
        /// 拨号函数（缺省 dial 中间件返回 not_supported）
        psmtest::middleware::builtin::dial_middleware::dial_fn dial{};
        /// 流量统计 sink（relay 结束点上报）
        psmtest::middleware::context::traffic_sink *traffic{nullptr};
    };

    /**
     * @class session
     * @brief 单连接会话编排
     * @details 识别 → 装配 → 管线（auth/dial/relay）。
     *          每个连接构造一次，run() 结束后销毁。
     */
    class session
    {
    public:
        /**
         * @brief 构造
         * @param opts 编排选项
         */
        explicit session(session_options opts) : opts_(std::move(opts))
        {
        }

        /**
         * @brief 运行会话
         * @param inbound 入站传输
         * @return 最终错误码（success = 隧道正常结束）
         */
        [[nodiscard]] auto run(psmtest::shared_transmission inbound) -> net::awaitable<psmtest::fault::code>
        {
            // 1. 协议识别
            psmtest::recognition::pipeline recog(opts_.routes);
            auto res = co_await recog.recognize(std::move(inbound));
            if (!res.success || res.detected == psmtest::recognition::protocol_type::unknown)
            {
                co_return psmtest::fault::code::protocol_error;
            }

            // 2. 上下文装配
            psmtest::middleware::context ctx;
            ctx.detected = static_cast<std::uint16_t>(res.detected);
            ctx.inbound = std::move(res.transport);
            ctx.traffic = opts_.traffic;
            if (opts_.prepare)
            {
                const auto ec = co_await opts_.prepare(res, ctx);
                if (psmtest::fault::failed(ec))
                {
                    co_return ec;
                }
            }

            // 3. 中间件管线：auth → dial → relay
            psmtest::middleware::pipeline pipe;
            if (opts_.auth)
            {
                pipe.add(std::make_shared<psmtest::middleware::builtin::auth_middleware>(opts_.auth));
            }
            pipe.add(std::make_shared<psmtest::middleware::builtin::dial_middleware>(opts_.dial));
            pipe.add(std::make_shared<psmtest::middleware::builtin::relay_middleware>(
                nullptr, opts_.relay_idle_timeout));
            co_return co_await pipe.run(ctx.inbound, ctx);
        }

    private:
        session_options opts_; ///< 编排选项
    };

} // namespace psmtest::runtime
