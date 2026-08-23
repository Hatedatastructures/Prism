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
#include <common/core/diagnose/log.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/builtin/auth.hpp>
#include <common/core/middleware/builtin/dial.hpp>
#include <common/core/middleware/builtin/mux.hpp>
#include <common/core/middleware/builtin/pad.hpp>
#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/recognition/recognition.hpp>
#include <common/core/transmission.hpp>

namespace preview::runtime
{

    namespace net = boost::asio;

    /**
     * @struct session_options
     * @brief 会话编排选项
     */
    struct session_options
    {
        /// 协议接入函数：完成握手并将入站传输替换为协议数据连接
        using protocol_accept_fn = std::function<net::awaitable<
            preview::fault::code>(preview::shared_transmission &,
                                  preview::middleware::context &)>;

        /// SNI 路由表（可选，TLS 分流）
        preview::recognition::sni_route_table *routes{nullptr};
        /// 认证器（可选；缺省跳过认证）
        preview::shared_authenticator auth{};
        /// 中继空闲超时（0 = 禁用）
        std::chrono::milliseconds relay_idle_timeout{std::chrono::seconds(60)};
        /// 协议接入函数（可选；缺省保留识别后的原始传输）
        protocol_accept_fn accept_protocol{};
        /// 装配回调：按识别结果填充 ctx（target/凭据）；返回非 success 终止
        std::function<net::awaitable<preview::fault::code>(
            const preview::recognition::recognize_result &, preview::middleware::context &)>
            prepare{};
        /// 多路复用引导函数（可选；缺省直通）
        preview::middleware::builtin::mux_middleware::mux_fn mux{};
        /// 填充配置（可选；缺省不填充）
        const preview::middleware::context::pad_config *pad{nullptr};
        /// 拨号函数（缺省 dial 中间件返回 not_supported）
        preview::middleware::builtin::dial_middleware::dial_fn dial{};
        /// dgram 会话服务（ctx.is_dgram 时替代 dial/relay；协议无关）
        std::function<net::awaitable<preview::fault::code>(
            preview::middleware::context &)>
            udp_service{};
        /// 流量统计 sink（relay 结束点上报）
        preview::middleware::context::traffic_sink *traffic{nullptr};
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
        [[nodiscard]] auto run(preview::shared_transmission inbound) -> net::awaitable<preview::fault::code>
        {
            // 1. 协议识别（预读回注）
            preview::recognition::pipeline recog(opts_.routes);
            auto res = co_await recog.recognize(std::move(inbound));
            // 协议专用 listener：已配置 accept_protocol 时，recognition 仅负责预读回注，
            // 是否识别成功交给 accept_protocol 决定（Trojan/SS2022 等首字节不可识别）。
            if (!opts_.accept_protocol)
            {
                if (!res.success || res.detected == preview::recognition::protocol_type::unknown)
                {
                    co_return preview::fault::code::protocol_error;
                }
            }

            // 2. 上下文装配
            preview::middleware::context ctx;
            ctx.detected = static_cast<std::uint16_t>(res.detected);
            ctx.inbound = std::move(res.transport);
            ctx.traffic = opts_.traffic;
            ctx.pad = opts_.pad;
            if (opts_.accept_protocol)
            {
                auto protocol_guard = ctx.inbound;
                const auto ec =
                    co_await opts_.accept_protocol(ctx.inbound, ctx);
                if (preview::fault::failed(ec))
                {
                    if (protocol_guard)
                    {
                        protocol_guard->close();
                    }
                    if (ctx.inbound)
                    {
                        ctx.inbound->close();
                    }
                    co_return ec;
                }
                protocol_guard.reset();
            }
            if (opts_.prepare)
            {
                const auto ec = co_await opts_.prepare(res, ctx);
                if (preview::fault::failed(ec))
                {
                    // 与 accept_protocol 失败路径对称：装配终止时显式收口入站传输
                    if (ctx.inbound)
                    {
                        ctx.inbound->close();
                    }
                    co_return ec;
                }
            }

            // 3. dgram 会话（UDP 数据面，替代 dial/relay 编排）
            if (ctx.is_dgram)
            {
                if (!opts_.udp_service)
                {
                    if (ctx.inbound)
                    {
                        ctx.inbound->close();
                    }
                    co_return preview::fault::code::not_supported;
                }
                co_return co_await opts_.udp_service(ctx);
            }

            // 4. 认证 + 多路复用 + 拨号（不含 relay）
            if (opts_.accept_protocol && opts_.auth)
            {
                // 适配器未回填 raw_identity：已通过协议认证的会话会被 auth
                // 中间件再次拒绝，属配置矛盾，提前告警便于定位
                preview::diagnose::warn("accept_protocol 与 auth 中间件同时配置："
                                        "适配器未回填 raw_identity，已通过协议认证的会话将被拒绝");
            }
            preview::middleware::pipeline pipe;
            if (opts_.auth)
            {
                pipe.add(std::make_shared<preview::middleware::builtin::auth_middleware>(opts_.auth));
            }
            pipe.add(std::make_shared<preview::middleware::builtin::mux_middleware>(opts_.mux));
            pipe.add(std::make_shared<preview::middleware::builtin::pad_middleware>());
            pipe.add(std::make_shared<preview::middleware::builtin::dial_middleware>(opts_.dial));
            const auto dial_ec = co_await pipe.run(ctx.inbound, ctx);
            if (preview::fault::failed(dial_ec))
            {
                if (ctx.post_dial)
                {
                    co_await ctx.post_dial(dial_ec);
                }
                co_return dial_ec;
            }
            // 5. 拨号成功后发送协议级应答（如 SOCKS5 CONNECT success）
            if (ctx.post_dial)
            {
                co_await ctx.post_dial(preview::fault::code::success);
            }
            // 6. 双向转发
            preview::middleware::builtin::relay_middleware relay(
                nullptr, opts_.relay_idle_timeout);
            co_return co_await relay.handle(ctx.inbound, ctx);
        }

    private:
        session_options opts_; ///< 编排选项
    };

} // namespace preview::runtime
