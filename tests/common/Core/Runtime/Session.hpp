/**
 * @file Session.hpp
 * @brief 会话编排（T4-2）
 * @details 把协议识别 → 上下文装配 → 中间件管线串成完整会话：
 *          1. Recognition::Pipeline 探测协议类型（预读回注）
 *          2. Prepare 回调按识别结果装配 Target / 凭据
 *          3. Middleware 管线：Auth（可选）→ Dial → relay
 *          - 识别失败 / 未知协议 → protocol_error
 *          - 认证失败 → auth_failed（管线终止）
 *          - relay 结束点自动上报流量（traffic sink）
 * @note 对应生产 Session::diversion；协议握手由各协议 Conn 承担
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

#include <common/Core/Authenticator.hpp>
#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Builtin/Auth.hpp>
#include <common/Core/Middleware/Builtin/Dial.hpp>
#include <common/Core/Middleware/Builtin/Mux.hpp>
#include <common/Core/Middleware/Builtin/Pad.hpp>
#include <common/Core/Middleware/Builtin/Relay.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>
#include <common/Core/Recognition/Recognition.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Runtime
{

    namespace net = boost::asio;

    /**
     * @struct SessionOptions
     * @brief 会话编排选项
     */
    struct SessionOptions
    {
        /// 协议接入函数：完成握手并将入站传输替换为协议数据连接
        using ProtocolAcceptFn = std::function<net::awaitable<
            Preview::Fault::Code>(Preview::SharedTransmission &,
                                  Preview::Middleware::Context &)>;

        /// SNI 路由表（可选，TLS 分流）
        Preview::Recognition::SniRouteTable *routes{nullptr};
        /// 认证器（可选；缺省跳过认证）
        Preview::SharedAuthenticator Auth{};
        /// 中继空闲超时（0 = 禁用）
        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        /// 协议接入函数（可选；缺省保留识别后的原始传输）
        ProtocolAcceptFn AcceptProtocol{};
        /// 装配回调：按识别结果填充 ctx（Target/凭据）；返回非 success 终止
        std::function<net::awaitable<Preview::Fault::Code>(
            const Preview::Recognition::RecognizeResult &, Preview::Middleware::Context &)>
            Prepare{};
        /// 多路复用引导函数（可选；缺省直通）
        Preview::Middleware::Builtin::MuxMiddleware::MuxFn mux{};
        /// 填充配置（可选；缺省不填充）
        const Preview::Middleware::Context::PadConfig *pad{nullptr};
        /// 拨号函数（缺省 Dial 中间件返回 not_supported）
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        /// Dgram 会话服务（ctx.IsDgram 时替代 Dial/relay；协议无关）
        std::function<net::awaitable<Preview::Fault::Code>(
            Preview::Middleware::Context &)>
            udp_service{};
        /// 流量统计 sink（relay 结束点上报）
        Preview::Middleware::Context::TrafficSink *traffic{nullptr};
    };

    /**
     * @class Session
     * @brief 单连接会话编排
     * @details 识别 → 装配 → 管线（Auth/Dial/relay）。
     *          每个连接构造一次，Run() 结束后销毁。
     */
    class Session
    {
    public:
        /**
         * @brief 构造
         * @param opts 编排选项
         */
        explicit Session(SessionOptions opts) : Opts_(std::move(opts))
        {
        }

        /**
         * @brief 运行会话
         * @param Inbound 入站传输
         * @return 最终错误码（success = 隧道正常结束）
         */
        [[nodiscard]] auto Run(Preview::SharedTransmission Inbound) -> net::awaitable<Preview::Fault::Code>
        {
            // 1. 协议识别（预读回注）
            Preview::Recognition::Pipeline recog(Opts_.routes);
            auto Res = co_await recog.Recognize(std::move(Inbound));
            // 协议专用 listener：已配置 AcceptProtocol 时，recognition 仅负责预读回注，
            // 是否识别成功交给 AcceptProtocol 决定（Trojan/SS2022 等首字节不可识别）。
            if (!Opts_.AcceptProtocol)
            {
                if (!Res.success || Res.detected == Preview::Recognition::ProtocolType::Unknown)
                {
                    co_return Preview::Fault::Code::ProtocolError;
                }
            }

            // 2. 上下文装配
            Preview::Middleware::Context ctx;
            ctx.detected = static_cast<std::uint16_t>(Res.detected);
            ctx.Inbound = std::move(Res.transport);
            ctx.traffic = Opts_.traffic;
            ctx.pad = Opts_.pad;
            if (Opts_.AcceptProtocol)
            {
                auto ProtocolGuard = ctx.Inbound;
                const auto Ec =
                    co_await Opts_.AcceptProtocol(ctx.Inbound, ctx);
                if (Preview::Fault::Failed(Ec))
                {
                    if (ProtocolGuard)
                    {
                        ProtocolGuard->Close();
                    }
                    if (ctx.Inbound)
                    {
                        ctx.Inbound->Close();
                    }
                    co_return Ec;
                }
                ProtocolGuard.reset();
            }
            if (Opts_.Prepare)
            {
                const auto Ec = co_await Opts_.Prepare(Res, ctx);
                if (Preview::Fault::Failed(Ec))
                {
                    // 与 AcceptProtocol 失败路径对称：装配终止时显式收口入站传输
                    if (ctx.Inbound)
                    {
                        ctx.Inbound->Close();
                    }
                    co_return Ec;
                }
            }

            // 3. Dgram 会话（UDP 数据面，替代 Dial/relay 编排）
            if (ctx.IsDgram)
            {
                if (!Opts_.udp_service)
                {
                    if (ctx.Inbound)
                    {
                        ctx.Inbound->Close();
                    }
                    co_return Preview::Fault::Code::NotSupported;
                }
                co_return co_await Opts_.udp_service(ctx);
            }

            // 4. 认证 + 多路复用 + 拨号（不含 relay）
            if (Opts_.AcceptProtocol && Opts_.Auth)
            {
                // 适配器未回填 RawIdentity：已通过协议认证的会话会被 Auth
                // 中间件再次拒绝，属配置矛盾，提前告警便于定位
                Preview::Diagnose::Warn("AcceptProtocol 与 Auth 中间件同时配置："
                                        "适配器未回填 RawIdentity，已通过协议认证的会话将被拒绝");
            }
            Preview::Middleware::Pipeline pipe;
            if (Opts_.Auth)
            {
                pipe.Add(std::make_shared<Preview::Middleware::Builtin::AuthMiddleware>(Opts_.Auth));
            }
            pipe.Add(std::make_shared<Preview::Middleware::Builtin::MuxMiddleware>(Opts_.mux));
            pipe.Add(std::make_shared<Preview::Middleware::Builtin::PadMiddleware>());
            pipe.Add(std::make_shared<Preview::Middleware::Builtin::DialMiddleware>(Opts_.Dial));
            const auto DialEc = co_await pipe.Run(ctx.Inbound, ctx);
            if (Preview::Fault::Failed(DialEc))
            {
                if (ctx.PostDial)
                {
                    co_await ctx.PostDial(DialEc);
                }
                co_return DialEc;
            }
            // 5. 拨号成功后发送协议级应答（如 SOCKS5 CONNECT success）
            if (ctx.PostDial)
            {
                co_await ctx.PostDial(Preview::Fault::Code::Success);
            }
            // 6. 双向转发
            Preview::Middleware::Builtin::RelayMiddleware relay(
                nullptr, Opts_.RelayIdleTimeout);
            co_return co_await relay.Handle(ctx.Inbound, ctx);
        }

    private:
        SessionOptions Opts_; ///< 编排选项
    };

} // namespace Preview::Runtime
