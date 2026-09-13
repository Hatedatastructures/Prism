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

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Builtin/Auth.hpp>
#include <preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <preview/Runtime/Middleware/Builtin/Mux.hpp>
#include <preview/Runtime/Middleware/Builtin/Pad.hpp>
#include <preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    /**
     * @struct SessionOptions
     * @brief 会话编排选项
     */
    struct SessionOptions
    {
        /// 协议接入函数：完成握手并将入站传输替换为协议数据连接
        using ProtocolAcceptFn = std::function<Net::awaitable<
            Preview::Fault::Code>(Preview::SharedTransmission &,
                                  Preview::Middleware::Context &)>;

        /// 按识别候选 ID 解析 winner-only 协议接入函数
        using ResolveCandidateFn = std::function<ProtocolAcceptFn(Preview::Recognition::CandidateId)>;

        /// SNI 路由表（可选，TLS 分流）
        Preview::Recognition::SniRouteTable *routes{nullptr};
        /// 伪装方案执行器（可选；由启动层拥有）
        Preview::Recognition::SchemeExecutor *Scheme{nullptr};
        /// 认证器（可选；缺省跳过认证）
        Preview::SharedAuthenticator Auth{};
        /// 中继空闲超时（0 = 禁用）
        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        /// 协议接入函数（可选；缺省保留识别后的原始传输）
        ProtocolAcceptFn AcceptProtocol{};
        /// Profile 路径的不可变候选配置
        Preview::Recognition::SharedProfile Profile{};
        /// Profile 路径按 CandidateId 解析接入函数；仅 winner 调用一次
        ResolveCandidateFn ResolveCandidate{};
        /// Resolver 命名兼容别名；Profile 路径优先使用 ResolveCandidate
        ResolveCandidateFn Resolver{};
        /// 装配回调：按识别结果填充 ctx（Target/凭据）；返回非 success 终止
        std::function<Net::awaitable<Preview::Fault::Code>(
            const Preview::Recognition::RecognizeResult &, Preview::Middleware::Context &)>
            Prepare{};
        /// 多路复用引导函数（可选；缺省直通）
        Preview::Middleware::Builtin::MuxMiddleware::MuxFn mux{};
        /// 填充配置（可选；缺省不填充）
        const Preview::Middleware::Context::PadConfig *pad{nullptr};
        /// 拨号函数（缺省 Dial 中间件返回 not_supported）
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        /// Dgram 会话服务（ctx.IsDgram 时替代 Dial/relay；协议无关）
        std::function<Net::awaitable<Preview::Fault::Code>(
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
         * @param Options 编排选项
         */
        explicit Session(SessionOptions Options) : Opts_(std::move(Options))
        {
        }

        /**
         * @brief 运行会话
         * @param Inbound 入站传输
         * @return 最终错误码（success = 隧道正常结束）
         */
        [[nodiscard]] auto Run(
            Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::Fault::Code>
        {
            // 1. 协议识别（预读回注）
            Preview::Recognition::Pipeline Recognizer(Opts_.routes, Opts_.Scheme);
            if (Opts_.Profile)
            {
                Recognizer = Preview::Recognition::Pipeline(Opts_.Profile);
            }
            auto Res = co_await Recognizer.Recognize(std::move(Inbound));
            SessionOptions::ProtocolAcceptFn Acceptor;
            if (Opts_.Profile)
            {
                if (!Res.success || Res.Status != Preview::Recognition::RecognitionStatus::Accepted ||
                    Res.Candidate == Preview::Recognition::InvalidCandidate)
                {
                    CloseTransport(Res.transport);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                SessionOptions::ResolveCandidateFn Resolver;
                if (Opts_.ResolveCandidate)
                {
                    Resolver = Opts_.ResolveCandidate;
                }
                else
                {
                    Resolver = Opts_.Resolver;
                }
                if (Resolver)
                {
                    Acceptor = Resolver(Res.Candidate);
                }
                if (!Acceptor)
                {
                    CloseTransport(Res.transport);
                    co_return Preview::Fault::Code::ProtocolError;
                }
            }
            else
            {
                // 协议专用 listener：已配置 AcceptProtocol 时，recognition 仅负责预读回注，
                // 是否识别成功交给 AcceptProtocol 决定（Trojan/SS2022 等首字节不可识别）。
                if (!Opts_.AcceptProtocol &&
                    (!Res.success || Res.detected == Preview::Recognition::ProtocolType::Unknown))
                {
                    CloseTransport(Res.transport);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                Acceptor = Opts_.AcceptProtocol;
            }

            // 2. 上下文装配
            Preview::Middleware::Context ctx;
            ctx.detected = static_cast<std::uint16_t>(Res.detected);
            ctx.Inbound = std::move(Res.transport);
            ctx.traffic = Opts_.traffic;
            ctx.pad = Opts_.pad;
            if (Acceptor)
            {
                auto ProtocolGuard = ctx.Inbound;
                const auto Ec = co_await Acceptor(ctx.Inbound, ctx);
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
            if (!Opts_.Profile && Opts_.AcceptProtocol && Opts_.Auth && !ctx.ProtocolAuthenticated)
            {
                // 未完成协议认证的 legacy adapter 仍需提供 RawIdentity/RawSecret，
                // 否则通用 Auth 中间件会拒绝该会话。
                Preview::Diagnose::Warn("AcceptProtocol 与 Auth 中间件同时配置："
                                        "未认证 adapter 必须回填 RawIdentity/RawSecret");
            }
            Preview::Middleware::Pipeline pipe;
            // 协议 handler 已完成凭据校验时，协议认证是本会话的权威认证结果；
            // 只有未提供协议认证的入口才追加通用 Auth 中间件，避免二次认证清空 identity/lease。
            if (Opts_.Auth && !ctx.ProtocolAuthenticated)
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
                CloseTransport(ctx.Inbound);
                CloseTransport(ctx.Outbound);
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
        static auto CloseTransport(Preview::SharedTransmission Transport) -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        SessionOptions Opts_; ///< 编排选项
    };

} // namespace Preview::Runtime
