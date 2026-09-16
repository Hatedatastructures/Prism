/**
 * @file SessionServices.hpp
 * @brief 会话运行时服务的共享所有权上下文
 * @details SessionOptions 通过 shared_ptr 持有本对象后，识别路由、方案
 *          执行器、填充配置、流量 sink 与异步服务回调可跨 detached
 *          会话安全存活。旧式裸指针字段只作为迁移兼容入口。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <functional>
#include <memory>

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Builtin/Mux.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>
#include <Preview/Runtime/Recognition/Route.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

} // namespace Preview::Runtime

namespace Preview::Recognition
{

    struct RecognizeResult;

} // namespace Preview::Recognition

namespace Preview::Runtime
{

    /**
     * @struct SessionServices
     * @brief 单会话及其 detached 子操作共享的服务所有者
     */
    struct SessionServices
    {
        using ProtocolAcceptFn = std::function<Net::awaitable<
            Preview::Fault::Code>(Preview::SharedTransmission &, Preview::Middleware::Context &)>;
        using ResolveCandidateFn = std::function<ProtocolAcceptFn(Preview::Recognition::CandidateId)>;
        using PrepareFn = std::function<Net::awaitable<Preview::Fault::Code>(
            const Preview::Recognition::RecognizeResult &, Preview::Middleware::Context &)>;
        using UdpServiceFn = std::function<Net::awaitable<Preview::Fault::Code>(
            Preview::Middleware::Context &)>;
        using DatagramServiceFn = Preview::Runtime::DatagramDataPlane::ServiceFn;

        /// SNI 路由表的共享所有权
        std::shared_ptr<Preview::Recognition::SniRouteTable> Routes{};
        /// 伪装方案执行器的共享所有权
        std::shared_ptr<Preview::Recognition::SchemeExecutor> Scheme{};
        /// 填充配置的共享所有权
        std::shared_ptr<const Preview::Middleware::Context::PadConfig> Pad{};
        /// 流量 sink 的共享所有权
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic{};
        /// 应用级异步日志 owner；Session 只提交值快照，不执行文件 I/O。
        Preview::Diagnose::Logger::Owner Logger{};
        /// 每个 Session 创建自己的 TraceContext，避免跨 Session 共享可变字段。
        Preview::Statistics::TraceSelection TraceSelection{};
        /// 原生 TLS context 的共享所有权；为空时仅接受裸 TCP。
        std::shared_ptr<Net::ssl::context> NativeTls{};

        /// 认证器的共享所有权
        Preview::SharedAuthenticator Auth{};
        /// 入站 carrier probe 与握手的总时限
        std::chrono::milliseconds HandshakeTimeout{std::chrono::seconds(5)};
        /// 中继空闲超时
        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        /// 协议接入函数
        ProtocolAcceptFn AcceptProtocol{};
        /// winner-only 候选解析函数
        ResolveCandidateFn ResolveCandidate{};
        /// 兼容旧命名的候选解析函数
        ResolveCandidateFn Resolver{};
        /// 识别结果装配函数
        PrepareFn Prepare{};
        /// 多路复用函数
        Preview::Middleware::Builtin::MuxMiddleware::MuxFn Mux{};
        /// 拨号函数
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        /// UDP 服务函数
        UdpServiceFn UdpService{};
        /// 不可变识别 profile
        Preview::Recognition::SharedProfile Profile{};
    };

    using SharedSessionServices = std::shared_ptr<SessionServices>;

} // namespace Preview::Runtime
