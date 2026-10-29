/**
 * @file Services.hpp
 * @brief 会话运行时服务的共享所有权上下文
 * @details SessionOptions 通过 shared_ptr 持有本对象后，不可变识别 profile、
 *          填充配置、流量 sink 与异步服务回调可跨 detached
 *          会话安全存活。协议服务快照不持有 Mux 调度回调，避免根服务自拥有。
 */

#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace Prism::Runtime
{

    namespace Net = boost::asio;

} // namespace Prism::Runtime

namespace Prism::Recognition
{

    struct RecognizeResult;

} // namespace Prism::Recognition

namespace Prism::Runtime
{

    /**
     * @struct SessionServices
     * @brief 协议子会话所需服务的值快照；所有 shared owner 随快照保活。
     */
    struct SessionServices
    {

        using ResolveCandidateFn = std::function<std::shared_ptr<Prism::Contract::StreamFactory>(Prism::Recognition::CandidateId)>;

        /// 填充配置的共享所有权
        std::shared_ptr<const Prism::Middleware::Context::PadConfig> Pad{};
        /// 流量 sink 的共享所有权
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic{};
        /// recognition admission 延迟 sink；为空时热路径不读取时钟。
        std::shared_ptr<Prism::Foundation::RecognitionLatencySink> RecognitionLatency{};
        /// 配置 generation 的直接 pin；旧认证与协议 profile 随会话保留。
        Prism::Foundation::GenerationPin Generation{};
        /// 本代 mux root 共用的准入计数；由本 Session 的不可变 generation 服务快照提供。
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState{};
        /// owning runtime snapshot pin，随真实 carrier/activity 退休一并释放。
        std::shared_ptr<const void> RuntimeSnapshotPin{};
        /// 进程/generation 上下文；Session 派生 Worker 和 Session identity。
        Prism::Diagnose::ContextState ProcessContext{Prism::Diagnose::ContextState::Empty()};
        /// 原生 TLS context 的共享所有权；为空时仅接受裸 TCP。
        std::shared_ptr<Net::ssl::context> NativeTls{};
        /// 真正worker块池，共享拥有总容量；每个session不能创建自己的最大预算池。
        std::shared_ptr<Prism::Memory::BytePool> Bytes{};

        /// 入站 carrier probe 与握手的总时限
        std::chrono::milliseconds HandshakeTimeout{std::chrono::seconds(5)};
        /// 中继空闲超时
        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        /// 协议接入函数
        std::shared_ptr<Prism::Contract::StreamFactory> AcceptProtocol{};
        /// winner-only 候选解析函数
        ResolveCandidateFn ResolveCandidate{};

        /// 拨号函数
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        /// 不可变识别 profile
        Prism::Recognition::SharedProfile Profile{};
    };

    using SharedSessionServices = std::shared_ptr<SessionServices>;

} // namespace Prism::Runtime
