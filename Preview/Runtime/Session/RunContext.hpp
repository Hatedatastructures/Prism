/**
 * @file RunContext.hpp
 * @brief Session 运行阶段的 owner-held 输入、服务和中间结果
 * @details 该结构把识别/admission 与 data-plane/relay 之间的共享状态收敛为
 *          一个有领域语义的 request context，避免跨模块传递长参数列表。
 */

#pragma once
#include <Preview/Contract/Ingress/StreamFactory.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Runtime/ActiveTransports.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Runtime/SessionTraceRing.hpp>
#include <Preview/Runtime/Session/RecognitionLogging.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;
    using SessionCancellationChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    /**
     * @struct SessionRunContext
     * @brief 一个 Session 运行实例的稳定执行上下文
     * @details Control、Active 与 Cancellation 由 Session owner 持有；其余字段
     *          是启动时解析好的服务快照，热路径不再按名称查找服务。
     */
    struct SessionRunContext final
    {
        SharedSessionServices Services{};
        // 借用 Session owner 的唯一 token；RunSession 按值持有 Session 至最终关闭及错误投递结束。
        SessionRegistry::Registration *Registration{nullptr};
        std::shared_ptr<SessionControl> Control{};
        std::shared_ptr<SessionTraceWriter> TraceWriter{};
        std::shared_ptr<ActiveTransports> Active{};
        std::shared_ptr<SessionSupport::SessionLogState> LogState{};
        std::shared_ptr<SessionCancellationChannel> Cancellation{};
        Net::any_io_executor Executor{};

        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        std::shared_ptr<Preview::Contract::StreamFactory> AcceptProtocol{};
        Preview::Recognition::SharedProfile Profile{};
        SessionServices::ResolveCandidateFn ResolveCandidate{};
        const Preview::Middleware::Context::PadConfig *Pad{nullptr};
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic{};
        std::shared_ptr<Preview::Foundation::RecognitionLatencySink> RecognitionLatency{};
        std::string SourceIp;

        Preview::SharedTransmission Inbound{};
        Preview::Recognition::RecognizeResult Recognition{};
        Preview::Middleware::Context Context;
        SessionSupport::SessionLogWriter Logger{};
        bool AuthenticationInfoLogged{false};
        bool HasOutboundDecorator{false};
    };

} // namespace Preview::Runtime
