/**
 * @file RunContext.hpp
 * @brief Session 运行阶段的 owner-held 输入、服务和中间结果
 * @details 该结构把识别/admission 与 data-plane/relay 之间的共享状态收敛为
 *          一个有领域语义的 request context，避免跨模块传递长参数列表。
 */

#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/this_coro.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Runtime/SessionTraceRing.hpp>
#include <Prism/Runtime/Session/RecognitionLogging.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Runtime
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
        std::shared_ptr<Prism::Contract::StreamFactory> AcceptProtocol{};
        Prism::Recognition::SharedProfile Profile{};
        SessionServices::ResolveCandidateFn ResolveCandidate{};
        const Prism::Middleware::Context::PadConfig *Pad{nullptr};
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic{};
        std::shared_ptr<Prism::Foundation::RecognitionLatencySink> RecognitionLatency{};
        std::string SourceIp;

        Prism::SharedTransmission Inbound{};
        Prism::Recognition::RecognizeResult Recognition{};
        Prism::Middleware::Context Context;
        SessionSupport::SessionLogWriter Logger{};
        bool AuthenticationInfoLogged{false};
        bool HasOutboundDecorator{false};

        /** @brief 数据面 Run 结束后释放所有借用传输 view，交由 ActiveTransports 独占最终排空。 */
        auto ReleaseCarrierViews() noexcept -> void
        {
            Inbound.reset();
            Recognition.transport.reset();
            Context.Outbound.reset();
            Context.DataPlane.PostDial = {};
            std::visit([](auto& Root) { Root.Transport.reset(); }, Context.DataPlane.Root);
            if (auto* Datagram = Context.DataPlane.Datagram()) Datagram->Session.reset();
            if (auto* Mux = Context.DataPlane.Mux()) Mux->Session.reset();
        }

        /** @brief root view 已释放后退休 provider 接入期间持有的 replay/connection 等资源。 */
        [[nodiscard]] auto DrainAdmissionOwner()
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto Owner = std::move(Context.DataPlane.AdmissionOwner);
            if (!Owner) co_return Prism::Fault::Failure{};
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            try
            {
                const auto Drained = co_await Owner->Drain();
                if (!Drained) co_return Drained.error();
            }
            catch (...)
            {
                co_return Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            co_return Prism::Fault::Failure{};
        }
    };

} // namespace Prism::Runtime
