/**
 * @file Session.hpp
 * @brief 单连接会话编排接口与拥有型选项。
 * @details Session 接管其 admission lease、registry token 和 transport close owner；
 *          Run 在入站 executor 完成识别、认证、数据面 relay 与最终 drain。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Runtime/Session/Registry.hpp>
#include <Prism/Runtime/Session/Services.hpp>
#include <Prism/Runtime/Session/Trace/Ring.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

namespace Prism::Executor
{
    class ClosingResource;
}

namespace Prism::Contract::Ingress
{
    class SessionRetirementOwner;
}

namespace Prism::Runtime
{
    namespace Net = boost::asio;
    class ActiveTransports;
    class SessionControl;

    /** @struct SessionOptions @brief 会话构造所需的拥有型依赖。 */
    struct SessionOptions
    {
        SharedSessionServices Services{std::make_shared<SessionServices>()};
        std::shared_ptr<SessionControl> Control{};
        std::string SourceIp;
    };

    namespace SessionSupport
    {
        struct SessionLogState;
    }

    namespace Detail
    {
        /**
         * @brief admission 延迟样本的 RAII 提交作用域。
         * @details 持有 sink 共享引用与样本值；析构报告时长，不拥有或关闭 Session。
         */
        class RecognitionLatencyScope final
        {
        public:
            using Clock = std::chrono::steady_clock;
            RecognitionLatencyScope(
                std::shared_ptr<Prism::Foundation::RecognitionLatencySink> Sink,
                Prism::Foundation::RecognitionLatencySample Sample) noexcept;
            RecognitionLatencyScope(const RecognitionLatencyScope&) = delete;
            auto operator=(const RecognitionLatencyScope&) -> RecognitionLatencyScope& = delete;
            ~RecognitionLatencyScope() noexcept;

        private:
            std::shared_ptr<Prism::Foundation::RecognitionLatencySink> Sink_;
            Prism::Foundation::RecognitionLatencySample Sample_;
            Clock::time_point Started_{};
        };
    }

    /**
     * @class Session
     * @brief 单连接会话编排与最终生命周期 owner。
     * @details Run 接管入站传输；调用方应等待其完成，Session 最终关闭者为自身的
     *          Control/ActiveTransports 协作链，数据面 I/O 在传输 executor 上排空。
     */
    class Session
    {
    public:
        explicit Session(SessionOptions Options);
        Session(const Session&) = delete;
        auto operator=(const Session&) -> Session& = delete;
        ~Session();

        [[nodiscard]] auto Control() const noexcept -> std::shared_ptr<SessionControl>;
        [[nodiscard]] auto Services() const noexcept -> SharedSessionServices;
        [[nodiscard]] auto SetGenerationUseLease(
            Prism::Foundation::GenerationUseLease Value) noexcept -> bool;
        auto SetDeferredCleanup(std::shared_ptr<Prism::Executor::ClosingResource> Value) -> void;
        auto SetRegistration(SessionRegistry::Registration Value) -> void;
        auto SetTraceWriter(std::shared_ptr<SessionTraceWriter> Value) noexcept -> void;
        auto Cancel() -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto Close() -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto Run(Prism::SharedTransmission Inbound)
            -> Net::awaitable<Prism::Fault::Failure>;
        [[nodiscard]] auto IsDrained() const noexcept -> bool;

    private:
        [[nodiscard]] auto RunCore(Prism::SharedTransmission Inbound,
            const std::shared_ptr<SessionSupport::SessionLogState>& LogState)
            -> Net::awaitable<Prism::Fault::Failure>;
        [[nodiscard]] auto DrainAdmissionOwner() -> Net::awaitable<Prism::Fault::Failure>;
        auto RecordClosed(const Prism::Fault::Failure& Failure) noexcept -> void;

        SessionOptions Opts_;
        SharedSessionServices Services_;
        SessionRegistry::Registration Registration_;
        Prism::Foundation::GenerationUseLease GenerationUse_;
        std::shared_ptr<SessionControl> Control_;
        std::shared_ptr<SessionTraceWriter> TraceWriter_;
        std::shared_ptr<ActiveTransports> Active_;
        std::shared_ptr<Prism::Contract::Ingress::SessionRetirementOwner> AdmissionOwner_;
        std::atomic<bool> Drained_{false};
        std::shared_ptr<Prism::Executor::ClosingResource> DeferredCleanup_;
    };
}
