/**
 * @file RecognitionAdmission.hpp
 * @brief Session 载体探测、协议识别、接入和上下文装配
 * @details 该 owner 只负责把入站传输物化为带有协议身份和认证上下文的
 *          middleware context；typed data-plane 的执行由 DataPlaneRelay 拥有。
 */

#pragma once
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <expected>
#include <memory>
#include <optional>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/CandidateHandle.hpp>

namespace Prism::Recognition
{
    class Profile;
    struct CarrierMetadata;
    struct RecognizeResult;
}

namespace Prism::Contract
{
    class StreamFactory;
}

namespace Prism::Runtime
{

    namespace Net = boost::asio;
    struct SessionRunContext;

    namespace Detail
    {
        /** @brief 按 Native TLS 已协商的 SNI 解析仍属于当前 carrier 的路由候选。 */
        [[nodiscard]] auto ResolveNegotiatedTlsRoute(const Prism::Recognition::Profile* Profile,
            const Prism::Recognition::CarrierMetadata& Carrier)
            -> std::expected<std::optional<Prism::Recognition::CandidateHandle>, Prism::Fault::Failure>;
    }

    /**
     * @class SessionRecognitionAdmission
     * @brief 识别与协议接入 owner
     */
    class SessionRecognitionAdmission final
    {
    public:
        /** @brief 按载体、识别和协议接入阶段移交唯一数据面。 */
        [[nodiscard]] static auto Run(SessionRunContext& Run)
            -> Net::awaitable<Prism::Fault::Failure>;

    private:
        static auto ProbeCarrier(SessionRunContext& Run) -> Net::awaitable<Prism::Fault::Failure>;

        static auto CommitNativeTls(SessionRunContext& Run,
                                    std::chrono::steady_clock::time_point HandshakeDeadline)
            -> Net::awaitable<Prism::Fault::Failure>;

        /** @brief 按握手后的真实 SNI 选择同一 TLS carrier 的路由目标。 */
        [[nodiscard]] static auto ApplyNegotiatedTlsRoute(SessionRunContext& Run) -> bool;

        static auto Recognize(SessionRunContext& Run) -> Net::awaitable<Prism::Fault::Failure>;

        static auto ResolveFactory(SessionRunContext& Run)
            -> std::expected<std::shared_ptr<Prism::Contract::StreamFactory>,
                              Prism::Fault::Failure>;

        static auto PublishSessionRegistration(SessionRunContext& Run)
            -> Prism::Fault::Failure;

        static auto Accept(SessionRunContext& Run,
                           std::shared_ptr<Prism::Contract::StreamFactory> Acceptor)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto RecognitionFailure(
            const Prism::Recognition::RecognizeResult& Result,
            const Prism::Fault::Code Fallback = Prism::Fault::Code::ProtocolError) noexcept
            -> Prism::Fault::Failure;
    };
} // namespace Prism::Runtime
