/**
 * @file LayeredCandidateFactory.hpp
 * @brief TLS carrier 与内层协议候选的 Composition 组合器
 * @details Runtime 只看到一个候选。提交阶段先由 TLS carrier 完成外层
 *          解包/认证，Session 随后通过同一候选的接入回调调用内层协议
 *          handler；试探阶段不会触发任一 handler。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <utility>

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Session.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    /**
     * @class LayeredCandidateFactory
     * @brief 将 TLS carrier 候选和内层协议接入器组合为一个 Runtime 候选
     */
    class LayeredCandidateFactory
    {
    public:
        /**
         * @brief 构造分层候选
         * @param Options TLS carrier 识别和提交参数
         * @param Carrier TLS carrier 提交回调
         * @param Inner 内层协议候选；只消费其 Accept 回调和最终协议类型
         * @return 可交给 ProfileBuilder 的分层候选
         */
        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       CarrierAcceptFn Carrier,
                                       CandidateBinding Inner) -> CandidateBinding
        {
            auto Tls = TlsCandidateFactory::Make(std::move(Options), std::move(Carrier));
            CandidateBinding Result;
            Result.Spec = std::move(Tls.Spec);
            Result.Spec.Protocol = Inner.Spec.Protocol;
            Result.Spec.Kind = Core::CandidateKind::TlsCarrier;
            Result.Accept = [Accept = std::move(Inner.Accept)](
                                Preview::SharedTransmission &Inbound,
                                Preview::Middleware::Context &Context) -> Net::awaitable<Preview::Fault::Code>
            {
                if (!Accept)
                {
                    co_return Preview::Fault::Code::ProtocolError;
                }
                co_return co_await Accept(Inbound, Context);
            };
            return Result;
        }
    };

} // namespace Preview::Composition::Recognition
