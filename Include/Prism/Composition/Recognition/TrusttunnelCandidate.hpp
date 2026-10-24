/**
 * @file TrusttunnelCandidate.hpp
 * @brief 原生 TLS 与 TrustTunnel HTTP/2 分层候选契约。
 */

#pragma once

#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <memory>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /**
     * @struct TrusttunnelCandidateState
     * @brief TrustTunnel TLS 候选的已准备交接状态。
     * @details NativeTls 与不可变 wire/auth binding 一起捕获；已准备回调不保存配置或上下文裸引用，
     *          失败时仍由 carrier 结果交还输入传输。
     */
    struct TrusttunnelCandidateState final
    {
        std::shared_ptr<Net::ssl::context> NativeTls;
        Prism::Trusttunnel::SharedWireAuthBinding Binding;
    };

    [[nodiscard]] auto AcceptPreparedTrusttunnel(TrusttunnelCandidateState State,
        Prism::SharedTransmission Inbound,
        std::shared_ptr<Prism::Memory::BytePool> Bytes)
        -> Net::awaitable<Core::CarrierAcceptResult>;

    [[nodiscard]] auto MakeTrusttunnelCandidate(CandidateOptions Options,
        std::shared_ptr<Net::ssl::context> NativeTls, Prism::Trusttunnel::SharedWireAuthBinding Binding)
        -> CandidateBinding;

} // namespace Prism::Composition::Recognition
