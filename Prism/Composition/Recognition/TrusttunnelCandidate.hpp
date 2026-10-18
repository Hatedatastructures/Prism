/**
 * @file TrusttunnelCandidate.hpp
 * @brief Native TLS + TrustTunnel HTTP/2 分层候选。
 */

#pragma once

#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/Http2Server.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>

#include <boost/asio/ssl/context.hpp>

#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    namespace Detail
    {
        /** @brief 将协议完整失败原样映射到 Recognition owner 结果。 */
        inline auto SetTrusttunnelFailure(
            Core::CarrierAcceptResult &Result,
            const Prism::Fault::Failure &Failure) -> void
        {
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
        }
    }

    /**
     * @struct TrusttunnelCandidateState
     * @brief TrustTunnel TLS candidate 的 owning prepared handoff 状态。
     * @details NativeTls 与 immutable wire/auth binding 一起捕获；prepared callback
     *          不保存配置或上下文裸引用，失败时仍由 carrier 结果交还输入。
     */
    struct TrusttunnelCandidateState final
    {
        std::shared_ptr<Net::ssl::context> NativeTls;
        Prism::Trusttunnel::SharedWireAuthBinding Binding;
    };

    [[nodiscard]] inline auto AcceptPreparedTrusttunnel(TrusttunnelCandidateState State,
        Prism::SharedTransmission Inbound,
        std::shared_ptr<Prism::Memory::BytePool> Bytes)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "trusttunnel";
        if (!State.NativeTls || !State.Binding)
        {
            Result.Code = Prism::Fault::Code::NotSupported;
            Result.Transport = std::move(Inbound);
            co_return Result;
        }
        auto Accepted = co_await Prism::Trusttunnel::AcceptHttp2(
            Prism::Trusttunnel::Http2AcceptRequest{
                std::move(Inbound), *State.NativeTls, State.Binding, std::move(Bytes)});
        if (!Accepted)
        {
            Detail::SetTrusttunnelFailure(Result, Accepted.error());
            co_return Result;
        }
        auto Connection = std::move(*Accepted);
        if (!Connection.Transport)
        {
            const Prism::Fault::Failure Failure{
                Prism::Fault::Code::ProtocolError,
                std::make_error_code(std::errc::protocol_error)};
            Detail::SetTrusttunnelFailure(Result, Failure);
            co_return Result;
        }
        Result.Transport = std::move(Connection.Transport);
        co_return Result;
    }

    [[nodiscard]] inline auto MakeTrusttunnelCandidate(CandidateOptions Options,
        std::shared_ptr<Net::ssl::context> NativeTls, Prism::Trusttunnel::SharedWireAuthBinding Binding)
        -> CandidateBinding
    {
        TlsCandidateOptions Outer;
        Outer.Id = Options.Id;
        Outer.Name = Options.Name;
        Outer.Scheme = "trusttunnel";
        Outer.Alpn = {"h2"};
        Outer.Fallback = true;
        Outer.Carrier = TlsCarrier::TrustTunnel;

        const TrusttunnelCandidateState State{std::move(NativeTls), std::move(Binding)};
        auto AcceptPrepared = [State](Core::CarrierAcceptPreparedInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            co_return co_await AcceptPreparedTrusttunnel(
                State, std::move(Input.Inbound), std::move(Input.Bytes));
        };

        auto Tls = TlsCandidateFactory::MakePrepared(std::move(Outer), std::move(AcceptPrepared));
        CandidateBinding Result;
        Result.Spec = std::move(Tls.Spec);
        Result.Spec.Protocol = Prism::Contract::ProtocolType::TrustTunnel;
        Result.Spec.Kind = Core::CandidateKind::TlsCarrier;
        Result.Accept = std::make_shared<Prism::Trusttunnel::IngressFactory>(
            Prism::Trusttunnel::IngressOptions{State.Binding});
        return Result;
    }

} // namespace Prism::Composition::Recognition
