/** @file TrusttunnelCandidate.cpp @brief TLS 与 TrustTunnel 分层候选适配实现。 */

#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Prism/Composition/Recognition/Detail/TrusttunnelFailure.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Server.hpp>

#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{
    namespace Detail
    {

        auto SetTrusttunnelFailure(Core::CarrierAcceptResult& Result,
            const Prism::Fault::Failure& Failure) -> void
        {
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
        }

    } // namespace Detail

    auto AcceptPreparedTrusttunnel(TrusttunnelCandidateState State,
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

    auto MakeTrusttunnelCandidate(CandidateOptions Options,
        std::shared_ptr<Net::ssl::context> NativeTls,
        Prism::Trusttunnel::SharedWireAuthBinding Binding) -> CandidateBinding
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
