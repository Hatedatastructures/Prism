/**
 * @file TrusttunnelCandidate.hpp
 * @brief Native TLS + TrustTunnel HTTP/2 分层候选。
 */

#pragma once

#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Protocols/Trusttunnel/Http2.hpp>

#include <boost/asio/ssl/context.hpp>

#include <memory>
#include <string>
#include <utility>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    [[nodiscard]] inline auto MakeTrusttunnelCandidate(
        CandidateOptions Options,
        std::shared_ptr<Net::ssl::context> NativeTls,
        Preview::Trusttunnel::ServerConfig Config) -> CandidateBinding
    {
        TlsCandidateOptions Outer;
        Outer.Id = Options.Id;
        Outer.Name = Options.Name;
        Outer.Scheme = "trusttunnel";
        Outer.Alpn = {"h2"};
        Outer.Fallback = true;
        Outer.Carrier = TlsCarrier::Trusttunnel;

        auto AcceptPrepared = [NativeTls, Config = std::move(Config)](
                                   Preview::SharedTransmission Inbound,
                                   std::shared_ptr<const void>)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "trusttunnel";
            if (!NativeTls)
            {
                Result.Code = Preview::Fault::Code::NotSupported;
                Result.Transport = std::move(Inbound);
                co_return Result;
            }
            auto [ErrorCode, Authority, Transport] = co_await Preview::Trusttunnel::AcceptHttp2(
                std::move(Inbound), *NativeTls, Config);
            Result.Code = Preview::Fault::ToCode(Preview::make_error_code(ErrorCode));
            if (ErrorCode != Preview::Error::None)
            {
                Result.NativeError = Preview::make_error_code(ErrorCode);
            }
            if (ErrorCode != Preview::Error::None || !Transport)
            {
                if (ErrorCode == Preview::Error::None)
                {
                    Result.NativeError =
                        std::make_error_code(std::errc::protocol_error);
                }
                co_return Result;
            }
            const auto Http2 = std::dynamic_pointer_cast<Preview::Trusttunnel::Http2Transport>(
                Transport);
            if (!Http2)
            {
                Result.Code = Preview::Fault::Code::ProtocolError;
                co_return Result;
            }
            Http2->SetAuthority(std::move(Authority));
            Result.Transport = std::move(Http2);
            co_return Result;
        };

        auto Tls = TlsCandidateFactory::MakePrepared(
            std::move(Outer), std::move(AcceptPrepared));
        CandidateBinding Result;
        Result.Spec = std::move(Tls.Spec);
        Result.Spec.Protocol = Core::ProtocolType::TrustTunnel;
        Result.Spec.Kind = Core::CandidateKind::TlsCarrier;
        Result.Accept = Preview::Runtime::MakeAcceptTrusttunnel();
        return Result;
    }

} // namespace Preview::Composition::Recognition
