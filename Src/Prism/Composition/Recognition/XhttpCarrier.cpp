/** @file XhttpCarrier.cpp @brief XHTTP server carrier adapter 实现。 */

#include <Prism/Composition/Recognition/TlsCarrierRunners.hpp>
#include <Prism/Composition/Recognition/TlsCarrierFailure.hpp>

#include <Prism/Protocols/Xhttp/Xhttp.hpp>

#include <memory>
#include <utility>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RunXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "xhttp";
        if (!TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
            co_return Result;
        }
        auto Accepted = co_await Prism::Xhttp::Accept(
            Prism::Xhttp::AcceptRequest{
                std::move(Input.Inbound), *TlsContext, Config, std::move(Input.Bytes)});
        if (!Accepted)
        {
            Result.Code = Accepted.error().Code;
            Result.NativeError = Accepted.error().Native;
            co_return Result;
        }
        Result.Metadata.Sni = std::move(Accepted->Negotiated.ServerName);
        Result.Metadata.Alpn = std::move(Accepted->Negotiated.Alpn);
        Result.Metadata.TlsVersion = std::move(Accepted->Negotiated.Version);
        Result.Metadata.EchAccepted = Accepted->Negotiated.EchAccepted;
        Result.Metadata.NativeTlsEstablished = true;
        Result.Transport = std::move(Accepted->Transport);
        co_return Result;
    }

    [[nodiscard]] auto MakeXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext), Config = std::move(Config)](
                   Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunXhttpServerAccept(TlsContext, Config, std::move(Input));
        };
    }
} // namespace Prism::Composition::Recognition
