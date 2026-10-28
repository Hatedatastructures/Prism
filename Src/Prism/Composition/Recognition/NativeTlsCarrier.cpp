/** @file NativeTlsCarrier.cpp @brief strict Native TLS server carrier adapter 实现。 */

#include <Prism/Composition/Recognition/Detail/CarrierRunners.hpp>
#include <Prism/Composition/Recognition/Detail/CarrierFailure.hpp>

#include <Prism/Protocols/Native/Native.hpp>

#include <memory>
#include <utility>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RunNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        if (!TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        auto Accepted = co_await Prism::Native::Accept(
            Prism::Native::AcceptRequest{
                std::move(Input.Inbound), *TlsContext, std::move(Input.Bytes)});
        if (!Accepted)
        {
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }
        Result.Metadata.Sni = std::move(Accepted->ServerName);
        Result.Metadata.Alpn = std::move(Accepted->Alpn);
        Result.Metadata.TlsVersion = std::move(Accepted->TlsVersion);
        Result.Metadata.EchAccepted = Accepted->EchAccepted;
        Result.Metadata.NativeTlsEstablished = true;
        Result.Transport = std::move(Accepted->Transport);
        co_return Result;
    }

    [[nodiscard]] auto MakeNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext)](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunNativeTlsServerAccept(TlsContext, std::move(Input));
        };
    }
} // namespace Prism::Composition::Recognition
