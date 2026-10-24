/** @file WebsocketCarrier.cpp @brief WebSocket server carrier adapter 实现。 */

#include <Prism/Composition/Recognition/TlsCarrierRunners.hpp>
#include <Prism/Composition/Recognition/TlsCarrierFailure.hpp>

#include <Prism/Protocols/Native/Native.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>

#include <memory>
#include <utility>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RunWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "ws";
        auto Transport = std::move(Input.Inbound);
        auto Bytes = std::move(Input.Bytes);
        if (TlsContext)
        {
            auto Tls = co_await Prism::Native::Accept(
                Prism::Native::AcceptRequest{std::move(Transport), *TlsContext, Bytes});
            if (!Tls)
            {
                Detail::SetCarrierFailure(Result, Tls.error());
                co_return Result;
            }
            Result.Metadata.Sni = std::move(Tls->ServerName);
            Result.Metadata.Alpn = std::move(Tls->Alpn);
            Result.Metadata.TlsVersion = std::move(Tls->TlsVersion);
            Result.Metadata.EchAccepted = Tls->EchAccepted;
            Result.Metadata.NativeTlsEstablished = true;
            Transport = std::move(Tls->Transport);
        }
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Ws::AcceptOptions{std::move(Transport), std::move(Bytes), std::move(Config)});
        if (!Accepted)
        {
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }
        Result.Transport = std::move(Accepted->Connection);
        co_return Result;
    }

    [[nodiscard]] auto MakeWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext), Config = std::move(Config)](
                   Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunWebsocketServerAccept(TlsContext, Config, std::move(Input));
        };
    }
} // namespace Prism::Composition::Recognition
