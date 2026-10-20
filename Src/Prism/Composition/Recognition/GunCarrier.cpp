/** @file GunCarrier.cpp @brief Gun/Grpc server carrier adapter 实现。 */

#include <Prism/Composition/Recognition/TlsCarrierRunners.hpp>
#include <Prism/Composition/Recognition/TlsCarrierFailure.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Native/Native.hpp>

#include <exception>
#include <memory>
#include <new>
#include <utility>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RunGunServerAccept(
        GunServerAcceptOptions Options,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "gun";
        if (!Options.TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        if (Options.Mode != GunServerMode::GunLite &&
            Options.Mode != GunServerMode::Grpc)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Input.Inbound);
        if (!Prepared)
        {
            Detail::SetCarrierFailure(Result, Prepared.error());
            co_return Result;
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        Prism::SharedTransmission TransportOwner;
        bool AdmissionReleased = false;
        try
        {
            auto Tls = co_await Prism::Native::Accept(
                Prism::Native::AcceptRequest{
                    std::move(Input.Inbound), *Options.TlsContext, std::move(Input.Bytes)});
            if (!Tls)
            {
                Detail::SetCarrierFailure(Result, co_await Admission.Retire(Tls.error()));
                co_return Result;
            }
            Result.Metadata.Sni = std::move(Tls->ServerName);
            Result.Metadata.Alpn = std::move(Tls->Alpn);
            Result.Metadata.TlsVersion = std::move(Tls->TlsVersion);
            Result.Metadata.EchAccepted = Tls->EchAccepted;
            Result.Metadata.NativeTlsEstablished = true;
            TransportOwner = std::static_pointer_cast<Prism::Transmission>(
                std::move(Tls->Transport));
            const auto Tracked = Admission.Track(TransportOwner);
            if (!Tracked)
            {
                auto Failure = co_await Admission.Retire(Tracked.error());
                Failure = co_await Detail::RetireCarrierInput(TransportOwner, Failure);
                Detail::SetCarrierFailure(Result, Failure);
                co_return Result;
            }
            if (Options.Mode == GunServerMode::Grpc)
            {
                auto Connection = co_await Prism::Gun::Grpc::StreamTransport::Accept(
                    TransportOwner,
                    Prism::Gun::Grpc::Config{
                        Options.Config.Path, {}, Prism::Gun::Grpc::DefaultMaxMessageBytes});
                if (!Connection)
                {
                    Detail::SetCarrierFailure(
                        Result, co_await Admission.Retire(Connection.error()));
                    co_return Result;
                }
                Result.Transport = std::move(*Connection);
                Admission.Release();
                co_return Result;
            }

            Admission.Release();
            AdmissionReleased = true;
            auto Accepted = co_await Prism::Gun::Accept(TransportOwner, Options.Config);
            if (!Accepted)
            {
                Detail::SetCarrierFailure(Result, Accepted.error());
                co_return Result;
            }
            Result.Transport = std::move(Accepted->Connection);
            co_return Result;
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        const auto Cause = Prism::Contract::InboundAdmission::ExceptionFailure(
            std::move(Fatal));
        auto Failure = Cause;
        if (AdmissionReleased)
        {
            Failure = co_await Detail::RetireCarrierInput(TransportOwner, Cause);
        }
        else
        {
            Failure = co_await Admission.Retire(Cause);
        }
        Detail::SetCarrierFailure(Result, Failure);
        co_return Result;
    }

    [[nodiscard]] auto MakeGunServerAccept(GunServerAcceptOptions Options)
        -> CarrierAcceptFn
    {
        return [Options = std::move(Options)](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunGunServerAccept(Options, std::move(Input));
        };
    }
} // namespace Prism::Composition::Recognition
