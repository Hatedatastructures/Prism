/**
 * @file RealityAdmission.cpp
 * @brief Reality carrier 准备与准入实现。
 */
#include <Prism/Protocols/Reality/Prepared.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Reality/Detail/CarrierRecord.hpp>
#include <Prism/Protocols/Reality/Detail/CarrierStream.hpp>
#include <Prism/Protocols/Reality/Detail/Handshake.hpp>
#include <Prism/Protocols/Reality/Detail/SessionId.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Reality
{
    namespace Detail
    {
        TlsRecordStream::TlsRecordStream(
            Prism::SharedTransmission Transport,
            Tls13Keys Keys,
            std::optional<Prism::Fault::Failure> PendingTerminal)
            : Prism::Transmission(
                  Transport ? Transport->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Transport)), Keys_(std::move(Keys)),
              PendingTerminal_(std::move(PendingTerminal))
        {
        }
    }

    auto AcceptPrepared(PreparedRequest Request)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        auto PreparedAdmission = co_await Prism::Contract::InboundAdmission::Prepare(
            Request.Inbound);
        if (!PreparedAdmission)
        {
            co_return std::unexpected(PreparedAdmission.error());
        }
        auto Admission = std::move(*PreparedAdmission);
        auto Inbound = Request.Inbound;
        if (!Inbound)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }

        auto Authenticated = Detail::AuthenticateClient(Request);
        if (!Authenticated)
        {
            co_return std::unexpected(co_await Admission.Retire(Authenticated.error()));
        }
        auto Handshake = Detail::BuildServerHandshake(Request, *Authenticated);
        if (!Handshake)
        {
            co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
        }
        const auto WriteFailure = co_await Detail::WriteServerFlight(Inbound, *Handshake);
        if (WriteFailure.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(WriteFailure));
        }
        const auto FinishedFailure = co_await Detail::VerifyClientFinished(
            Inbound, Request.RawMessage, *Handshake);
        if (FinishedFailure.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(FinishedFailure));
        }

        std::shared_ptr<Detail::TlsRecordStream> Stream;
        Prism::Fault::Failure ConstructionFailure;
        try
        {
            Stream = std::make_shared<Detail::TlsRecordStream>(
                std::move(Inbound), std::move(Handshake->Keys),
                std::move(Handshake->PendingTerminal));
        }
        catch (...)
        {
            ConstructionFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (ConstructionFailure.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(ConstructionFailure));
        }

        const auto Tracked = Admission.Track(
            std::static_pointer_cast<Prism::Transmission>(Stream));
        if (!Tracked)
        {
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Root = Prism::Contract::StreamDataPlane{Stream, {}};
            const auto Rejected = co_await Admission.Reject(std::move(Plane), Tracked.error());
            co_return std::unexpected(Rejected.error());
        }
        Admission.Release();
        co_return std::static_pointer_cast<Prism::Transmission>(std::move(Stream));
    }
}
