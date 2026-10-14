/**
 * @file Prepared.hpp
 * @brief Reality 唯一已预读 ClientHello 的 typed 服务端握手入口。
 * @details 认证、TLS flight 与 record 状态由完整 Detail owner 承担。
 */
#pragma once

#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Reality/Types.hpp>
#include <Preview/Protocols/Reality/Detail/Authentication.hpp>
#include <Preview/Protocols/Reality/Detail/Handshake.hpp>
#include <Preview/Protocols/Reality/Detail/Record.hpp>
#include <Preview/Protocols/Reality/Detail/RecordStream.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Preview::Reality
{
    namespace Net = boost::asio;    /**
     * @brief 完成已预读 ClientHello 的 Reality 服务端 wire 握手。
     * @param Request Inbound 按值接管，ClientHello 材料借用至协程完成。
     * @return 成功返回 owning record stream；失败保留 typed/native cause。
     * @note InboundAdmission 持有失败关闭与 drain 回执；成功后接管权随 stream 移交。
     */
    [[nodiscard]] inline auto AcceptPrepared(PreparedRequest Request)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        auto PreparedAdmission = co_await Preview::Contract::InboundAdmission::Prepare(
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
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
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

        const auto WriteFailure = co_await Detail::WriteServerFlight(
            Inbound, *Handshake);
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
        Preview::Fault::Failure ConstructionFailure;
        try
        {
            Stream = std::make_shared<Detail::TlsRecordStream>(
                std::move(Inbound), std::move(Handshake->Keys));
        }
        catch (...)
        {
            ConstructionFailure = Preview::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (ConstructionFailure.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(ConstructionFailure));
        }

        const auto Tracked = Admission.Track(
            std::static_pointer_cast<Preview::Transmission>(Stream));
        if (!Tracked)
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{Stream, {}};
            const auto Rejected = co_await Admission.Reject(std::move(Plane), Tracked.error());
            co_return std::unexpected(Rejected.error());
        }
        Admission.Release();
        co_return std::static_pointer_cast<Preview::Transmission>(std::move(Stream));
    }


}
