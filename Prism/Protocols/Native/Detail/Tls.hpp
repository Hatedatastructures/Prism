/**
 * @file Tls.hpp
 * @brief Native 严格 TLS 握手的私有执行 owner。
 * @details 负责准入、TLS engine 调用、失败退休与成功 transport 接管。
 */
#pragma once

#include <Prism/Protocols/Native/Types.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <utility>

namespace Prism::Native
{    namespace Detail
    {
        struct StrictHandshakeRequest final
        {
            SharedTransmission Inbound;
            std::reference_wrapper<Net::ssl::context> Context;
            std::string ServerName;
            std::shared_ptr<Prism::Memory::BytePool> Bytes;
            Prism::Transport::Encrypted::HandshakeRole Role{
                Prism::Transport::Encrypted::HandshakeRole::Server};
        };

        [[nodiscard]] inline auto RunStrictHandshake(StrictHandshakeRequest Request)
            -> Net::awaitable<AcceptResult>
        {
            if (!Request.Inbound)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Inbound);
            if (!Prepared)
            {
                co_return std::unexpected(Prepared.error());
            }
            auto Admission = std::move(*Prepared);
            if (!Request.Bytes)
            {
                const auto Failure = co_await Admission.Retire(
                    {Prism::Fault::Code::InvalidArgument});
                co_return std::unexpected(Failure);
            }

            std::exception_ptr Fatal;
            try
            {
                const auto Deadline = std::chrono::steady_clock::now() +
                    Prism::Transport::Encrypted::DefaultHandshakeTimeout;
                auto Handshake = co_await Prism::Transport::Encrypted::SslHandshake(
                    {std::move(Request.Inbound), Request.Context, Deadline,
                     std::move(Request.Bytes), Request.Role, std::move(Request.ServerName)});
                if (!Handshake.Failure.Succeeded() || !Handshake.Stream)
                {
                    auto Failure = Handshake.Failure;
                    if (!Failure.Failed())
                    {
                        Failure = {Prism::Fault::Code::TlsHsfail};
                    }
                    if (Handshake.Stream)
                    {
                        auto TlsOwner = std::make_shared<Prism::Transport::Encrypted>(
                            std::move(Handshake.Stream), std::move(Handshake.Bytes));
                        auto Child = std::static_pointer_cast<Prism::Transmission>(TlsOwner);
                        const auto Tracked = Admission.Track(Child);
                        if (!Tracked)
                        {
                            Prism::Contract::ProtocolDataPlane Plane;
                            Plane.Root = Prism::Contract::StreamDataPlane{Child, {}};
                            const auto Rejected = co_await Admission.Reject(
                                std::move(Plane), Failure);
                            co_return std::unexpected(Rejected.error());
                        }
                    }
                    co_return std::unexpected(co_await Admission.Retire(Failure));
                }

                auto Transport = std::make_shared<Prism::Transport::Encrypted>(
                    std::move(Handshake.Stream), std::move(Handshake.Bytes));
                auto Child = std::static_pointer_cast<Prism::Transmission>(Transport);
                const auto Tracked = Admission.Track(Child);
                if (!Tracked)
                {
                    Prism::Contract::ProtocolDataPlane Plane;
                    Plane.Root = Prism::Contract::StreamDataPlane{Child, {}};
                    const auto Rejected = co_await Admission.Reject(
                        std::move(Plane), Tracked.error());
                    co_return std::unexpected(Rejected.error());
                }
                NegotiatedTlsSession Negotiated;
                Negotiated.Transport = Child;
                Negotiated.ServerName = std::move(Handshake.Negotiated.ServerName);
                Negotiated.Alpn = std::move(Handshake.Negotiated.Alpn);
                Negotiated.TlsVersion = std::move(Handshake.Negotiated.Version);
                Negotiated.EchAccepted = Handshake.Negotiated.EchAccepted;
                Admission.Release();
                co_return Negotiated;
            }
            catch (const std::bad_alloc &)
            {
                Fatal = std::current_exception();
            }
            auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Fatal));
            Failure = co_await Admission.Retire(Failure);
            co_return std::unexpected(Failure);
        }
    }
}
