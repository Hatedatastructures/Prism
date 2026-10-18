/**
 * @file ClientTls.hpp
 * @brief XHTTP 客户端 TLS 握手与失败回收策略。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

#include <openssl/ssl.h>

namespace Prism::Xhttp::Detail
{

    /** @brief XHTTP 客户端 TLS 建立的完整冷路径输入。 */
    struct ClientTlsRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        std::string Host;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /** @brief 将 TLS engine 加入已预预约的失败退休票据并等待真实关闭。 */
    [[nodiscard]] inline auto RetireClientTlsFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Transport::Encrypted::SharedStream Stream,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>
    {
        if (Stream)
        {
            auto Owner = std::make_shared<Prism::Transport::Encrypted>(
                std::move(Stream), nullptr);
            const auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Owner));
            if (!Tracked)
            {
                auto Released = Owner->ReleaseStream();
                if (Released)
                {
                    auto Detached = std::move(*Released);
                    Detached.reset();
                }
                else
                {
                    if (Cause.Succeeded()) Cause = Released.error();
                    const auto Closed = Owner->Close();
                    const auto Drained = co_await Owner->Activity()->Drain();
                    if (!Closed && Cause.Succeeded()) Cause = Closed.error();
                    if (!Drained && Cause.Succeeded()) Cause = Drained.error();
                }
            }
        }
        co_return co_await Admission.Retire(Cause);
    }

    /** @brief 建立客户端 TLS 流并应用 SNI、ALPN 和超时回收策略。 */
    [[nodiscard]] inline auto ConnectTls(
        ClientTlsRequest Request,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<Prism::Transport::Encrypted::SharedStream,
                                        Prism::Fault::Failure>>
    {
        if (!Request.Raw)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        if (!Request.Bytes)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }

        Prism::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
            std::move(Connector), Request.SslContext);
        auto EncryptedOwner = std::make_shared<Prism::Transport::Encrypted>(
            Stream, Request.Bytes);
        const auto Tracked = Admission.Track(
            std::static_pointer_cast<Prism::Transmission>(EncryptedOwner));
        if (!Tracked)
        {
            auto Released = EncryptedOwner->ReleaseStream();
            if (Released)
            {
                auto Detached = std::move(*Released);
                Stream.reset();
                Detached.reset();
            }
            else
            {
                const auto Closed = EncryptedOwner->Close();
                const auto Drained = co_await EncryptedOwner->Activity()->Drain();
                if (!Closed || !Drained)
                {
                    co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
                }
            }
            co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
        }
        if (!Request.Host.empty())
        {
            const auto &HostName = Request.Host;
            if (SSL_set_tlsext_host_name(
                    EncryptedOwner->Stream().native_handle(), HostName.c_str()) != 1)
            {
                co_return std::unexpected(co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail}));
            }
        }

        constexpr unsigned char Alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(
                EncryptedOwner->Stream().native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail}));
        }

        Net::steady_timer Deadline(EncryptedOwner->Executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto DoHandshake = [EncryptedOwner]() -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code Error;
            co_await EncryptedOwner->Stream().async_handshake(
                Net::ssl::stream_base::client,
                Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        };
        boost::system::error_code HandshakeError;
        bool TimedOut = false;
        std::exception_ptr Fatal;
        try
        {
            const auto Result = co_await (
                DoHandshake() || Deadline.async_wait(Net::use_awaitable));
            TimedOut = Result.index() == 1;
            if (!TimedOut) HandshakeError = std::get<0>(Result);
        }
        catch (...)
        {
            Fatal = std::current_exception();
        }
        if (Fatal)
        {
            const auto Failure = co_await Admission.Retire(FailureFromException(Fatal));
            co_return std::unexpected(Failure);
        }
        if (TimedOut || HandshakeError)
        {
            auto Failure = Prism::Fault::FromNative(
                static_cast<std::error_code>(HandshakeError));
            if (TimedOut)
            {
                Failure = {Prism::Fault::Code::Timeout};
            }
            if (HandshakeError &&
                (HandshakeError.category() == Net::error::get_ssl_category() ||
                 HandshakeError.category() == Net::ssl::error::get_stream_category()))
            {
                Failure.Code = Prism::Fault::Code::TlsHsfail;
                if (SSL_get_verify_result(
                        EncryptedOwner->Stream().native_handle()) != X509_V_OK)
                {
                    Failure.Code = Prism::Fault::Code::Verifyfail;
                }
            }
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        auto Released = EncryptedOwner->ReleaseStream();
        if (!Released)
        {
            co_return std::unexpected(co_await Admission.Retire(Released.error()));
        }
        Stream = std::move(*Released);
        co_return std::move(Stream);
    }

} // namespace Prism::Xhttp::Detail
