/**
 * @file ClientTls.hpp
 * @brief XHTTP 客户端 TLS 握手与失败回收策略。
 */

#pragma once

#include <Preview/Protocols/Xhttp/Detail/Common.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Encrypted.hpp>

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

namespace Preview::Xhttp::Detail
{

    /** @brief XHTTP 客户端 TLS 建立的完整冷路径输入。 */
    struct ClientTlsRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        std::string Host;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    /** @brief 将 TLS engine 加入已预预约的失败退休票据并等待真实关闭。 */
    [[nodiscard]] inline auto RetireClientTlsFailure(
        Preview::Contract::InboundAdmission &Admission,
        Preview::Transport::Encrypted::SharedStream Stream,
        Preview::Fault::Failure Cause) -> Net::awaitable<Preview::Fault::Failure>
    {
        if (Stream)
        {
            auto Owner = std::make_shared<Preview::Transport::Encrypted>(
                std::move(Stream), nullptr);
            const auto Tracked = Admission.Track(
                std::static_pointer_cast<Preview::Transmission>(Owner));
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
        Preview::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<Preview::Transport::Encrypted::SharedStream,
                                        Preview::Fault::Failure>>
    {
        if (!Request.Raw)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
        }
        if (!Request.Bytes)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
        }

        Preview::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<Preview::Transport::Encrypted::StreamType>(
            std::move(Connector), Request.SslContext);
        auto EncryptedOwner = std::make_shared<Preview::Transport::Encrypted>(
            Stream, Request.Bytes);
        const auto Tracked = Admission.Track(
            std::static_pointer_cast<Preview::Transmission>(EncryptedOwner));
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
                    Preview::Fault::Failure{Preview::Fault::Code::TlsHsfail}));
            }
        }

        constexpr unsigned char Alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(
                EncryptedOwner->Stream().native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Preview::Fault::Failure{Preview::Fault::Code::TlsHsfail}));
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
            auto Failure = Preview::Fault::FromNative(
                static_cast<std::error_code>(HandshakeError));
            if (TimedOut)
            {
                Failure = {Preview::Fault::Code::Timeout};
            }
            if (HandshakeError &&
                (HandshakeError.category() == Net::error::get_ssl_category() ||
                 HandshakeError.category() == Net::ssl::error::get_stream_category()))
            {
                Failure.Code = Preview::Fault::Code::TlsHsfail;
                if (SSL_get_verify_result(
                        EncryptedOwner->Stream().native_handle()) != X509_V_OK)
                {
                    Failure.Code = Preview::Fault::Code::Verifyfail;
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

} // namespace Preview::Xhttp::Detail
