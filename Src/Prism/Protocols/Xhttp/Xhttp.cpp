/**
 * @file Xhttp.cpp
 * @brief XHTTP 客户端与服务端统一工厂实现。
 */
#include <Prism/Protocols/Xhttp/Entry.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Protocols/Xhttp/Detail/ClientTls.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitClient.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServerAccept.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamClient.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamServer.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamTransport.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <system_error>
#include <tuple>
#include <utility>

#include <openssl/ssl.h>

namespace Prism::Xhttp
{
    namespace Detail
    {
        auto RetireClientTlsFailure(
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

        auto ConnectTls(
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

            const auto TrackedRaw = Admission.Track(Request.Raw);
            if (!TrackedRaw)
            {
                co_return std::unexpected(co_await Admission.Retire(TrackedRaw.error()));
            }
            Prism::Transport::Connector Connector(std::move(Request.Raw));
            auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
                std::move(Connector), Request.SslContext);
            if (!Request.Host.empty())
            {
                const auto &HostName = Request.Host;
                if (SSL_set_tlsext_host_name(
                        Stream->native_handle(), HostName.c_str()) != 1)
                {
                    co_return std::unexpected(co_await Admission.Retire(
                        Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail}));
                }
            }

            constexpr unsigned char Alpn[] = {2, 'h', '2'};
            if (SSL_set_alpn_protos(Stream->native_handle(), Alpn, sizeof(Alpn)) != 0)
            {
                co_return std::unexpected(co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail}));
            }

            Net::steady_timer Deadline(Stream->get_executor());
            Deadline.expires_after(std::chrono::seconds(30));
            auto DoHandshake = [Stream]() -> Net::awaitable<boost::system::error_code>
            {
                boost::system::error_code Error;
                co_await Stream->async_handshake(Net::ssl::stream_base::client,
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
                            Stream->native_handle()) != X509_V_OK)
                    {
                        Failure.Code = Prism::Fault::Code::Verifyfail;
                    }
                }
                co_return std::unexpected(co_await Admission.Retire(Failure));
            }
            co_return Stream;
        }
    }

    auto Connect(ClientConnectRequest Request) -> Net::awaitable<FactoryResult>
    {
        if (!Request.SslContext)
        {
            co_return std::unexpected(co_await Detail::RetireFactoryInput(
                std::move(Request.Raw),
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        if (!Request.Configuration.Enabled())
        {
            co_return std::unexpected(co_await Detail::RetireFactoryInput(
                std::move(Request.Raw),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));
        }
        if (Request.Configuration.IsSplit())
        {
            co_return co_await Detail::ConnectSplit(Detail::SplitClientConnectRequest{
                std::move(Request.Raw), *Request.SslContext, std::move(Request.Configuration),
                std::move(Request.Host), std::move(Request.Bytes)});
        }
        co_return co_await Detail::ConnectStream(std::move(Request));
    }

    auto Accept(AcceptRequest Request) -> Net::awaitable<ServerAcceptResult>
    {
        if (!Request.Raw)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        if (!Request.Bytes)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        if (!Request.Configuration.Enabled())
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));
        }
        std::exception_ptr Fatal;
        try
        {
            if (Request.Configuration.IsSplit())
            {
                auto Handler = std::make_shared<Detail::XhttpSplitAccept>(
                    Detail::XhttpSplitAcceptRequest{
                        std::move(Request.Raw), Request.SslContext,
                        std::move(Request.Configuration), std::move(Request.Bytes)});
                co_return co_await Handler->Run(Admission);
            }
            auto Handler = std::make_shared<Detail::XhttpAccept>(
                Detail::XhttpAcceptRequest{
                    std::move(Request.Raw), Request.SslContext,
                    std::move(Request.Configuration), std::move(Request.Bytes)});
            co_return co_await Handler->Run(Admission);
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }
}
