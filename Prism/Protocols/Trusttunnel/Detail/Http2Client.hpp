/**
 * @file Http2Client.hpp
 * @brief TrustTunnel HTTP/2 client carrier、CONNECT request 和响应 owner。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ClientTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2ClientDriver.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Trusttunnel::Detail
{

    /** @brief HTTP/2 客户端 TLS 建立的完整冷路径输入。 */
    [[nodiscard]] inline auto RunHttp2TlsHandshake(
        Prism::Transport::Encrypted::SharedStream Stream)
        -> Net::awaitable<boost::system::error_code>
    {
        boost::system::error_code ErrorCode;
        co_await Stream->async_handshake(Net::ssl::stream_base::client,
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return ErrorCode;
    }

    using Http2TlsResult = std::expected<
        Prism::Transport::Encrypted::SharedStream,
        Prism::Fault::Failure>;

    /** @brief 使用同一预预约 owner retire TLS setup/handshake failure 与 recovered raw。 */
    [[nodiscard]] inline auto RetireHttp2TlsFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Fault::Failure Cause,
        Prism::SharedTransmission Recovered)
        -> Net::awaitable<Http2TlsResult>
    {
        if (Recovered)
        {
            const auto Tracked = Admission.Track(Recovered);
            if (!Tracked && Cause.Succeeded())
            {
                Cause = Tracked.error();
            }
        }
        co_return std::unexpected(co_await Admission.Retire(Cause));
    }

    /**
     * @brief 在 I/O 前已准备 ticket 的前提下建立客户端 TLS/h2 stream。
     * @param Request 按值拥有上游、服务器名和字节池；TLS context 借用到握手返回。
     * @param Admission 与 Raw 同一连接的预预约 owner，失败时在本 helper 内完成真实 retire。
     * @return 唯一 expected stream 结果；失败保留首个 Code/Native，success 由调用方继续接管。
     */
    [[nodiscard]] inline auto ConnectHttp2Tls(
        Http2TlsClientRequest Request,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<Http2TlsResult>
    {
        if (!Request.Raw)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument},
                {});
        }
        const auto Tracked = Admission.Track(Request.Raw);
        if (!Tracked)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission, Tracked.error(), Request.Raw);
        }
        if (!Request.Bytes)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument},
                Request.Raw);
        }
        Prism::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
            std::move(Connector), Request.SslContext);
        if (!Request.ServerName.empty())
        {
            const auto &Name = Request.ServerName;
            if (SSL_set_tlsext_host_name(Stream->native_handle(), Name.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                co_return co_await RetireHttp2TlsFailure(
                    Admission,
                    Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail},
                    std::move(Recovered));
            }
        }
        constexpr unsigned char Alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(Stream->native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail},
                std::move(Recovered));
        }
        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await (RunHttp2TlsHandshake(Stream) || std::move(DeadlineWait));
        if (Result.index() == 1)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{
                    Prism::Fault::Code::Timeout,
                    std::make_error_code(std::errc::timed_out)},
                std::move(Recovered));
        }
        const auto HandshakeError = std::get<0>(Result);
        if (HandshakeError)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::FromNative(
                    static_cast<std::error_code>(HandshakeError)),
                std::move(Recovered));
        }
        co_return Stream;
    }
    [[nodiscard]] inline auto ConnectHttp2Core(
        Http2ConnectParameters Parameters,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<SharedTransmission, Prism::Fault::Failure>>
    {
        auto StreamResult = co_await ConnectHttp2Tls(
            Http2TlsClientRequest{std::move(Parameters.Upstream), Parameters.SslContext,
                                  std::string(Parameters.ServerName), Parameters.Bytes},
            Admission);
        if (!StreamResult)
        {
            co_return std::unexpected(StreamResult.error());
        }
        auto Stream = std::move(*StreamResult);
        auto State = MakeHttp2ClientState(
            std::make_shared<Prism::Transport::Encrypted>(
                std::move(Stream), std::move(Parameters.Bytes)));
        auto Accepted =
            std::make_shared<AcceptedClientTransport<Http2ClientState>>(State);
        auto Tracked = Admission.Track(
            std::static_pointer_cast<Prism::Transmission>(Accepted));
        if (!Tracked)
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Tracked.error()));
        const auto DriverStart = StartHttp2ClientDriver(State);
        if (DriverStart.Failed())
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, DriverStart));
        }
        State->Session->SendSettings();
        const auto Authority = std::string(Parameters.Target) + ":" + std::to_string(Parameters.Port);
        const auto StreamId = State->Session->OpenStream(
            {{":method", "CONNECT"}, {":authority", Authority},
             {"proxy-authorization", BasicAuth(Parameters.Config.username, Parameters.Config.password)}},
            false);
        if (!StreamId)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, StreamId.error()));
        }
        State->Transport->BindStream(*StreamId);
        const auto Flushed = co_await FlushHttp2ClientFrames(State);
        if (!Flushed)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Flushed.error()));
        }
        Net::steady_timer ResponseDeadline(State->Encrypted->Executor());
        ResponseDeadline.expires_after(std::chrono::seconds(30));
        boost::system::error_code ResponseError;
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        auto DeadlineWait = ResponseDeadline.async_wait(Net::use_awaitable);
        const auto ResponseResult = co_await (std::move(Receive) || std::move(DeadlineWait));
        if (ResponseResult.index() == 1)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State,
                Prism::Fault::Failure{Prism::Fault::Code::Timeout,
                                        std::make_error_code(std::errc::timed_out)}));
        }
        const auto Response = std::get<0>(ResponseResult);
        if (ResponseError)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State,
                Prism::Fault::FromNative(static_cast<std::error_code>(ResponseError))));
        }
        if (!Response)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Response.error()));
        }
        Admission.Release();
        co_return SharedTransmission(std::move(Accepted));
    }
} // namespace Prism::Trusttunnel::Detail
