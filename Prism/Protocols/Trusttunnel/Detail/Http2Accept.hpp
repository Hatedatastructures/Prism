/**
 * @file Http2Accept.hpp
 * @brief TrustTunnel HTTP/2 server carrier、CONNECT request 和认证 owner。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ServerTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2DataSubmitter.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
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

    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
    using Net::experimental::awaitable_operators::operator||;
    using Http2ReadyChannel =
        Net::experimental::channel<void(boost::system::error_code, Http2ServerResult)>;

    /**
     * @brief 保留 TLS 握手失败时仍在场的唯一底层 owner，并沿原 admission ticket 完成退休。
     * @details SslHandshake 失败时返回仍活跃的 TLS stream 或交回的 raw；Stream 必须包装成
     *          Encrypted 并先 Track。容量满则将真实 owner 作为拒绝 plane root 交给同一 ticket。
     *          首个握手 Failure 的 Code/Native 原样返回；Close 与 Activity Drain 仍由 Admission
     *          在载体原 executor 完成，失败未物理退休时保留同一 ticket 重试。
     */
    [[nodiscard]] inline auto RetireHttp2HandshakeFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Transport::Encrypted::HandshakeResult Handshake)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Failure = Handshake.Failure;
        if (Failure.Succeeded())
        {
            Failure = {Prism::Fault::Code::TlsHsfail};
        }

        if (Handshake.Stream)
        {
            auto Owner = std::make_shared<Prism::Transport::Encrypted>(
                std::move(Handshake.Stream), std::move(Handshake.Bytes));
            auto Child = std::static_pointer_cast<Prism::Transmission>(Owner);
            const auto Tracked = Admission.Track(Child);
            if (!Tracked)
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Child), {}};
                const auto Rejected = co_await Admission.Reject(std::move(Plane), Failure);
                Owner.reset();
                co_return Rejected.error();
            }
        }
        else if (Handshake.Recovered)
        {
            const auto Tracked = Admission.Track(Handshake.Recovered);
            if (!Tracked)
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{
                    std::move(Handshake.Recovered), {}};
                const auto Rejected = co_await Admission.Reject(std::move(Plane), Failure);
                co_return Rejected.error();
            }
        }

        co_return co_await Admission.Retire(Failure);
    }
    /**
     * @struct Http2DriverParameters
     * @brief HTTP/2 carrier driver 在挂起期间持有的完整 owning 状态。
     * @details session、wire、transport、TLS、握手通知、目标和 immutable binding
     *          共同存活到 callback/driver 结束，避免回调借用 Run 的局部变量。
     */
    struct Http2DriverParameters
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<Http2ReadyChannel> Ready;
        std::shared_ptr<std::string> Target;
        SharedWireAuthBinding Binding;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        std::shared_ptr<CarrierOwner> Carrier;
    };

    /** @brief 等待 CONNECT wire proof，并保留超时、channel 和认证拒绝的正式失败。 */
    [[nodiscard]] inline auto WaitHttp2ServerReady(
        const std::shared_ptr<Http2ReadyChannel> &Ready,
        Net::any_io_executor Executor) -> Net::awaitable<Http2ServerResult>
    {
        Net::steady_timer Deadline(std::move(Executor));
        Deadline.expires_after(std::chrono::seconds(30));
        boost::system::error_code ReadyError;
        auto Wait = Ready->async_receive(Net::redirect_error(Net::use_awaitable, ReadyError));
        auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await (std::move(Wait) || std::move(DeadlineWait));
        if (Result.index() == 1)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }
        if (ReadyError)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ReadyError)));
        }
        co_return std::get<0>(Result);
    }

    /**
     * @brief 接收并认证服务端 HTTP/2 CONNECT request。
     * @details TLS、HTTP/2 settings、认证、stream 绑定和 carrier driver 由本 owner
     *          统一持有；返回成功的 Transmission 后，调用方继续负责上游转发。
     */
    class Http2Accept final : public std::enable_shared_from_this<Http2Accept>
    {
    public:
        explicit Http2Accept(Http2AcceptRequest Request)
            : Raw_(std::move(Request.Raw)), SslContext_(Request.SslContext),
              Binding_(std::move(Request.Binding)), Bytes_(std::move(Request.Bytes))
        {
        }

        [[nodiscard]] auto Run(Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<std::expected<Http2Accepted, Prism::Fault::Failure>>
        {
            if (!Binding_ || !Bytes_)
            {
                co_return std::unexpected(co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
            }
            auto Handshake = co_await Prism::Transport::Encrypted::SslHandshake(
                {std::move(Raw_), SslContext_,
                 std::chrono::steady_clock::now() + Prism::Transport::Encrypted::DefaultHandshakeTimeout,
                 std::move(Bytes_)});
            if (Handshake.Failure.Failed() || !Handshake.Stream)
            {
                const auto Failure = co_await RetireHttp2HandshakeFailure(
                    Admission, std::move(Handshake));
                co_return std::unexpected(Failure);
            }
            auto Encrypted = std::make_shared<Prism::Transport::Encrypted>(
                std::move(Handshake.Stream), std::move(Handshake.Bytes));
            const auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Encrypted));
            if (!Tracked)
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{Encrypted, {}};
                const auto Rejected = co_await Admission.Reject(
                    std::move(Plane), Tracked.error());
                co_return std::unexpected(Rejected.error());
            }
            const auto Prepared = co_await PrepareServerDriver(
                Encrypted, Admission, std::move(Binding_));
            if (!Prepared) co_return std::unexpected(Prepared.error());
            const auto Driver = *Prepared;
            const auto Owner = Driver->Carrier;
            const auto Ready = Driver->Ready;
            const auto Target = Driver->Target;
            Http2ServerResult ReadyResult;
            Prism::Fault::Failure ReadyException;
            try
            {
                ReadyResult = co_await WaitHttp2ServerReady(
                    Ready, Encrypted->Executor());
            }
            catch (...)
            {
                ReadyException = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            if (ReadyException.Failed())
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner, ReadyException));
            if (!ReadyResult)
            {
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner, ReadyResult.error()));
            }
            auto Accepted = AuthenticatedTransport::CreateForHandshake(Owner, *Target);
            if (!Accepted)
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner,
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError}));
            Admission.Release();
            co_return Http2Accepted{*Target, std::move(Accepted)};
        }

    private:
        [[nodiscard]] static auto RetireServerFailure(
            Prism::Contract::InboundAdmission &Admission,
            const std::shared_ptr<CarrierOwner> &Owner,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            Owner->Lifecycle->RecordFailure(Cause);
            const auto Drained = co_await Owner->Drain();
            if (Owner->IsRetired())
            {
                Admission.Release();
                const auto First = Owner->Lifecycle->Failure();
                if (First.Failed()) co_return First;
                co_return Cause;
            }

            auto AdmissionCause = Cause;
            if (AdmissionCause.Succeeded() && !Drained)
                AdmissionCause = Drained.error();
            const auto Inbound = co_await Admission.Retire(AdmissionCause);
            const auto First = Owner->Lifecycle->Failure();
            if (First.Failed()) co_return First;
            if (!Drained) co_return Drained.error();
            co_return Inbound;
        }

        [[nodiscard]] static auto PrepareServerDriver(
            std::shared_ptr<Prism::Transport::Encrypted> Encrypted,
            Prism::Contract::InboundAdmission &Admission,
            SharedWireAuthBinding Binding)
            -> Net::awaitable<std::expected<
                std::shared_ptr<Http2DriverParameters>, Prism::Fault::Failure>>
        {
            auto Session = std::make_shared<H2::Session>(Encrypted->Executor(), true);
            auto Wire = MakeHttp2Wire(Encrypted);
            auto Ready = std::make_shared<Http2ReadyChannel>(Encrypted->Executor(), 1);
            auto Target = std::make_shared<std::string>();
            auto Transport = std::make_shared<Http2Transport>(Http2Transport::Options{
                .Executor = Encrypted->Executor(),
                .Write = Http2ServerDataWriter{Session, Wire},
                .Finish = Http2ServerFinisher{Session, Wire},
                .Close = Http2Transport::CloseCb{}});
            auto Lifecycle = std::make_shared<CarrierLifecycle>(Encrypted->Executor());
            auto Owner = std::make_shared<CarrierOwner>(CarrierOwnerLayers{
                Transport, Wire, Encrypted, Lifecycle, Binding});
            auto Driver = std::make_shared<Http2DriverParameters>(Http2DriverParameters{
                Session, Wire, Transport, Encrypted, Ready, Target, std::move(Binding),
                Lifecycle, Owner});
            Lifecycle->DriverState = Driver;
            const std::weak_ptr<Http2DriverParameters> WeakDriver = Driver;
            Session->OnHeaders = [WeakDriver](
                std::int32_t StreamId, const H2::HeaderList &Headers, bool)
            {
                if (const auto Value = WeakDriver.lock())
                    Http2Accept::HandleHeaders(*Value, StreamId, Headers);
            };
            Session->OnData = [WeakDriver](
                std::int32_t StreamId, std::span<const std::byte> Data)
            {
                if (const auto Value = WeakDriver.lock())
                    Http2Accept::HandleData(*Value, StreamId, Data);
            };
            Session->OnStreamClose = [WeakDriver](
                const Prism::Http2::StreamReceiveClosure &Closure)
            {
                if (const auto Value = WeakDriver.lock())
                    Http2Accept::HandleStreamClose(*Value, Closure);
            };

            Session->SendSettings();
            Http2ServerResult SettingsFlushed;
            Prism::Fault::Failure SettingsException;
            try
            {
                SettingsFlushed = co_await FlushHttp2Frames(Session, Wire);
            }
            catch (...)
            {
                SettingsException = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            if (SettingsException.Failed())
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner, SettingsException));
            if (!SettingsFlushed)
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner, SettingsFlushed.error()));

            const auto DriverStart = StartDriver(Driver);
            if (DriverStart.Failed())
                co_return std::unexpected(co_await RetireServerFailure(
                    Admission, Owner, DriverStart));
            co_return Driver;
        }

        static auto HandleHeaders(Http2DriverParameters &Parameters, std::int32_t StreamId,
                                  const H2::HeaderList &Headers) -> void
        {
            if (Parameters.Transport->StreamId_ >= 0)
            {
                return;
            }
            bool IsConnect = false;
            std::string_view Authority;
            std::string_view Authorization;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":method" && Header.Value == "CONNECT")
                {
                    IsConnect = true;
                }
                else if (Header.Name == ":authority")
                {
                    Authority = Header.Value;
                }
                else if (Header.Name == "proxy-authorization")
                {
                    Authorization = Header.Value;
                }
            }
            if (!IsConnect || Authority.empty() ||
                !VerifyBasicAuth(Authorization, Parameters.Binding->Configuration.username,
                                 Parameters.Binding->Configuration.password))
            {
                auto Failure = Prism::Fault::Failure{Prism::Fault::Code::AuthFailed};
                const auto Reset = Parameters.Session->ResetStream(StreamId, 7);
                if (!Reset)
                {
                    Failure = Reset.error();
                    Parameters.Lifecycle->RecordFailure(Failure);
                }
                PublishReady(Parameters, std::unexpected(Failure));
                return;
            }
            *Parameters.Target = std::string(Authority);
            Parameters.Transport->SetAuthority(*Parameters.Target);
            Parameters.Transport->BindStream(StreamId);
            const auto HeaderResult = Parameters.Session->SubmitHeaders(
                StreamId, {{":status", "200"}}, false);
            if (!HeaderResult)
            {
                const auto Failure = HeaderResult.error();
                Parameters.Lifecycle->RecordFailure(Failure);
                PublishReady(Parameters, std::unexpected(Failure));
                return;
            }
            PublishReady(Parameters, Http2ServerResult{});
        }

        static auto PublishReady(Http2DriverParameters &Parameters, Http2ServerResult Result)
            -> void
        {
            const auto Sent = Parameters.Ready->try_send(
                boost::system::error_code{}, std::move(Result));
            if (!Sent)
            {
                Parameters.Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
        }

        static auto HandleData(Http2DriverParameters &Parameters, std::int32_t StreamId,
                               std::span<const std::byte> Data) -> void
        {
            if (StreamId == Parameters.Transport->StreamId_)
            {
                Parameters.Transport->Push(Data);
            }
        }

        static auto HandleStreamClose(
            Http2DriverParameters &Parameters,
            const Prism::Http2::StreamReceiveClosure &Closure) -> void
        {
            if (Closure.StreamId == Parameters.Transport->StreamId_)
            {
                if (Closure.Kind == H2::StreamReceiveClosureKind::Reset)
                {
                    auto Code = Prism::Fault::Code::ProtocolError;
                    if (Closure.ErrorCode == H2::ErrorNoError)
                    {
                        Code = Prism::Fault::Code::ConnectionReset;
                    }
                    const Prism::Fault::Failure Failure{Code};
                    Parameters.Lifecycle->RecordFailure(Failure);
                    Parameters.Transport->NotifyError(Failure);
                }
                else
                {
                    Parameters.Transport->NotifyEof();
                }
            }
        }

        static auto FinishDriver(
            const std::shared_ptr<Http2DriverParameters> &Driver,
            const Prism::Fault::Failure Failure) -> void
        {
            if (!Driver)
            {
                return;
            }
            if (Driver->Lifecycle) Driver->Lifecycle->RecordFailure(Failure);
            if (Driver->Session)
            {
                Driver->Session->OnHeaders = {};
                Driver->Session->OnData = {};
                Driver->Session->OnStreamClose = {};
            }
            if (Driver->Transport)
            {
                if (Failure.Failed())
                    Driver->Transport->NotifyError(Failure);
                else
                    Driver->Transport->NotifyEof();
                const auto Closed = Driver->Transport->Close();
                if (!Closed && Driver->Lifecycle)
                    Driver->Lifecycle->RecordFailure(Closed.error());
            }
            if (Driver->Wire)
            {
                Driver->Wire->Close();
            }
            if (Driver->Encrypted)
            {
                const auto Closed = Driver->Encrypted->Close();
                if (!Closed && Driver->Lifecycle)
                    Driver->Lifecycle->RecordFailure(Closed.error());
            }
            if (Driver->Ready)
            {
                auto ReadyFailure = Failure;
                if (ReadyFailure.Succeeded())
                    ReadyFailure = {Prism::Fault::Code::Eof};
                PublishReady(*Driver, std::unexpected(ReadyFailure));
            }
            Driver->Binding.reset();
            Driver->Target.reset();
            Driver->Ready.reset();
            Driver->Lifecycle.reset();
            Driver->Transport.reset();
            Driver->Wire.reset();
            Driver->Session.reset();
            Driver->Encrypted.reset();
        }

        struct DriverCompletion final
        {
            std::shared_ptr<CarrierLifecycle> Lifecycle;
            std::shared_ptr<Http2DriverParameters> Driver;

            auto operator()(std::exception_ptr Exception) -> void
            {
                if (Exception && Driver)
                {
                    const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception));
                    if (Lifecycle) Lifecycle->RecordFailure(Failure);
                    Http2Accept::FinishDriver(Driver, Failure);
                }
                Driver.reset();
                if (Lifecycle) Lifecycle->CompleteDriver();
            }
        };

        static auto StartDriver(const std::shared_ptr<Http2DriverParameters> &Driver)
            -> Prism::Fault::Failure
        {
            if (!Driver || !Driver->Encrypted)
            {
                return {Prism::Fault::Code::InvalidArgument};
            }
            const auto Lifecycle = Driver->Lifecycle;
            if (Lifecycle) Lifecycle->StartDriver();
            auto CompletionDriver = Driver;
            try
            {
                Net::co_spawn(
                    Driver->Encrypted->Executor(), RunDriver(Driver),
                    DriverCompletion{Lifecycle, std::move(CompletionDriver)});
            }
            catch (...)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                if (Lifecycle) Lifecycle->RecordFailure(Failure);
                FinishDriver(Driver, Failure);
                if (Lifecycle) Lifecycle->CompleteDriver();
                return Failure;
            }
            return {};
        }

        static auto RunDriver(std::shared_ptr<Http2DriverParameters> Driver)
            -> Net::awaitable<void>
        {
            std::array<std::byte, 16384> Buffer{};
            Prism::Fault::Failure Failure;
            while (true)
            {
                const auto Part = co_await Driver->Encrypted->ReadSome(Buffer);
                if (Part.Failure.Failed())
                {
                    if (Part.Failure.Code != Prism::Fault::Code::Eof &&
                        Part.Failure.Code != Prism::Fault::Code::Canceled)
                        Failure = Part.Failure;
                    break;
                }
                if (Part.Bytes == 0) break;
                if (Part.Bytes > Buffer.size())
                {
                    Failure = Prism::Fault::Failure{Prism::Fault::Code::IoError};
                    break;
                }
                std::error_code FeedError;
                const auto ReadWindow = std::span<const std::byte>(Buffer.data(), Part.Bytes);
                if (!Driver->Session->Feed(ReadWindow, FeedError) &&
                    FeedError != make_error_code(Prism::Error::NeedMore))
                {
                    if (FeedError)
                    {
                        Failure = Prism::Fault::FromNative(FeedError);
                    }
                    else
                    {
                        Failure = {Prism::Fault::Code::ProtocolError};
                    }
                    break;
                }
                const auto Flushed = co_await FlushHttp2Frames(Driver->Session, Driver->Wire);
                if (!Flushed)
                {
                    Failure = Flushed.error();
                    break;
                }
            }
            FinishDriver(Driver, Failure);
        }

        SharedTransmission Raw_;
        Net::ssl::context &SslContext_;
        SharedWireAuthBinding Binding_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
    };
} // namespace Prism::Trusttunnel::Detail
