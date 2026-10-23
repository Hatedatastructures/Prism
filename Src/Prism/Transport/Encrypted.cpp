/** @file Encrypted.cpp @brief TLS stream 装饰层、writer driver 与握手实现。 */
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/TlsStream.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <Prism/Transport/WriteDriver.hpp>

#include <boost/asio/deferred.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <openssl/ssl.h>

#include <chrono>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Transport::Detail
{
    class TlsWriteDriver final : public WriteDriver
    {
    public:
        explicit TlsWriteDriver(std::shared_ptr<TlsStream> Stream)
            : Stream_(std::move(Stream)),
              Activity_(MakeActivityGroup(
                  Stream_->Activity(),
                  std::vector<std::shared_ptr<Contract::CarrierActivity>>{
                      Stream_->next_layer().NextLayer()->Activity()}))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Stream_->get_executor();
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Contract::CarrierActivity> override
        {
            return Activity_;
        }

        auto WritePartial(std::span<const std::byte> Buffer,
                          Completion Handler) -> void override
        {
            Stream_->WriteSome(Buffer, std::move(Handler));
        }

        auto WriteShutdown(Completion Handler) -> void override
        {
            Stream_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto Cancel() -> ControlResult override
        {
            if (auto *Inner = Stream_->next_layer().NextLayer()) return Inner->Cancel();
            return {};
        }

        [[nodiscard]] auto Close() -> ControlResult override
        {
            if (auto *Inner = Stream_->next_layer().NextLayer()) return Inner->Close();
            return {};
        }

    private:
        std::shared_ptr<TlsStream> Stream_;
        std::shared_ptr<Contract::CarrierActivity> Activity_;
    };
}

namespace Prism::Transport
{
    Encrypted::Encrypted(SharedStream Stream, std::shared_ptr<Memory::BytePool> Bytes)
        : Transmission(Stream->get_executor()), Stream_(std::move(Stream)),
          Writer_(std::make_shared<Writer>(
              std::move(Bytes), std::make_shared<Detail::TlsWriteDriver>(Stream_))),
          Activity_(MakeActivityGroup(
              Transmission::Activity(),
              std::vector<std::shared_ptr<Contract::CarrierActivity>>{
                  Writer_->Activity(), Stream_->Activity()}))
    {
    }

    auto Encrypted::Activity() const noexcept
        -> std::shared_ptr<Contract::CarrierActivity>
    {
        if (Activity_) return Activity_;
        return Transmission::Activity();
    }

    auto Encrypted::NextLayer() noexcept -> Transmission*
    {
        if (!Stream_) return nullptr;
        return Stream_->next_layer().NextLayer();
    }

    auto Encrypted::NextLayer() const noexcept -> const Transmission*
    {
        if (!Stream_) return nullptr;
        return Stream_->next_layer().NextLayer();
    }

    auto Encrypted::Stream() noexcept -> StreamType&
    {
        return *Stream_;
    }

    auto Encrypted::Stream() const noexcept -> const StreamType&
    {
        return *Stream_;
    }

    auto Encrypted::ReleaseStream() -> std::expected<SharedStream, Fault::Failure>
    {
        if (!Stream_)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }
        if (!IoIdle() || !Writer_->IsIdle() || !Stream_->IsIdle())
        {
            return std::unexpected(Fault::Failure{Fault::Code::WouldBlock});
        }
        auto Result = std::move(Stream_);
        Writer_.reset();
        Activity_.reset();
        return Result;
    }

    auto Encrypted::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (!Stream_)
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler),
                               {0, {Fault::Code::InvalidArgument}});
            return;
        }
        Stream_->ReadSome(Buffer, std::move(Handler));
    }

    auto Encrypted::StartWrite(std::span<const std::byte> Buffer,
                               Completion Handler) -> void
    {
        if (!Stream_)
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler),
                               {0, {Fault::Code::InvalidArgument}});
            return;
        }
        Writer_->Write(Buffer, std::move(Handler));
    }

    auto Encrypted::StartWriteShutdown(Completion Handler) -> void
    {
        if (!Stream_)
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler),
                               {0, {Fault::Code::InvalidArgument}});
            return;
        }
        Writer_->WriteShutdown(std::move(Handler));
    }

    auto Encrypted::OnClose() -> ControlResult
    {
        if (!Stream_) return {};
        return Writer_->Close();
    }

    auto Encrypted::OnCancel() -> ControlResult
    {
        if (!Stream_) return {};
        return Writer_->Cancel();
    }

    auto Encrypted::HandshakeFailure(const SharedStream &Stream,
                                     boost::system::error_code Error) -> Fault::Failure
    {
        auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
        if (Error.category() == Net::error::get_ssl_category() ||
            Error.category() == Net::ssl::error::get_stream_category())
        {
            Failure.Code = Fault::Code::TlsHsfail;
            auto *PeerCertificate = SSL_get_peer_certificate(Stream->native_handle());
            const bool HasPeerCertificate = PeerCertificate != nullptr;
            if (PeerCertificate)
            {
                X509_free(PeerCertificate);
            }
            // 没有对端证书时不使用 verify_result 覆盖真实的协议/密码套件告警。
            if (HasPeerCertificate &&
                SSL_get_verify_result(Stream->native_handle()) != X509_V_OK)
            {
                Failure.Code = Fault::Code::Verifyfail;
            }
        }
        return Failure;
    }

    auto Encrypted::ReadNegotiatedTlsInfo(const SharedStream &Stream)
        -> NegotiatedTlsInfo
    {
        NegotiatedTlsInfo Result;
        const auto *Tls = Stream->native_handle();
        if (const auto *ServerName = SSL_get_servername(Tls, TLSEXT_NAMETYPE_host_name))
        {
            Result.ServerName = ServerName;
        }
        const std::uint8_t *Alpn = nullptr;
        unsigned AlpnLength = 0;
        SSL_get0_alpn_selected(Tls, &Alpn, &AlpnLength);
        if (Alpn && AlpnLength != 0)
        {
            Result.Alpn.assign(reinterpret_cast<const char *>(Alpn), AlpnLength);
        }
        if (const auto *Version = SSL_get_version(Tls))
        {
            Result.Version = Version;
        }
        Result.EchAccepted = SSL_ech_accepted(Tls) == 1;
        return Result;
    }

    auto Encrypted::SslHandshake(HandshakeRequest Request)
        -> Net::awaitable<HandshakeResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        HandshakeResult Result;
        Result.Bytes = std::move(Request.Bytes);
        if (!Request.Inbound || !Result.Bytes)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            Result.Recovered = std::move(Request.Inbound);
            co_return Result;
        }
        if (Request.Deadline <= std::chrono::steady_clock::now())
        {
            Result.Failure = {Fault::Code::Timeout};
            Result.Recovered = std::move(Request.Inbound);
            co_return Result;
        }
        auto Stream = std::make_shared<StreamType>(
            Connector(std::move(Request.Inbound)), Request.Context.get());
        if (Request.Role == HandshakeRole::Client && !Request.ServerName.empty() &&
            SSL_set_tlsext_host_name(
                Stream->native_handle(), Request.ServerName.c_str()) != 1)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            Result.Recovered = Stream->next_layer().Release();
            co_return Result;
        }
        if (Request.Role == HandshakeRole::Server && !Request.ServerName.empty())
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            Result.Recovered = Stream->next_layer().Release();
            co_return Result;
        }
        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_at(Request.Deadline);
        const auto HandshakeType = Request.Role == HandshakeRole::Server
                                       ? Net::ssl::stream_base::server
                                       : Net::ssl::stream_base::client;
        auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
            Stream->async_handshake(HandshakeType, Net::deferred),
            Deadline.async_wait(Net::deferred))
            .async_wait(Net::experimental::wait_for_one(), Net::use_awaitable);
        if (Error) Result.Failure = HandshakeFailure(Stream, Error);
        if (Order[0] == 1 && !TimerError) Result.Failure.Code = Fault::Code::Timeout;
        if (Result.Failure.Succeeded())
        {
            Result.Negotiated = ReadNegotiatedTlsInfo(Stream);
            Result.Stream = std::move(Stream);
            co_return Result;
        }
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Drained = co_await Stream->Activity()->Drain();
        if (!Drained)
        {
            Result.Failure = Drained.error();
            Result.Stream = std::move(Stream);
            co_return Result;
        }
        Result.Recovered = Stream->next_layer().Release();
        co_return Result;
    }

    auto MakeEncrypted(Encrypted::SharedStream Stream,
                       std::shared_ptr<Memory::BytePool> Bytes)
        -> SharedTransmission
    {
        return std::make_shared<Encrypted>(std::move(Stream), std::move(Bytes));
    }
}
