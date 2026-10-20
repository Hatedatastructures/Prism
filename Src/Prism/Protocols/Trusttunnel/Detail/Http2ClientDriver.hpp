/**
 * @file Http2ClientDriver.hpp
 * @brief TrustTunnel HTTP/2 client 的 driver、accepted state 与真实退休 owner。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ClientTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
    using Net::experimental::awaitable_operators::operator||;
    struct Http2TlsClientRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        std::string ServerName;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };
    using Http2ResponseChannel =
        Net::experimental::channel<void(boost::system::error_code, Http2ClientResult)>;

    struct Http2ClientState final
    {
        explicit Http2ClientState(Net::any_io_executor ExecutorValue)
            : Domain(std::move(ExecutorValue)),
              Lifecycle(std::make_shared<CarrierLifecycle>(Domain))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Domain; }

        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult;

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Retired.load(std::memory_order_acquire);
        }

        Net::any_io_executor Domain;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2ResponseChannel> Response;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        std::shared_ptr<CarrierOwner> Carrier;
        std::atomic<bool> Retired{false};
        Prism::Fault::FailureState Failure;
    };

    struct Http2ClientDataWriter final
    {
        std::weak_ptr<H2::Session> Session;
        std::weak_ptr<Http2WireWriter> Wire;

        struct Request final
        {
            std::weak_ptr<H2::Session> Session;
            std::weak_ptr<Http2WireWriter> Wire;
            std::int32_t StreamId{0};
            std::span<const std::byte> Data;
        };

        [[nodiscard]] static auto Run(Request Value) -> Net::awaitable<Http2ClientResult>;

        [[nodiscard]] auto operator()(const std::int32_t StreamId,
                                      const std::span<const std::byte> Data) const
            -> Net::awaitable<Http2ClientResult>;
    };

    struct Http2ClientFinisher final
    {
        std::weak_ptr<H2::Session> Session;
        std::weak_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(const std::int32_t StreamId) const
            -> Net::awaitable<Http2ClientResult>;

        [[nodiscard]] static auto Run(const std::weak_ptr<H2::Session> &SessionReference,
                                      const std::weak_ptr<Http2WireWriter> &WireReference,
                                      const std::int32_t StreamId) -> Net::awaitable<Http2ClientResult>;
    };

    struct Http2ClientHeadersEvent final
    {
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2ResponseChannel> Response;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        std::int32_t StreamId{0};
        const H2::HeaderList &Headers;
    };

    auto HandleHttp2ClientHeaders(Http2ClientHeadersEvent Input) -> void;

    struct Http2ClientHeadersObserver final
    {
        std::weak_ptr<Http2Transport> Transport;
        std::weak_ptr<Http2ResponseChannel> Response;
        std::weak_ptr<CarrierLifecycle> Lifecycle;

        auto operator()(
            const std::int32_t StreamId, const H2::HeaderList &Headers, const bool) const -> void;
    };

    auto HandleHttp2ClientData(
        const std::shared_ptr<Http2Transport> &Transport,
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void;

    auto HandleHttp2ClientClose(
        const std::shared_ptr<Http2Transport> &Transport,
        const std::shared_ptr<CarrierLifecycle> &Lifecycle,
        const H2::StreamReceiveClosure &Closure) -> void;

    [[nodiscard]] auto CloseHttp2ClientCarrier(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        const std::shared_ptr<Http2WireWriter> &Wire)
        -> Http2ClientResult;

    [[nodiscard]] auto MakeHttp2ClientState(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2ClientState>;

    [[nodiscard]] auto RunHttp2ClientDriver(
        std::shared_ptr<Http2ClientState> State) -> Net::awaitable<Prism::Fault::Failure>;

    struct Http2ClientDriverCompletion final
    {
        std::shared_ptr<Http2ClientState> State;

        auto operator()(
            std::exception_ptr Exception,
            Prism::Fault::Failure Failure) const noexcept -> void;
    };

    auto StartHttp2ClientDriver(std::shared_ptr<Http2ClientState> State)
        -> Prism::Fault::Failure;

    [[nodiscard]] auto FlushHttp2ClientFrames(const std::shared_ptr<Http2ClientState> &State)
        -> Net::awaitable<Http2ClientResult>;

    [[nodiscard]] auto RetireHttp2ClientFactory(
        Prism::Contract::InboundAdmission &Admission,
        const std::shared_ptr<Http2ClientState> &State,
        Prism::Fault::Failure Cause)
        -> Net::awaitable<Prism::Fault::Failure>;


} // namespace Prism::Trusttunnel::Detail
