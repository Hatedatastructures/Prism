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
    [[nodiscard]] auto RetireHttp2HandshakeFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Transport::Encrypted::HandshakeResult Handshake)
        -> Net::awaitable<Prism::Fault::Failure>;
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
    [[nodiscard]] auto WaitHttp2ServerReady(
        const std::shared_ptr<Http2ReadyChannel> &Ready,
        Net::any_io_executor Executor) -> Net::awaitable<Http2ServerResult>;

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
            -> Net::awaitable<std::expected<Http2Accepted, Prism::Fault::Failure>>;

        /** @brief 供模块白盒测试观察已接管 carrier 的 driver 生命周期。 */
        [[nodiscard]] static auto GetLifecycleForTest(
            const Prism::Trusttunnel::AuthenticatedTransport &Transport) noexcept
            -> std::shared_ptr<CarrierLifecycle>
        {
            return Transport.Owner_->Lifecycle;
        }

    private:
        [[nodiscard]] static auto RetireServerFailure(
            Prism::Contract::InboundAdmission &Admission,
            const std::shared_ptr<CarrierOwner> &Owner,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto PrepareServerDriver(
            std::shared_ptr<Prism::Transport::Encrypted> Encrypted,
            Prism::Contract::InboundAdmission &Admission,
            SharedWireAuthBinding Binding)
            -> Net::awaitable<std::expected<
                std::shared_ptr<Http2DriverParameters>, Prism::Fault::Failure>>;

        static auto HandleHeaders(Http2DriverParameters &Parameters, std::int32_t StreamId,
                                  const H2::HeaderList &Headers) -> void;

        static auto PublishReady(Http2DriverParameters &Parameters, Http2ServerResult Result)
            -> void;

        static auto HandleData(Http2DriverParameters &Parameters, std::int32_t StreamId,
                               std::span<const std::byte> Data) -> void;

        static auto HandleStreamClose(
            Http2DriverParameters &Parameters,
            const Prism::Http2::StreamReceiveClosure &Closure) -> void;

        static auto FinishDriver(
            const std::shared_ptr<Http2DriverParameters> &Driver,
            const Prism::Fault::Failure Failure) -> void;

        struct DriverCompletion final
        {
            std::shared_ptr<CarrierLifecycle> Lifecycle;
            std::shared_ptr<Http2DriverParameters> Driver;

            auto operator()(std::exception_ptr Exception) -> void;
        };

        static auto StartDriver(const std::shared_ptr<Http2DriverParameters> &Driver)
            -> Prism::Fault::Failure;

        static auto RunDriver(std::shared_ptr<Http2DriverParameters> Driver)
            -> Net::awaitable<void>;

        SharedTransmission Raw_;
        Net::ssl::context &SslContext_;
        SharedWireAuthBinding Binding_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
    };
} // namespace Prism::Trusttunnel::Detail
