/**
 * @file UdpTunnel.hpp
 * @brief VLESS 普通 UDP 的固定目标与独立流入/UDP 回包 pump。
 * @details 流和 UDP socket 只承载 [uint16BE payload length][payload]；
 *          目标由握手固定，发送不等待对应回包，单一 reply loop 接收所有回包。
 */
#pragma once

#include <Prism/Contract/Ingress/Datagram/Session.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/Task/State.hpp>
#include <Prism/Protocols/Common/Datagram/Observation.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Protocols/Common/Datagram/Binding.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpTunnelFrames.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <vector>

namespace Prism::Vless
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;
    using Failure = Prism::Fault::Failure;
    using TunnelResult = std::expected<void, Failure>;

    struct UdpTunnelSummary final
    {
        std::uint64_t Datagrams{0};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
    };

    /** @brief VLESS 普通 UDP 的握手固定目标与会话服务。 */
    struct UdpTunnelOptions final
    {
        Prism::Contract::DatagramServices Services;
        Address Target;
        Prism::Lifecycle::TaskIdentity TaskIdentity{};
        Prism::AccountId AccountId{};
        std::function<void(const Address&)> OnFirstTarget{};
        std::function<void(const UdpTunnelSummary&)> OnSessionEnd{};
    };

    /**
     * @brief 运行固定目标普通 VLESS UDP 隧道。
     * @details 一个 reader 持有所有入站流帧，一个 reply writer 持有所有 UDP 回包写入；
     *          两者并行，故上游静默或多回包不会把发送路径变成一问一答。
     */
    class UdpTunnel final : public Prism::Contract::DatagramSession,
                            public Prism::Contract::CarrierActivity,
                            public std::enable_shared_from_this<UdpTunnel>
    {
    public:
        explicit UdpTunnel(std::shared_ptr<Conn<>> Stream, UdpTunnelOptions Options);

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;

        auto Seal() noexcept -> void override;
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        auto Cancel() noexcept -> void override;

        auto Close() noexcept -> void override;

    private:
        struct RunState;

        [[nodiscard]] static auto RequireStreamExecutor(const std::shared_ptr<Conn<>>& Stream)
            -> Net::any_io_executor;

        auto CancelOnExecutor() noexcept -> void;
        auto CloseOnExecutor() noexcept -> void;

        auto Execute() -> Net::awaitable<TunnelResult>;

        auto RunCore() -> Net::awaitable<TunnelResult>;

        [[nodiscard]] auto ResolveTarget() -> Net::awaitable<std::expected<Udp::endpoint, Failure>>;

        auto ReceiveFrames(const std::shared_ptr<RunState>& State, const Udp::endpoint Target)
            -> Net::awaitable<TunnelResult>;

        auto SendReplies(const std::shared_ptr<RunState>& State, const Udp::endpoint Target)
            -> Net::awaitable<TunnelResult>;

        [[nodiscard]] auto IsCloseCancellation(const Failure& Cause) const noexcept -> bool;

        auto RecordFailure(const Failure Value) noexcept -> void;

        auto Report() noexcept -> void;

        auto CloseResources() noexcept -> void;

        std::shared_ptr<Conn<>> Stream_;
        UdpTunnelOptions Options_;
        Net::strand<Net::any_io_executor> Executor_;
        UdpTunnelFrames Frames_;
        Udp::socket Egress_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> Activity_;
        std::shared_ptr<RunState> RunState_;
        Prism::Fault::FailureState RunFailure_;
        Prism::Foundation::TrafficObservation Observation_;
        Net::cancellation_signal Cancellation_;
        std::vector<std::uint8_t> TxFrame_;
        std::atomic<bool> CloseResourcesCompleted_{false};
        std::uint64_t DatagramCount_{0};
        std::uint64_t SentBytes_{0}, RecvBytes_{0};
        bool Started_{false}, Drained_{false}, Closed_{false}, Cancelled_{false}, Reported_{false};
    };
} // namespace Prism::Vless
