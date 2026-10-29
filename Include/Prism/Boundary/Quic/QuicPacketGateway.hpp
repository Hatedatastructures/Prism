/**
 * @file QuicPacketGateway.hpp
 * @brief Prism UDP 入口中的 QUIC CID 生命周期与包接收边界。
 * @details Gateway 不解析应用协议；协议 descriptor/QUIC engine 通过
 *          PacketHandler 接入，Gateway 只拥有 CID 表、预算和 shutdown 状态。
 */
#pragma once

#include <Prism/Boundary/Datagram/Classifier.hpp>
#include <Prism/Boundary/Quic/QuicAdmissionBudget.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

namespace Prism::Boundary
{

    enum class QuicReadiness : std::uint8_t
    {
        Offline,
        Socket,
        ReceiveLoop,
        Handshake,
        Protocol,
        Draining,
        Closed,
        Failed,
    };

    struct QuicPacketGatewayHealth final
    {
        bool SocketReady{false};
        bool ReceiveLoopReady{false};
        bool HandshakeReady{false};
        bool ProtocolReady{false};
        bool Draining{false};
        bool BoundedFailure{false};
        std::size_t Connections{0};
        std::size_t Packets{0};
        QuicReadiness Readiness{QuicReadiness::Offline};

        [[nodiscard]] auto Healthy() const noexcept -> bool;
    };

    struct QuicPacketGatewayOptions final
    {
        /** @brief 必填；由入口 owner 创建，并复用于对应的 connection registry。 */
        std::shared_ptr<QuicAdmissionBudget> AdmissionBudget;
        std::function<void(const BoundaryPacket &)> OnPacket;
        std::function<bool(const BoundaryPacket &)> Dispatch;
    };

    class QuicPacketGateway final
    {
    public:
        explicit QuicPacketGateway(QuicPacketGatewayOptions OptionsValue);

        auto MarkSocketReady() noexcept -> void;

        auto MarkReceiveLoopReady() noexcept -> void;

        auto MarkHandshakeReady() noexcept -> void;

        auto MarkProtocolReady() noexcept -> void;

        [[nodiscard]] auto RegisterConnection(
            std::span<const std::byte> ConnectionId,
            std::function<bool(const BoundaryPacket &)> Handler) -> bool;

        /** @brief 接受 owner 的真实关闭回执并返还唯一 admission 槽。 */
        auto OnConnectionClosed(std::span<const std::byte> ConnectionId) -> bool;

        /**
         * @brief 同步借用数据包完成连接查找与接纳，不转移或修改输入所有权。
         * @return 接纳成功返回 true；未知连接、关闭、预算或处理器失败返回 false。
         * @note 回调仅在调用期间借用数据包，不得保存其引用；拒绝后调用者仍可完整回落。
         *       在网关所属 executor 串行调用，无挂起、取消或半关闭；最终关闭由 Close 负责。
         */
        [[nodiscard]] auto Handle(const BoundaryPacket &Packet) -> bool;

        auto Drain() noexcept -> void;

        auto Close() noexcept -> void;

        [[nodiscard]] auto Health() const noexcept -> QuicPacketGatewayHealth;

        [[nodiscard]] auto ConnectionCount() const noexcept -> std::size_t;

        /** @brief 返回应用创建的同一 typed 预算，供 Registry 注入唯一容量事实。 */
        [[nodiscard]] auto AdmissionBudget() const noexcept
            -> std::shared_ptr<QuicAdmissionBudget>;

        [[nodiscard]] auto Readiness() const noexcept -> QuicReadiness;

    private:
        static constexpr std::size_t MaxConnectionIdLength = 20U;

        struct ConnectionState final
        {
            std::function<bool(const BoundaryPacket &)> Handler;
            std::shared_ptr<QuicAdmissionBudget::Reservation> Admission;
        };

        [[nodiscard]] static auto MakeCidKey(std::span<const std::byte> ConnectionId) -> std::string;

        auto MarkBoundedFailure() noexcept -> void;

        QuicPacketGatewayOptions Options_;
        std::unordered_map<std::string, ConnectionState> Connections_;
        bool SocketReady_{false};
        bool ReceiveLoopReady_{false};
        bool HandshakeReady_{false};
        bool ProtocolReady_{false};
        bool Draining_{false};
        bool Closed_{false};
        bool BoundedFailure_{false};
        QuicReadiness Readiness_{QuicReadiness::Offline};
    };

    using SharedQuicPacketGateway = std::shared_ptr<QuicPacketGateway>;

} // namespace Prism::Boundary
