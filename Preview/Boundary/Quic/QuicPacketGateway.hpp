/**
 * @file QuicPacketGateway.hpp
 * @brief Preview UDP 入口中的 QUIC CID 生命周期与包接收边界。
 * @details Gateway 不解析应用协议；协议 descriptor/QUIC engine 通过
 *          PacketHandler 接入，Gateway 只拥有 CID 表、预算和 shutdown 状态。
 */
#pragma once

#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Boundary/Quic/QuicAdmissionBudget.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Boundary
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

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return SocketReady && ReceiveLoopReady && HandshakeReady && ProtocolReady &&
                   !Draining && !BoundedFailure;
        }
    };

    struct QuicPacketGatewayOptions final
    {
        std::shared_ptr<QuicAdmissionBudget> AdmissionBudget;
        std::function<void(const BoundaryPacket &)> OnPacket;
        std::function<bool(const BoundaryPacket &)> Dispatch;
    };

    class QuicPacketGateway final
    {
    public:
        explicit QuicPacketGateway(QuicPacketGatewayOptions OptionsValue)
            : Options_(std::move(OptionsValue))
        {
            if (!Options_.AdmissionBudget)
            {
                throw std::invalid_argument("QUIC admission budget is required");
            }
        }

        auto MarkSocketReady() noexcept -> void
        {
            if (!Closed_ && !Draining_ && !BoundedFailure_)
            {
                SocketReady_ = true;
                if (Readiness_ == QuicReadiness::Offline)
                {
                    Readiness_ = QuicReadiness::Socket;
                }
            }
        }

        auto MarkReceiveLoopReady() noexcept -> void
        {
            if (SocketReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                ReceiveLoopReady_ = true;
                if (Readiness_ == QuicReadiness::Socket)
                {
                    Readiness_ = QuicReadiness::ReceiveLoop;
                }
            }
        }

        auto MarkHandshakeReady() noexcept -> void
        {
            if (ReceiveLoopReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                HandshakeReady_ = true;
                if (Readiness_ == QuicReadiness::ReceiveLoop)
                {
                    Readiness_ = QuicReadiness::Handshake;
                }
            }
        }

        auto MarkProtocolReady() noexcept -> void
        {
            if (HandshakeReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                ProtocolReady_ = true;
                if (Readiness_ == QuicReadiness::Handshake)
                {
                    Readiness_ = QuicReadiness::Protocol;
                }
            }
        }

        [[nodiscard]] auto RegisterConnection(
            std::span<const std::byte> ConnectionId,
            std::function<bool(const BoundaryPacket &)> Handler) -> bool
        {
            if (Closed_ || Draining_ || ConnectionId.empty() || ConnectionId.size() > MaxConnectionIdLength ||
                !Handler)
            {
                return false;
            }
            const auto Key = MakeCidKey(ConnectionId);
            if (Connections_.contains(Key))
            {
                return false;
            }
            auto Reservation = Options_.AdmissionBudget->TryReserve();
            if (!Reservation)
            {
                return false;
            }
            if (!Reservation->RetainOwner())
            {
                Reservation->Complete();
                return false;
            }
            auto State = ConnectionState{std::move(Handler), Reservation};
            try
            {
                const auto [It, Inserted] = Connections_.emplace(Key, std::move(State));
                (void)It;
                if (!Inserted)
                {
                    Reservation->Complete();
                    return false;
                }
            }
            catch (...)
            {
                Reservation->Complete();
                throw;
            }
            return true;
        }

        /** @brief 接受 owner 的真实关闭回执并返还唯一 admission 槽。 */
        auto OnConnectionClosed(std::span<const std::byte> ConnectionId) -> bool
        {
            if (ConnectionId.empty())
            {
                return false;
            }
            const auto It = Connections_.find(MakeCidKey(ConnectionId));
            if (It == Connections_.end())
            {
                return false;
            }
            It->second.Admission->Complete();
            Connections_.erase(It);
            return true;
        }

        /**
         * @brief 同步借用数据包完成连接查找与接纳，不转移或修改输入所有权。
         * @return 接纳成功返回 true；未知连接、关闭、预算或处理器失败返回 false。
         * @note 回调仅在调用期间借用数据包，不得保存其引用；拒绝后调用者仍可完整回落。
         *       在网关所属 executor 串行调用，无挂起、取消或半关闭；最终关闭由 Close 负责。
         */
        [[nodiscard]] auto Handle(const BoundaryPacket &Packet) -> bool
        {
            if (Closed_ || Draining_ || Packet.Classification.Kind != DatagramKind::Quic ||
                Packet.Classification.ConnectionIdBytes.empty())
            {
                return false;
            }

            const auto It = Connections_.find(MakeCidKey(Packet.Classification.ConnectionIdBytes));
            if (It == Connections_.end())
            {
                return false;
            }
            auto *State = &It->second;
            if (!State->Admission->CanAcceptPacket())
            {
                MarkBoundedFailure();
                return false;
            }
            try
            {
                if (State->Handler && !State->Handler(Packet))
                {
                    MarkBoundedFailure();
                    return false;
                }
                if (Options_.Dispatch && !Options_.Dispatch(Packet))
                {
                    MarkBoundedFailure();
                    return false;
                }
            }
            catch (...)
            {
                MarkBoundedFailure();
                return false;
            }
            State->Admission->RecordAcceptedPacket();
            if (Options_.OnPacket)
            {
                try
                {
                    Options_.OnPacket(Packet);
                }
                catch (...)
                {
                    MarkBoundedFailure();
                    return false;
                }
            }
            return true;
        }

        auto Drain() noexcept -> void
        {
            Draining_ = true;
            HandshakeReady_ = false;
            ProtocolReady_ = false;
            Readiness_ = QuicReadiness::Draining;
        }

        auto Close() noexcept -> void
        {
            Drain();
            Closed_ = true;
            SocketReady_ = false;
            ReceiveLoopReady_ = false;
            Readiness_ = QuicReadiness::Closed;
        }

        [[nodiscard]] auto Health() const noexcept -> QuicPacketGatewayHealth
        {
            return {SocketReady_, ReceiveLoopReady_, HandshakeReady_, ProtocolReady_, Draining_,
                    BoundedFailure_, ConnectionCount(), Options_.AdmissionBudget->AcceptedPackets(), Readiness_};
        }

        [[nodiscard]] auto ConnectionCount() const noexcept -> std::size_t
        {
            return Options_.AdmissionBudget->ActiveConnections();
        }

        /** @brief 返回应用创建的同一 typed 预算，供 Registry 注入唯一容量事实。 */
        [[nodiscard]] auto AdmissionBudget() const noexcept
            -> std::shared_ptr<QuicAdmissionBudget>
        {
            return Options_.AdmissionBudget;
        }

        [[nodiscard]] auto Readiness() const noexcept -> QuicReadiness
        {
            return Readiness_;
        }

    private:
        static constexpr std::size_t MaxConnectionIdLength = 20U;

        struct ConnectionState final
        {
            std::function<bool(const BoundaryPacket &)> Handler;
            std::shared_ptr<QuicAdmissionBudget::Reservation> Admission;
        };

        [[nodiscard]] static auto MakeCidKey(std::span<const std::byte> ConnectionId) -> std::string
        {
            return {reinterpret_cast<const char *>(ConnectionId.data()), ConnectionId.size()};
        }

        auto MarkBoundedFailure() noexcept -> void
        {
            BoundedFailure_ = true;
            Readiness_ = QuicReadiness::Failed;
        }

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

} // namespace Preview::Boundary
