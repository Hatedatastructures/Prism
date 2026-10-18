/**
 * @file PublishPhase.hpp
 * @brief Prism 启动阶段的独立资源装配责任。
 */
#pragma once
#include <Prism/Application/Application.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
namespace Prism::Application::Startup::PublishPhase
{
    namespace Net = boost::asio;
    /** @brief 所有入口成功后在控制线程借用 Output 发布只读就绪状态；输出异常由外层事务回滚。 */
    inline auto Publish(const std::shared_ptr<Application::RuntimeState>& Runtime, std::ostream& Output)
        -> Readiness
    {
        const auto UdpHealth = Runtime->DatagramListener ? Runtime->DatagramListener->Health()
                                                         : Prism::Boundary::DatagramListenerHealth{};
        const auto QuicHealth = Runtime->QuicPacketGateway ? Runtime->QuicPacketGateway->Health()
                                                           : Prism::Boundary::QuicPacketGatewayHealth{};
        std::uint16_t OperationsPort = 0;
        if (Runtime->ManagementController)
        {
            OperationsPort = static_cast<std::uint16_t>(
                Runtime->ManagementController->LocalEndpoint().port());
        }
        std::uint16_t UdpPort = 0;
        if (UdpHealth.Bound)
        {
            UdpPort = static_cast<std::uint16_t>(
                Runtime->DatagramListener->LocalEndpoint().port());
        }
        Runtime->Ready = Readiness{Runtime->Listener->LocalEndpoint().port(),
            OperationsPort,
            Runtime->Generation->Id(),
            UdpPort,
            UdpHealth.Healthy(),
            !Runtime->Generation->Configuration().Listeners.Quic.empty() && QuicHealth.Healthy(),
            UdpHealth.Bound, QuicHealth.SocketReady, QuicHealth.HandshakeReady, QuicHealth.ProtocolReady};
        Runtime->Phase.store(RuntimePhase::Ready, std::memory_order_release);
        if (Runtime->Events)
        {
            Prism::Statistics::DetailedEvent Event;
            Event.Timestamp =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            Event.Generation = Runtime->Generation->Id();
            Event.Process = Runtime->Process->Id();
            Event.Kind = Prism::Statistics::EventKind::GenerationReloaded;
            Event.Severity = Prism::Statistics::EventSeverity::Info;
            Event.Detail = "application ready";
            (void)Runtime->Events->Append(std::move(Event));
        }
        (void)Prism::Diagnose::Debug(Runtime->RootContext, "RuntimeReady");
        Output << std::boolalpha
               << "Prism READY tcp_port=" << Runtime->Ready.Port
               << " udp_port=" << Runtime->Ready.UdpPort
               << " udp_ready=" << Runtime->Ready.UdpReady
               << " quic_ready=" << Runtime->Ready.QuicReady
               << " generation=" << Runtime->Ready.Generation.Value()
               << " quic_socket_ready=" << Runtime->Ready.QuicSocketReady
               << " quic_handshake_ready=" << Runtime->Ready.QuicHandshakeReady
               << " quic_protocol_ready=" << Runtime->Ready.QuicProtocolReady
               << std::noboolalpha << '\n'
               << std::flush;
        return Runtime->Ready;
    }
} // namespace Prism::Application::Startup::PublishPhase
