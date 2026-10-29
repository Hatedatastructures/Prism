/** @file Types.hpp @brief Boundary QUIC 注册表的 CID 与诊断值。 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <vector>

namespace Prism::Boundary
{

    using QuicConnectionId = std::vector<std::byte>;

    /** @brief QUIC CID 注册表诊断阶段。 */
    enum class QuicConnectionRegistryStage : std::uint8_t
    {
        PacketReceived,
        SessionIdentityUnavailable,
        FactoryCalled,
        FactoryReturned,
        FactoryReturnedNull,
        ServerStarted,
        ReceiveAccepted,
        ReceiveRejected
    };

    /** @brief 一次注册表诊断事件快照。 */
    struct QuicConnectionRegistryEvent final
    {
        QuicConnectionRegistryStage Stage{QuicConnectionRegistryStage::PacketReceived};
        bool Accepted{false};
        std::size_t ActiveConnections{0};
    };

    using QuicConnectionRegistryEventHandler =
        std::function<void(QuicConnectionRegistryEvent)>;

    /** @brief 返回注册表阶段的稳定诊断名称。 */
    [[nodiscard]] constexpr auto QuicConnectionRegistryStageName(
        const QuicConnectionRegistryStage Stage) noexcept -> std::string_view
    {
        switch (Stage)
        {
        case QuicConnectionRegistryStage::PacketReceived: return "PacketReceived";
        case QuicConnectionRegistryStage::SessionIdentityUnavailable: return "SessionIdentityUnavailable";
        case QuicConnectionRegistryStage::FactoryCalled: return "FactoryCalled";
        case QuicConnectionRegistryStage::FactoryReturned: return "FactoryReturned";
        case QuicConnectionRegistryStage::FactoryReturnedNull: return "FactoryReturnedNull";
        case QuicConnectionRegistryStage::ServerStarted: return "ServerStarted";
        case QuicConnectionRegistryStage::ReceiveAccepted: return "ReceiveAccepted";
        case QuicConnectionRegistryStage::ReceiveRejected: return "ReceiveRejected";
        }
        return "Unknown";
    }

} // namespace Prism::Boundary
