/** @file Observation.hpp @brief 数据报请求与结束的非阻塞观察。 */
#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Net/Target.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace Prism::Protocols
{
    struct DatagramSummary final
    {
        std::uint64_t Datagrams{0}, UpBytes{0}, DownBytes{0};
    };

    /** @brief 请求值快照；观察失败不进入协议错误处理路径。 */
    struct DatagramObservation final
    {
        Prism::Contract::RequestMetadata Request;
        std::string Identity;
        std::string DisplayIdentity;
        Prism::Contract::ProtocolType Protocol{Prism::Contract::ProtocolType::Unknown};
        Prism::AccountId AccountId{};

        auto FirstTarget(const Prism::Network::Target& Target) const noexcept -> void;

        auto Finish(DatagramSummary Summary) const noexcept -> void;
    };
}
