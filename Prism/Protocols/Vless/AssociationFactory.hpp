/** @file AssociationFactory.hpp @brief Vless 数据报会话的服务注入边界。 */
#pragma once
#include <Prism/Protocols/Vless/Detail/Target.hpp>
#include <Prism/Protocols/Vless/UdpTunnel.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
namespace Prism::Vless
{
    /** @brief 接管 carrier 和服务，返回唯一负责取消、drain 与关闭的协议 owner。 */
    inline auto MakeDatagramSession(std::shared_ptr<Conn<>> Carrier,
                                    Address Target,
                                    Prism::Protocols::DatagramBinding Binding)
        -> std::shared_ptr<Prism::Contract::DatagramSession>
    {
        UdpTunnelOptions Options;
        Options.Target = std::move(Target);
        Options.Services = std::move(Binding.Services);
        Options.TaskIdentity = Binding.Observation.Request.TaskIdentity;
        Options.AccountId = Binding.Observation.AccountId;
        Options.OnFirstTarget = [Observation = Binding.Observation](const Address& Target)
        { const auto Value = Prism::Vless::Detail::ToNetworkTarget(Target); if (Value) Observation.FirstTarget(*Value); };
        Options.OnSessionEnd = [Observation = std::move(Binding.Observation)](
            const UdpTunnelSummary& Summary)
        { Observation.Finish({Summary.Datagrams, Summary.UpBytes, Summary.DownBytes}); };
        return std::make_shared<UdpTunnel>(std::move(Carrier), std::move(Options));
    }
}
