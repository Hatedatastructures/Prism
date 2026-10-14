/** @file AssociationFactory.hpp @brief Vless 数据报会话的服务注入边界。 */
#pragma once
#include <Preview/Protocols/Vless/Detail/Target.hpp>
#include <Preview/Protocols/Vless/UdpTunnel.hpp>
#include <Preview/Protocols/Common/DatagramBinding.hpp>
namespace Preview::Vless
{
    /** @brief 接管 carrier 和服务，返回唯一负责取消、drain 与关闭的协议 owner。 */
    inline auto MakeDatagramSession(std::shared_ptr<Conn<>> Carrier,
                                    Address Target,
                                    Preview::Protocols::DatagramBinding Binding)
        -> std::shared_ptr<Preview::Contract::DatagramSession>
    {
        UdpTunnelOptions Options;
        Options.Target = std::move(Target);
        Options.Services = std::move(Binding.Services);
        Options.TaskIdentity = Binding.Observation.Request.TaskIdentity;
        Options.AccountId = Binding.Observation.AccountId;
        Options.OnFirstTarget = [Observation = Binding.Observation](const Address& Target)
        { const auto Value = Preview::Vless::Detail::ToNetworkTarget(Target); if (Value) Observation.FirstTarget(*Value); };
        Options.OnSessionEnd = [Observation = std::move(Binding.Observation)](
            const UdpTunnelSummary& Summary)
        { Observation.Finish({Summary.Datagrams, Summary.UpBytes, Summary.DownBytes}); };
        return std::make_shared<UdpTunnel>(std::move(Carrier), std::move(Options));
    }
}
