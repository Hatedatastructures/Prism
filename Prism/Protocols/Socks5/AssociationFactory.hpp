/** @file AssociationFactory.hpp @brief Socks5 数据报会话的服务注入边界。 */
#pragma once
#include <Prism/Protocols/Socks5/Detail/Target.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>
namespace Prism::Socks5
{
    /** @brief 接管 carrier 和服务，返回唯一负责取消、drain 与关闭的协议 owner。 */
    inline auto MakeDatagramSession(std::shared_ptr<Conn<>> Carrier,
                                    Prism::Protocols::DatagramBinding Binding)
        -> std::shared_ptr<UdpAssoc>
    {
        UdpAssocOptions Options;
        Options.IdleTimeout = Binding.Services.IdleTimeout;
        Options.Traffic = std::move(Binding.Services.Traffic);
        Options.TaskIdentity = Binding.Observation.Request.TaskIdentity;
        Options.AccountId = Binding.Observation.AccountId;
        Options.OnFirstTarget = [Observation = Binding.Observation](const Address& Target)
        { const auto Value = Prism::Socks5::Detail::ToNetworkTarget(Target); if (Value) Observation.FirstTarget(*Value); };
        Options.OnSessionEnd = [Observation = std::move(Binding.Observation)](
            const Prism::Protocols::DatagramSummary& Summary)
        { Observation.Finish({Summary.Datagrams, Summary.UpBytes, Summary.DownBytes}); };
        Options.Resolve = [Services = std::move(Binding.Services)](const Address& Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint,
                Prism::Fault::Failure>>
        {
            auto Value = Prism::Socks5::Detail::ToNetworkTarget(Target);
            if (!Value)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            co_return co_await Prism::Protocols::ResolveDatagram(Services, std::move(*Value));
        };
        const auto Executor = Carrier->Executor();
        return std::make_shared<UdpAssoc>(Executor, std::move(Carrier), std::move(Options));
    }
}
