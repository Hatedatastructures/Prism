/** @file DatagramObservation.hpp @brief 数据报请求与结束的非阻塞观察。 */
#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>

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

        auto FirstTarget(const Prism::Network::Target& Target) const noexcept -> void
        {
            if (Target.Host.Empty() || Target.Port == 0) return;
            try
            {
                const auto Text = Prism::Network::ToText(Target.Host);
                const auto User = !DisplayIdentity.empty() ? DisplayIdentity
                    : AccountId ? std::to_string(AccountId.Value()) : std::string{};
                const auto Source = Request.SourceIp.empty() ? std::string_view{"Unknown"}
                    : std::string_view{Request.SourceIp};
                if (User.empty())
                    (void)Prism::Diagnose::Info(Request.Trace, "Request SourceIp={} Target={}:{}",
                        Source, Text.View(), Target.Port);
                else
                    (void)Prism::Diagnose::Info(Request.Trace, "Request SourceIp={} Target={}:{} User={}",
                        Source, Text.View(), Target.Port, User);
            }
            catch (...) {}
        }

        auto Finish(DatagramSummary Summary) const noexcept -> void
        {
            try
            {
                (void)Prism::Diagnose::Trace(Request.Trace,
                    "UdpSessionSummary Protocol={} SourceIp={} Datagrams={} UpBytes={} DownBytes={}",
                    Prism::Contract::ToStringView(Protocol), Request.SourceIp,
                    Summary.Datagrams, Summary.UpBytes, Summary.DownBytes);
            }
            catch (...) {}
        }
    };
}
