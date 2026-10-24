/** @file DatagramObservation.cpp @brief Common 数据报观察与结束摘要实现。 */

#include <Prism/Protocols/Common/DatagramObservation.hpp>

#include <string>
#include <string_view>

namespace Prism::Protocols
{
    auto DatagramObservation::FirstTarget(
        const Prism::Network::Target& Target) const noexcept -> void
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

    auto DatagramObservation::Finish(DatagramSummary Summary) const noexcept -> void
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
} // namespace Prism::Protocols
