/** @file RestartPolicy.cpp @brief Prism 重启字段差异策略实现。 */
#include <Prism/Application/Reload/RestartPolicy.hpp>

#include <algorithm>
#include <cstddef>

namespace Prism::Application::Reload::RestartPolicy
{
    auto SameListenerShape(
        const std::vector<Configuration::ListenerEndpoint> &Left,
        const std::vector<Configuration::ListenerEndpoint> &Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Left.size(); ++Index)
        {
            if (Left[Index].Id != Right[Index].Id || Left[Index].Address != Right[Index].Address ||
                Left[Index].Port != Right[Index].Port)
            {
                return false;
            }
        }
        return true;
    }

    auto SameQuicEngineKinds(
        const Configuration::PrismConfiguration &Left,
        const Configuration::PrismConfiguration &Right) noexcept -> bool
    {
        std::size_t LeftCount = 0;
        std::size_t RightCount = 0;
        for (const auto &Protocol : Left.Protocols)
        {
            if (!Protocol.Quic)
            {
                continue;
            }
            ++LeftCount;
            const auto It = std::find_if(Right.Protocols.begin(), Right.Protocols.end(),
                [&Protocol](const auto &Candidate) { return Candidate.Id == Protocol.Id; });
            if (It == Right.Protocols.end() || !It->Quic || It->Builtin != Protocol.Builtin ||
                It->Name != Protocol.Name)
            {
                return false;
            }
        }
        for (const auto &Protocol : Right.Protocols)
        {
            if (Protocol.Quic)
            {
                ++RightCount;
            }
        }
        return LeftCount == RightCount;
    }

    auto RestartRequiredFields(const Input Request) -> std::vector<std::string>
    {
        std::vector<std::string> Fields;
        const auto& Current=Request.Current;
        const auto& Candidate=Request.Candidate;
        if (Current.Runtime.WorkerCount!=Candidate.Runtime.WorkerCount) Fields.emplace_back("Runtime.WorkerCount");
        if(Current.Runtime.MaxConnections!=Candidate.Runtime.MaxConnections)
            Fields.emplace_back("Runtime.MaxConnections");
        if(Current.Runtime.BytePool.InitialBytes!=Candidate.Runtime.BytePool.InitialBytes)
            Fields.emplace_back("Runtime.BytePool.InitialBytes");
        if(Current.Runtime.BytePool.GrowthBytes!=Candidate.Runtime.BytePool.GrowthBytes)
            Fields.emplace_back("Runtime.BytePool.GrowthBytes");
        if(Current.Runtime.BytePool.LimitBytes!=Candidate.Runtime.BytePool.LimitBytes)
            Fields.emplace_back("Runtime.BytePool.LimitBytes");
        if(!SameListenerShape(Current.Listeners.Tcp,Candidate.Listeners.Tcp)) Fields.emplace_back("Listeners.Tcp");
        if(!SameListenerShape(Current.Listeners.Udp,Candidate.Listeners.Udp)) Fields.emplace_back("Listeners.Udp");
        if(!SameListenerShape(Current.Listeners.Quic,Candidate.Listeners.Quic)) Fields.emplace_back("Listeners.Quic");
        if(Current.Operations.Enabled!=Candidate.Operations.Enabled) Fields.emplace_back("Operations.Enabled");
        if(Current.Operations.Endpoint!=Candidate.Operations.Endpoint) Fields.emplace_back("Operations.Endpoint");
        if(Current.Operations.WebDirectory!=Candidate.Operations.WebDirectory)
            Fields.emplace_back("Operations.WebDirectory");
        if(Current.Statistics.Enabled!=Candidate.Statistics.Enabled) Fields.emplace_back("Statistics.Enabled");
        if(!SameQuicEngineKinds(Current,Candidate)) Fields.emplace_back("Protocols.Quic.Engine");
        return Fields;
    }
}
