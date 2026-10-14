/** @file ConfigurationDifference.hpp @brief 根据真实配置字段差异决定必须重启的字段。 */
#pragma once
#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>
namespace Preview::Application::Reload::ConfigurationDifference
{
    namespace Configuration=Preview::Application::Configuration;
    [[nodiscard]] inline auto SameListenerShape(
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
    [[nodiscard]] inline auto SameQuicEngineKinds(
        const Configuration::PreviewConfiguration &Left,
        const Configuration::PreviewConfiguration &Right) noexcept -> bool
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
    /** @brief 同步借用当前和候选 immutable 配置；本次调用不保存引用。 */
    struct Input final
    {
        const Configuration::PreviewConfiguration& Current;
        const Configuration::PreviewConfiguration& Candidate;
    };
    /**
     * @brief 唯一重启差异owner；非空结果既是判定也是提供给管理端的实际字段列表。
     * @details 统计 collector 启用状态是 process-scoped；输出仅有字段名称，不含值或 secret。
     *          冷准备可能分配。取消、半关闭、
     *          最终关闭与executor均不适用本同步值计算，不启动任何进程或异步操作。
     */
    [[nodiscard]] inline auto RestartRequiredFields(const Input Request) -> std::vector<std::string>
    {
        std::vector<std::string> Fields;
        const auto& Current=Request.Current;
        const auto& Candidate=Request.Candidate;
        if(Current.Runtime.WorkerCount!=Candidate.Runtime.WorkerCount) Fields.emplace_back("Runtime.WorkerCount");
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
