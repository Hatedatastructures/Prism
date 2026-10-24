/** @file SessionTraceModel.hpp @brief 有界会话生命周期轨迹的值模型与查询合同。 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Prism::Runtime
{
    /** @brief 运行时会话生命周期阶段；不包含逐字节记录。 */
    enum class SessionTraceStage : std::uint8_t
    {
        TcpAccepted,
        WorkerDispatchAccepted,
        SessionAdmissionStarted,
        SessionStarted,
        CarrierProbeStarted,
        CarrierProbeCompleted,
        RecognitionStarted,
        RecognitionCompleted,
        ProtocolAcceptStarted,
        ProtocolAcceptCompleted,
        AuthenticationConfirmed,
        OutboundResolveDialStarted,
        OutboundResolveDialCompleted,
        RelayStarted,
        RelayFirstUploadByte,
        RelayFirstDownloadByte,
        RelayCompleted,
        SessionClosed,
    };

    /** @brief 轨迹阶段结果；None 只用于无终态结果的开始事件。 */
    enum class SessionTraceOutcome : std::uint8_t
    {
        None,
        Succeeded,
        Failed,
    };

    /** @brief 当前阶段能够真实观察到的身份；零值表示该阶段没有该身份。 */
    struct SessionTraceIdentity final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::SessionId Session{};
        Prism::WorkerId Worker{};
        Prism::AccountId Account{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        Prism::StreamId Stream{};
    };

    /** @brief 一条固定字段、无字符串负载的轨迹事件。 */
    struct SessionTraceRecord final
    {
        std::uint64_t Sequence{0U};
        std::int64_t UtcUnixNanoseconds{0};
        std::uint64_t ElapsedNanoseconds{0U};
        SessionTraceIdentity Identity{};
        SessionTraceStage Stage{SessionTraceStage::TcpAccepted};
        SessionTraceOutcome Outcome{SessionTraceOutcome::None};
        Prism::Fault::Code Failure{Prism::Fault::Code::Success};
    };

    /** @brief 单 Worker 的连续读取位置；不同 Worker 的序号相互独立。 */
    struct SessionTraceCursor final
    {
        Prism::WorkerId Worker{};
        std::uint64_t Sequence{0U};
    };

    /** @brief 指定 Worker 轨迹发生覆盖或并发改写时的明确信息。 */
    struct SessionTraceLoss final
    {
        Prism::WorkerId Worker{};
        std::uint64_t OverwrittenRecords{0U};
        std::uint64_t LostSinceCursor{0U};
        std::uint64_t ConcurrentReadSkips{0U};
    };

    /** @brief 对真实已记录字段进行精确匹配；零值身份不参与过滤。 */
    struct SessionTraceQuery final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::SessionId Session{};
        Prism::WorkerId Worker{};
        Prism::AccountId Account{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        Prism::StreamId Stream{};
        std::vector<SessionTraceCursor> Cursors;
        std::size_t LimitPerWorker{256U};
    };

    /** @brief Process 读取多条 Worker 环形轨迹后的值快照。 */
    struct SessionTraceSnapshot final
    {
        Prism::ProcessId Process{};
        std::vector<SessionTraceRecord> Records;
        std::vector<SessionTraceCursor> Cursors;
        std::vector<SessionTraceLoss> Loss;
        bool HasMore{false};
    };
}
