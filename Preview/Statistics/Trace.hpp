/**
 * @file Trace.hpp
 * @brief Preview 日志可复用的 trace 选择和只读值快照。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace Preview::Statistics
{

    /** @brief 日志记录需要携带的 trace 字段选择。 */
    struct TraceSelection final
    {
        bool IncludeCorrelation{true};
        bool IncludeWorker{true};
        bool IncludeSession{true};
        bool IncludeStream{false};
    };

    /**
     * @brief 记录提交时复制的 trace 值。
     * @details 记录只保存值，不保存 Context 内部地址，因此可安全跨越异步队列生命周期。
     */
    struct TraceSnapshot final
    {
        std::optional<Preview::RequestId> Correlation;
        std::optional<Preview::WorkerId> Worker;
        std::optional<Preview::SessionId> Session;
        std::optional<Preview::StreamId> Stream;
        std::optional<Preview::TaskId> Task;
        std::optional<Preview::GenerationId> Generation;
        std::string Carrier;
        std::string Protocol;
        std::string Sni;
        std::string Alpn;
        std::string TlsVersion;
        std::string Stage;
        std::string Status;
        std::string FaultCode;
        std::string NativeError;
        std::optional<std::uint64_t> ElapsedMs;
    };

} // namespace Preview::Statistics
