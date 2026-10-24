/**
 * @file MailboxCompareTrace.hpp
 * @brief Mailbox 基线的确定性命令轨迹。
 */

#pragma once

#include "MailboxCompare.hpp"

#include <cstdint>
#include <vector>

namespace Prism::Runtime::Perf
{

    struct TraceCommand final
    {
        std::uint64_t Payload{0};
    };

    struct Trace final
    {
        std::vector<TraceCommand> Commands;
        std::uint64_t Hash{0};
    };

} // namespace Prism::Runtime::Perf
