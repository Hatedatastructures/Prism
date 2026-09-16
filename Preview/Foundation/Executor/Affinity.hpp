#pragma once

#include <cstdint>

namespace Preview::Executor
{

    /** @brief 回调允许使用的执行器亲和性。 */
    enum class Affinity : std::uint8_t
    {
        Any,
        Caller,
        Process,
        Worker,
        Session,
        Stream,
        Control,
    };

    using ExecutorAffinity = Affinity;

} // namespace Preview::Executor

namespace Preview
{

    using ExecutorAffinity = Executor::Affinity;

} // namespace Preview
