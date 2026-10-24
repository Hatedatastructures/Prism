/** @file Affinity.hpp
 * @brief 回调执行器亲和性约束。
 */
#pragma once

#include <cstdint>

namespace Prism::Executor
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

} // namespace Prism::Executor

namespace Prism
{

    using ExecutorAffinity = Executor::Affinity;

} // namespace Prism
