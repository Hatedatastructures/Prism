#pragma once

#include <cstdint>

namespace Preview::Cancellation
{

    /** @brief 回调对取消的协作要求。 */
    enum class Mode : std::uint8_t
    {
        None,
        Cooperative,
        Required,
    };

    using Policy = Mode;
    using Value = Mode;
    using CancellationMode = Mode;

} // namespace Preview::Cancellation

namespace Preview
{

    using CancellationMode = Cancellation::Mode;

} // namespace Preview
