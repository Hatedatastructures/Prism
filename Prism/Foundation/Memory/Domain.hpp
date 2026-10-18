#pragma once

#include <cstdint>

namespace Prism::Memory
{

    /** @brief 值语义内存域，不携带资源所有权。 */
    enum class Domain : std::uint8_t
    {
        Global,
        Process = Global,
        Worker,
        Session,
        Stream,
        Request,
        Snapshot,
    };

    using MemoryDomain = Domain;

} // namespace Prism::Memory

namespace Prism
{

    using MemoryDomain = Memory::Domain;

} // namespace Prism
