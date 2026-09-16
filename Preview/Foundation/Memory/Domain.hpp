#pragma once

#include <cstdint>

namespace Preview::Memory
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

} // namespace Preview::Memory

namespace Preview
{

    using MemoryDomain = Memory::Domain;

} // namespace Preview
