/**
 * @file Container.cpp
 * @brief 当前线程 PMR 资源作用域实现。
 */
#include <Prism/Foundation/Memory/Container.hpp>

namespace Prism::Memory
{
    ResourceScope::ResourceScope(ResourcePointer Value) noexcept
        : Previous_(Detail::ThreadResource)
    {
        Detail::ThreadResource = Value;
    }

    ResourceScope::~ResourceScope() noexcept
    {
        Detail::ThreadResource = Previous_;
    }

    auto CurrentResource() -> ResourcePointer
    {
        if (Detail::ThreadResource)
        {
            return Detail::ThreadResource;
        }
        return std::pmr::get_default_resource();
    }

    auto EffectiveMr(ResourcePointer mr) noexcept -> ResourcePointer
    {
        if (mr)
        {
            return mr;
        }
        return CurrentResource();
    }
}
