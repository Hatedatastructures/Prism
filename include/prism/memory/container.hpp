/**
 * @file container.hpp
 * @brief 内存容器别名定义
 * @details 定义使用 std::pmr 多态内存资源的容器别名，
 * 为项目提供统一的内存管理基础设施。所有容器类型
 * 均使用 polymorphic_allocator 分配器，支持运行时
 * 切换内存资源，实现与自定义内存池的无缝集成。
 */
#pragma once

#include <string>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <memory_resource>
#include <type_traits>

namespace psm
{
}

namespace psm::memory
{
    using resource = std::pmr::memory_resource; // 内存资源类型，配合 monotonic_buffer 使用具有良好的缓存友好性

    using resource_pointer = std::add_pointer_t<resource>; // 内存资源指针类型，用于在函数间传递内存资源引用

    /**
     * @brief 获取当前默认内存资源
     * @details 对 std::pmr::get_default_resource() 的包装。
     * 如果调用了 system::enable_global_pooling()，则返回
     * global_pool()，否则返回系统堆分配器。
     * @return 当前默认内存资源指针，永不返回 nullptr
     */
    inline auto current_resource() -> resource_pointer
    {
        return std::pmr::get_default_resource();
    }

    template <typename Type>
    using allocator = std::pmr::polymorphic_allocator<Type>; // 多态内存分配器模板

    using synchronized_pool = std::pmr::synchronized_pool_resource; // 线程安全的池资源，内部使用互斥锁保护

    using unsynchronized_pool = std::pmr::unsynchronized_pool_resource; // 非线程安全的池资源，仅限单线程使用

    using monotonic_buffer = std::pmr::monotonic_buffer_resource; // 单调增长缓冲区资源，仅分配不释放

    using string = std::pmr::string; // PMR 字符串类型

    template <typename Value>
    using vector = std::pmr::vector<Value>; // PMR 动态数组模板

    template <typename Value>
    using list = std::pmr::list<Value>; // PMR 双向链表模板

    template <typename Key, typename Value, typename Compare = std::less<Key>>
    using map = std::pmr::map<Key, Value, Compare>; // PMR 红黑树映射模板

    template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_map = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>; // PMR 哈希映射模板

    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_set = std::pmr::unordered_set<Key, Hash, KeyEqual>; // PMR 哈希集合模板

} // namespace psm::memory
