/**
 * @file container.hpp
 * @brief 内存容器别名
 * @details 定义了使用 `std::pmr` 多态内存资源的容器别名，以支持统一的内存管理。
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

/**
 * @namespace ngx
 * @brief 项目根命名空间
 * @details 包含所有项目组件，包括协议、内存管理、传输等。
 */
namespace ngx {}

/**
 * @namespace ngx::memory
 * @brief 内存管理子系统
 * @details 提供基于 PMR (Polymorphic Memory Resource) 的内存管理基础设施。
 * 包含自定义分配器、内存池策略和容器别名，旨在减少堆分配开销并优化缓存局部性。
 */
namespace ngx::memory
{
    /**
     * @brief 内存资源类型
     * @details 使用 `std::pmr::memory_resource` 替代 `std::memory_resource`。
     * @note 当配合 `monotonic_buffer_resource` 使用时，内存分配连续紧凑，缓存友好。
     */
    using resource = std::pmr::memory_resource;

    /**
     * @brief 内存资源指针
     * @details 指向 `resource` 对象的指针，用于内存资源传递。
     */
    using resource_pointer = std::add_pointer_t<resource>;

    /**
     * @brief 获取当前默认内存资源
     * @return resource_pointer 当前默认内存资源指针
     */
    inline auto current_resource () -> resource_pointer
    {
        return std::pmr::get_default_resource();
    }

    /**
     * @brief 多态内存分配器
     * @details 使用 `std::pmr::polymorphic_allocator`。
     * @tparam Type 分配的对象类型
     */
    template <typename Type>
    using allocator = std::pmr::polymorphic_allocator<Type>;

    /**
     * @brief 线程安全的池资源
     * @details 使用 `std::pmr::synchronized_pool_resource`。
     * @warning 适合作为全局默认资源，内部有锁。
     */
    using synchronized_pool = std::pmr::synchronized_pool_resource;

    /**
     * @brief 非线程安全的池资源
     * @details 使用 `std::pmr::unsynchronized_pool_resource`。
     * @note 无锁，性能高，但仅限单线程或线程局部使用。
     */
    using unsynchronized_pool = std::pmr::unsynchronized_pool_resource;

    /**
     * @brief 单调增长缓冲区资源
     * @details 使用 `std::pmr::monotonic_buffer_resource`。
     * @note 仅分配不释放（直到资源销毁），适用于生命周期短且确定的场景（如请求处理）。
     */
    using monotonic_buffer = std::pmr::monotonic_buffer_resource;

    /**
     * @brief PMR 字符串
     * @details 使用 `std::pmr::string`。
     */
    using string = std::pmr::string;

    /**
     * @brief PMR 动态数组
     * @tparam Value 元素类型
     */
    template <typename Value>
    using vector = std::pmr::vector<Value>;

    /**
     * @brief PMR 双向链表
     * @tparam Value 元素类型
     */
    template <typename Value>
    using list = std::pmr::list<Value>;


    /**
     * @brief PMR 红黑树映射
     * @tparam Key 键类型
     * @tparam Value 值类型
     * @tparam Compare 比较器类型
     */
    template <typename Key, typename Value, typename Compare = std::less<Key>>
    using map = std::pmr::map<Key, Value, Compare>;

    /**
     * @brief PMR 哈希映射
     * @tparam Key 键类型
     * @tparam Value 值类型
     * @tparam Hash 哈希函数类型
     * @tparam KeyEqual 键比较器类型
     */
    template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_map = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>;

    /**
     * @brief PMR 哈希集合
     * @tparam Key 键类型
     * @tparam Hash 哈希函数类型
     * @tparam KeyEqual 键比较器类型
     */
    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_set = std::pmr::unordered_set<Key, Hash, KeyEqual>;

} // namespace ngx::memory
