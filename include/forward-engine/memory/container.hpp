#pragma once

#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <memory_resource>
#include <type_traits>

namespace ngx::memory
{
    /**
     * @brief 内存资源
     * @details 使用 std::pmr::memory_resource 替代 std::memory_resource
     * @note `monotonic_buffer_resource` 上分配时，内存资源紧凑排列，缓存极其友好
     */
    using resource = std::pmr::memory_resource;

    /**
     * @brief 内存资源指针
     * @details 指向 `resource` 对象的指针，用于内存资源管理
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
     * @brief 内存分配器
     * @details 使用 std::pmr::polymorphic_allocator 替代 std::polymorphic_allocator
     * @note `monotonic_buffer_resource` 上分配时，内存资源紧凑排列，缓存极其友好
     */
    template <typename Type>
    using allocator = std::pmr::polymorphic_allocator<Type>;

    /**
     * @brief 同步池资源
     * @details 使用 std::pmr::synchronized_pool_resource 替代 std::synchronized_pool_resource
     * @warning 只适合作为全局默认内存资源，不适合线程局部或特定算法内部
     */
    using synchronized_pool = std::pmr::synchronized_pool_resource;

    /**
     * @brief 非线程安全的池资源
     * @details 使用 std::pmr::unsynchronized_pool_resource 替代 std::unsynchronized_pool_resource
     * @note `monotonic_buffer_resource` 上分配时，内存资源紧凑排列，缓存极其友好
     */
    using unsynchronized_pool = std::pmr::unsynchronized_pool_resource;

    /**
     * @brief 单调增长资源
     * @details 使用 std::pmr::monotonic_buffer_resource 替代 std::monotonic_buffer_resource
     * @warning 只适合作为全局默认内存资源，不适合线程局部或特定算法内部
     */
    using monotonic_buffer = std::pmr::monotonic_buffer_resource;

    /**
     * @brief string 类型别名
     * @details 使用 std::pmr::string 替代 std::string
     * @note `monotonic_buffer_resource` 上分配时，字符串内容紧凑排列，缓存极其友好
     */
    using string = std::pmr::string;

    /**
     * @brief vector
     * @details 使用 std::pmr::vector 替代 std::vector
     * @note `monotonic_buffer_resource` 上分配时，数组元素紧凑排列，缓存极其友好
     */
    template <typename Value>
    using vector = std::pmr::vector<Value>;

    /**
     * @brief list
     * @details 使用 std::pmr::list 替代 std::list
     * @note `monotonic_buffer_resource` 上分配时，链表节点紧凑排列，缓存极其友好
     */
    template <typename Value>
    using list = std::pmr::list<Value>;


    /**
     * @brief unordered_map
     * @details 使用 std::pmr::unordered_map 替代 std::unordered_map
     * @note `monotonic_buffer_resource` 上分配时，哈希表元素紧凑排列，缓存极其友好
     */
    template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_map = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>;

    /**
     * @brief unordered_set
     * @details 使用 std::pmr::unordered_set 替代 std::unordered_set
     * @note `monotonic_buffer_resource` 上分配时，哈希集合元素紧凑排列，缓存极其友好
     */
    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_set = std::pmr::unordered_set<Key, Hash, KeyEqual>;

} // namespace ngx::memory
