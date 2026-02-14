/**
 * @file container.hpp
 * @brief 内存容器别名
 * @details 定义了使用 `std::pmr`（Polymorphic Memory Resource）多态内存资源的容器别名，以支持统一的内存管理。该模块是项目内存体系的基础，提供类型安全的容器接口，同时保持与自定义内存池的集成能力。
 * 
 * 设计目标：
 * - 统一内存管理：所有容器使用 `std::pmr::polymorphic_allocator`，支持运行时内存资源切换；
 * - 零抽象开销：类型别名不引入额外开销，编译后与标准容器相同；
 * - 性能优化：通过内存池集成减少堆分配，改善缓存局部性；
 * - 类型安全：保持标准容器的完整接口和类型检查。
 * 
 * 核心组件：
 * 1. 基础类型别名：`resource`、`resource_pointer`、`allocator`；
 * 2. 内存资源类型：`synchronized_pool`、`unsynchronized_pool`、`monotonic_buffer`；
 * 3. 容器别名：`string`、`vector`、`list`、`map`、`unordered_map`、`unordered_set`。
 * 
 * 
 * @note 所有别名都使用 `std::pmr` 版本，确保与项目内存池系统兼容。
 * @warning 使用这些容器时，必须注意内存资源的生命周期和线程安全性。
 * @see pool.hpp
 * @see pointer.hpp
 * 
 * ```
 * // 使用示例：创建使用内存池的容器
 * auto* pool = ngx::memory::system::global_pool();
 * ngx::memory::vector<int> vec(pool);           // 使用全局池
 * ngx::memory::string str(pool);                // 使用全局池
 * 
 * // 使用示例：帧分配器场景
 * ngx::memory::frame_arena arena;
 * ngx::memory::vector<int> temp_vec(arena.get());  // 使用帧分配器
 * 
 * // 使用示例：默认资源（如果启用了全局池化）
 * ngx::memory::string default_str;  // 使用默认资源
 * ```
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
 * @details 提供基于 `PMR`（Polymorphic Memory Resource）的内存管理基础设施。该命名空间是实现"性能军规"中内存管理要求的核心，为项目提供高性能、零开销的内存管理能力。
 * 
 * 核心组件：
 * @details - 内存池系统：全局和线程局部池（`pool.hpp`），提供高性能内存分配；
 * @details - 容器别名：使用 `PMR` 分配器的标准容器别名（本文件），支持内存感知容器；
 * @details - 智能指针：支持自定义删除器的智能指针（`pointer.hpp`），集成内存池系统；
 * @details - 工具函数：内存分配和管理的辅助工具，提供便捷的内存操作接口。
 * 
 * 
 * @note 该命名空间的内容是性能敏感的，修改需进行性能评估。
 * @warning 线程局部资源分配的内存严禁跨线程使用。
 * @throws 内存分配操作可能抛出 `std::bad_alloc`
 * 
 * ```
 * // 使用示例：完整内存管理流程
 * // 获取内存池
 * auto* pool = ngx::memory::system::global_pool();
 * // 创建使用内存池的容器
 * ngx::memory::vector<int> numbers(pool);
 * numbers.push_back(42);
 * // 创建字符串
 * ngx::memory::string text(pool);
 * text = "Hello, world!";
 * // 使用智能指针
 * ngx::memory::unique_ptr<int> ptr = ngx::memory::make_unique<int>(pool, 42);
 * ```
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
     * @return `resource_pointer` 当前默认内存资源指针
     * @note 该函数不分配内存，仅返回指针。
     * @warning 不要 `delete` 返回的指针，它由标准库管理。
     * @details 返回 `C++` 标准库的当前默认内存资源指针。该函数是 `std::pmr::get_default_resource()` 的简单包装。
     * 
     * 默认资源：
     * @details - 如果程序调用了 `ngx::memory::system::enable_global_pooling()`，则返回 `global_pool()`；
     * @details - 否则返回 `std::pmr::new_delete_resource()`（系统堆分配器）。
     * 
     * ```
     * // 使用示例：获取默认资源
     * auto* default_res = ngx::memory::current_resource();
     * // 创建使用默认资源的容器
     * ngx::memory::vector<int> vec(default_res);
     * 
     * // 使用示例：启用全局池化后的行为
     * ngx::memory::system::enable_global_pooling();
     * auto* after_pooling = ngx::memory::current_resource();
     * // after_pooling == ngx::memory::system::global_pool()
     * ```
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
