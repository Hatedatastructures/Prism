/**
 * @file container.hpp
 * @brief 内存容器别名定义
 * @details 定义使用 std::pmr 多态内存资源的容器别名，为项目提供统一的
 * 内存管理基础设施。所有容器类型均使用 polymorphic_allocator 分配器，
 * 支持运行时切换内存资源，实现与自定义内存池的无缝集成。该模块是项目
 * 内存体系的核心组成部分，遵循性能军规中关于内存管理的各项要求。
 * 设计目标包括统一内存管理、零抽象开销、性能优化和类型安全四个方面。
 * 统一内存管理指所有容器使用 std::pmr::polymorphic_allocator，支持
 * 运行时内存资源切换。零抽象开销指类型别名不引入额外开销，编译后与
 * 标准容器完全相同。性能优化指通过内存池集成减少堆分配次数，改善缓存
 * 局部性。类型安全指保持标准容器的完整接口和类型检查能力。
 * 核心组件分为三类。第一类是基础类型别名，包括 resource、
 * resource_pointer 和 allocator。第二类是内存资源类型，包括
 * synchronized_pool、unsynchronized_pool 和 monotonic_buffer。
 * 第三类是容器别名，包括 string、vector、list、map、unordered_map
 * 和 unordered_set。
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
 * @namespace psm
 * @brief 项目根命名空间
 * @details 包含所有项目组件，涵盖协议处理、内存管理、网络传输等核心
 * 功能模块。该命名空间作为项目代码组织的顶层容器，确保各模块间的清晰
 * 边界和良好的命名隔离。
 */
namespace psm {}

/**
 * @namespace psm::memory
 * @brief 内存管理子系统
 * @details 提供基于 PMR 多态内存资源的内存管理基础设施。该命名空间是
 * 实现性能军规中内存管理要求的核心模块，为项目提供高性能、零开销的
 * 内存管理能力。所有内存相关的类型定义、工具函数和辅助设施均位于此
 * 命名空间内。
 * 核心组件包括四个部分。内存池系统提供全局和线程局部池，定义于
 * pool.hpp 文件，提供高性能内存分配能力。容器别名使用 PMR 分配器的
 * 标准容器别名，定义于本文件，支持内存感知容器。智能指针支持自定义
 * 删除器的智能指针，定义于 pointer.hpp 文件，集成内存池系统。工具
 * 函数提供内存分配和管理的辅助接口，简化常见内存操作。
 */
namespace psm::memory
{
    // 内存资源类型，使用 std::pmr::memory_resource 作为基础类型。
    // 当配合 monotonic_buffer_resource 使用时，内存分配连续紧凑，
    // 具有良好的缓存友好性。
    using resource = std::pmr::memory_resource;

    // 内存资源指针类型，用于在函数间传递内存资源引用。
    using resource_pointer = std::add_pointer_t<resource>;

    /**
     * @brief 获取当前默认内存资源
     * @return 当前默认内存资源指针，永不返回 nullptr
     *
     * @details 返回 C++ 标准库的当前默认内存资源指针。该函数是对
     * std::pmr::get_default_resource() 的简单包装，提供统一的访问
     * 接口。默认资源的确定遵循以下规则：如果程序调用了
     * system::enable_global_pooling()，则返回 global_pool()；否则
     * 返回 std::pmr::new_delete_resource() 即系统堆分配器。
     *
     * 该函数不分配任何内存，仅返回指针，调用开销极低。返回的指针由
     * 标准库管理，调用者不应尝试 delete 该指针。
     */
    inline auto current_resource() -> resource_pointer
    {
        return std::pmr::get_default_resource();
    }

    // 多态内存分配器模板，使用 std::pmr::polymorphic_allocator。
    // Type 参数指定分配的对象类型。
    template <typename Type>
    using allocator = std::pmr::polymorphic_allocator<Type>;

    // 线程安全的池资源，使用 std::pmr::synchronized_pool_resource。
    // 内部使用互斥锁保护，适合作为全局默认资源使用。
    using synchronized_pool = std::pmr::synchronized_pool_resource;

    // 非线程安全的池资源，使用 std::pmr::unsynchronized_pool_resource。
    // 完全无锁设计，性能极高，但仅限单线程或线程局部使用。
    using unsynchronized_pool = std::pmr::unsynchronized_pool_resource;

    // 单调增长缓冲区资源，使用 std::pmr::monotonic_buffer_resource。
    // 仅分配不释放，直到资源销毁时统一释放。适用于生命周期短且确定的
    // 场景，如单个请求处理过程中的临时分配。
    using monotonic_buffer = std::pmr::monotonic_buffer_resource;

    // PMR 字符串类型，使用 std::pmr::string。
    using string = std::pmr::string;

    // PMR 动态数组模板，Value 参数指定元素类型。
    template <typename Value>
    using vector = std::pmr::vector<Value>;

    // PMR 双向链表模板，Value 参数指定元素类型。
    template <typename Value>
    using list = std::pmr::list<Value>;

    // PMR 红黑树映射模板。Key 参数指定键类型，Value 参数指定值类型，
    // Compare 参数指定键比较器类型，默认为 std::less<Key>。
    template <typename Key, typename Value, typename Compare = std::less<Key>>
    using map = std::pmr::map<Key, Value, Compare>;

    // PMR 哈希映射模板。Key 参数指定键类型，Value 参数指定值类型，
    // Hash 参数指定哈希函数类型，KeyEqual 参数指定键相等比较器类型。
    template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_map = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>;

    // PMR 哈希集合模板。Key 参数指定键类型，Hash 参数指定哈希函数类型，
    // KeyEqual 参数指定键相等比较器类型。
    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_set = std::pmr::unordered_set<Key, Hash, KeyEqual>;

} // namespace psm::memory
