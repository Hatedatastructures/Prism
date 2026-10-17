/**
 * @file Container.hpp
 * @brief 内存容器别名定义
 * @details 定义使用 std::pmr 多态内存资源的容器别名，
 * 为项目提供统一的内存管理基础设施。所有容器类型
 * 均使用 polymorphic_allocator 分配器，支持运行时
 * 切换内存资源，实现与自定义内存池的无缝集成。
 * @note 镜像自 include/prism/foundation/memory/，同步策略：锁定
 */
#pragma once

#include <list>
#include <map>
#include <memory_resource>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Preview::Memory
{

    using Resource =
        std::pmr::memory_resource; // 内存资源类型，配合 MonotonicBuffer 使用具有良好的缓存友好性

    using ResourcePointer = std::add_pointer_t<Resource>; // 内存资源指针类型，用于在函数间传递内存资源引用

    namespace Detail
    {
        /** @brief 仅覆盖当前线程、由 ResourceScope 临时设置的 PMR 资源。 */
        inline thread_local ResourcePointer ThreadResource{nullptr};
    }

    /**
     * @brief 在同步调用栈内临时选择线程当前 PMR 资源。
     * @details 不分配、不加锁；作用域不能跨协程挂起或线程迁移，析构时恢复先前资源。
     */
    class ResourceScope final
    {
    public:
        explicit ResourceScope(ResourcePointer Value) noexcept
            : Previous_(Detail::ThreadResource)
        {
            Detail::ThreadResource = Value;
        }

        ~ResourceScope() noexcept
        {
            Detail::ThreadResource = Previous_;
        }

        ResourceScope(const ResourceScope&) = delete;
        auto operator=(const ResourceScope&) -> ResourceScope& = delete;
        ResourceScope(ResourceScope&&) = delete;
        auto operator=(ResourceScope&&) -> ResourceScope& = delete;

    private:
        ResourcePointer Previous_;
    };

    /**
     * @brief 获取当前线程作用域资源或进程默认 PMR 资源。
     * @details ResourceScope 生效时返回其临时资源；否则等价于
     * std::pmr::get_default_resource()。若调用 System::EnablePooling()，默认值为 GlobalPool()。
     * @return 当前默认内存资源指针，永不返回 nullptr
     */
    [[nodiscard]] inline auto CurrentResource()
         -> ResourcePointer
    {
        if (Detail::ThreadResource)
        {
            return Detail::ThreadResource;
        }
        return std::pmr::get_default_resource();
    }

    /**
     * @brief 获取有效的内存资源指针
     * @details 如果传入的 mr 非空则直接返回，否则返回默认内存资源。
     * 用于统一替代 mr ? mr : CurrentResource() 三元模式。
     * @param mr 可选的内存资源指针
     * @return 有效的内存资源指针，永不返回 nullptr
     */
    [[nodiscard]] inline auto EffectiveMr(ResourcePointer mr) noexcept 
        -> ResourcePointer
    {
        if (mr)
        {
            return mr;
        }
        return CurrentResource();
    }

    template <typename Type>
    using Allocator = std::pmr::polymorphic_allocator<Type>; // 多态内存分配器模板

    using SynchronizedPool = std::pmr::synchronized_pool_resource; // 线程安全的池资源，内部使用互斥锁保护

    using UnsynchronizedPool = std::pmr::unsynchronized_pool_resource; // 非线程安全的池资源，仅限单线程使用

    using MonotonicBuffer = std::pmr::monotonic_buffer_resource; // 单调增长缓冲区资源，仅分配不释放

    /// PMR 字符串类型（规范 v2 PascalCase 主别名）
    using String = std::pmr::string;

    /// PMR 动态数组模板（规范 v2 PascalCase 主别名）
    template <typename Value>
    using Vector = std::pmr::vector<Value>;

    template <typename Value>
    using List = std::pmr::list<Value>; // PMR 双向链表模板

    template <typename Key, typename Value, typename Compare = std::less<Key>>
    using Map = std::pmr::map<Key, Value, Compare>; // PMR 红黑树映射模板

    template <typename Key, typename Value, typename Hash = std::hash<Key>,
              typename KeyEqual = std::equal_to<Key>>
    using UnorderedMap = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>; // PMR 哈希映射模板

    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using UnorderedSet = std::pmr::unordered_set<Key, Hash, KeyEqual>; // PMR 哈希集合模板

} // namespace Preview::Memory
