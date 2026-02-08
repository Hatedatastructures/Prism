/**
 * @file pool.hpp
 * @brief 内存池系统
 * @details 提供全局和线程局部的内存池管理，以及基于内存池的对象分配基类和帧分配器。
 */
#pragma once

#include <forward-engine/memory/container.hpp>

namespace ngx::memory
{
    /**
     * @brief 内存策略配置
     * @details 定义内存池的参数，针对代理服务器负载进行优化。
     */
    struct policy
    {
        /**
         * @brief 每个 Chunk 包含的最大块数
         * @details 降低此值可减少内存峰值。
         * 256 * 16KB = 4MB (最大 Chunk 大小)，相比之前的 256MB 大幅降低了 OOM 风险。
         */
        static constexpr std::size_t max_blocks = 256;


        /**
         * @brief 最大池化阈值
         * @details 16KB 足以覆盖 HTTP Header、RPC 元数据和小型 Payload。
         * 大于此值的对象将直接走系统堆 (malloc)，避免长驻内存池。
         */
        static constexpr std::size_t max_pool_size = 16384;

        /**
         * @brief 小型缓冲区大小 (8KB)
         * @details 适用于临时缓冲区、栈上数组等场景。
         */
        static constexpr std::size_t small_buffer_size = 8192;
    };

    /**
     * @brief 全局内存系统管理器
     * @details 提供全局单例的内存池访问接口。
     */
    class system
    {
    public:
        /**
         * @brief 获取全局线程安全池 (Global Synchronized Pool)
         * @details 适用于：跨线程传递的对象、生命周期不确定的对象 (pooled_object 默认使用此池)。
         * @note 线程安全，内部有细粒度锁和 Thread Cache。
         * @return synchronized_pool* 全局同步池指针
         */
        static synchronized_pool *global_pool()
        {
            static auto *pool = []()
            {
                std::pmr::pool_options opts;
                opts.largest_required_pool_block = policy::max_pool_size;
                opts.max_blocks_per_chunk = policy::max_blocks;

                // new 出来的资源随进程销毁，避免静态析构顺序问题
                return new synchronized_pool(opts, std::pmr::new_delete_resource());
            }();
            return pool;
        }

        /**
         * @brief 获取线程局部内存池 (Thread-Local Unsynchronized Pool)
         * @details 适用于：frame_arena、局部临时计算、单线程处理逻辑。
         * @note 完全无锁 (Zero Lock)，性能极高，但绝对不可跨线程归还内存。
         * @return unsynchronized_pool* 线程局部池指针
         */
        static unsynchronized_pool *thread_local_pool()
        {
            // thread_local 保证每个线程一份
            thread_local auto *pool = []()
            {
                std::pmr::pool_options opts;
                opts.largest_required_pool_block = policy::max_pool_size;
                opts.max_blocks_per_chunk = policy::max_blocks;

                return new unsynchronized_pool(opts, std::pmr::new_delete_resource());
            }();
            return pool;
        }

        /**
         * @brief 启用全局池化策略
         * @details 将全局默认内存资源设置为 global_pool。
         */
        static void enable_global_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    };

    /**
     * @brief 对象池基类 (Mixin)
     * @details 继承此类的对象将自动使用内存池进行分配和释放。
     * @note 为了安全，通用对象一律使用全局同步池。
     * @tparam T 子类类型
     */
    template <typename T>
    class pooled_object
    {
    public:
        void *operator new(const std::size_t count)
        {
            if (count <= policy::max_pool_size)
            {
                return system::global_pool()->allocate(count);
            }
            // 大对象直接走系统堆
            return ::operator new(count);
        }

        void operator delete(void *ptr, const std::size_t count)
        {
            if (count <= policy::max_pool_size)
            {
                // 对应 allocate，必须归还给 global_pool
                system::global_pool()->deallocate(ptr, count);
            }
            else
            {
                ::operator delete(ptr);
            }
        }

        // 数组支持
        void *operator new[](const std::size_t count)
        {
            if (count <= policy::max_pool_size)
                return system::global_pool()->allocate(count);
            return ::operator new[](count);
        }

        void operator delete[](void *ptr, std::size_t count)
        {
            if (count <= policy::max_pool_size)
                system::global_pool()->deallocate(ptr, count);
            else
                ::operator delete[](ptr);
        }
    };

    /**
     * @brief 帧分配器 / 线性分配器
     * @details 使用栈上缓冲区和单调增长资源，提供极高的分配性能。
     * @note 使用 `thread_local_pool` 作为上游，确保无锁且高性能。
     */
    class frame_arena
    {
        // 降低内部缓冲大小，避免 session 对象过大
        // 大部分内存请求应直接透传给 thread_local_pool (无锁且高效)
        std::byte buffer_[128];
        monotonic_buffer resource_;

    public:
        /**
         * @brief 构造帧分配器
         * @details 初始化单调资源，使用栈缓冲区和线程局部池。
         */
        frame_arena()
            /**
             * Upstream 使用 thread_local_pool (无锁)，性能最大化
             * 在此不用初始化buffer_容器，反正还要覆盖，初始化还浪费性能
             */

            : resource_(buffer_, sizeof(buffer_), system::thread_local_pool())
        {
        }

        // 禁止拷贝和移动，确保 resource_ 指针有效性
        frame_arena(const frame_arena &) = delete;
        frame_arena &operator=(const frame_arena &) = delete;

        /**
         * @brief 获取内存资源指针
         * @return resource_pointer
         */
        resource_pointer get() { return &resource_; }

        /**
         * @brief 重置分配器
         * @details 释放所有已分配内存，重置游标。
         */
        void reset() { resource_.release(); }
    };

} // namespace ngx::memory
