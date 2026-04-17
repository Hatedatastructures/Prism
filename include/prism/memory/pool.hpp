/**
 * @file pool.hpp
 * @brief 内存池系统定义
 * @details 提供全局和线程局部的内存池管理，以及基于
 * 内存池的对象分配基类和帧分配器。遵循热路径无分配、
 * 线程封闭和大小分类的设计原则。
 */
#pragma once

#include <prism/memory/container.hpp>

namespace psm::memory
{
    /**
     * @struct policy
     * @brief 内存策略配置
     * @details 定义内存池的调优参数，针对代理服务器
     * 典型负载进行优化，平衡内存利用率、分配速度和
     * 内存峰值。
     */
    struct policy
    {
        // 每个 Chunk 包含的最大块数，降低此值可减少内存峰值
        static constexpr std::size_t max_blocks = 256;

        // 最大池化阈值，16KB 足以覆盖 HTTP Header 等典型对象
        static constexpr std::size_t max_pool_size = 16384;
    }; // struct policy

    /**
     * @class system
     * @brief 全局内存系统管理器
     * @details 提供全局单例的内存池访问接口，管理全局
     * 同步池、线程局部池和热路径池。所有方法均为静态
     * 方法，无需实例化。
     */
    class system
    {
    public:
        /**
         * @brief 获取全局线程安全池
         * @return 全局同步池指针，永不返回 nullptr
         * @details 适用于跨线程传递的对象和生命周期
         * 不确定的长期对象。使用 new 分配，确保在静态
         * 析构阶段后仍可用。
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
         * @brief 获取线程局部内存池
         * @return 线程局部池指针，永不返回 nullptr
         * @details 返回线程局部的无锁内存池，适用于临时
         * 计算和单线程处理逻辑。使用 thread_local 存储，
         * 每个线程独立实例。
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
         * @brief 获取热路径内存池
         * @return 线程局部池指针，与 thread_local_pool() 相同
         * @details 热路径专用的内存池，是 thread_local_pool()
         * 的语义化别名。分配的对象生命周期必须与当前线程
         * 绑定，禁止跨线程传递。
         */
        static unsynchronized_pool *hot_path_pool()
        {
            return thread_local_pool();
        }

        /**
         * @brief 启用全局池化策略
         * @details 将默认内存资源设置为全局内存池。调用后，
         * 所有未指定显式内存资源的 PMR 容器将自动使用
         * global_pool()。应在程序启动早期调用。
         */
        static void enable_global_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    }; // class system

    /**
     * @class pooled_object
     * @brief 对象池基类模板
     * @tparam T 子类类型，使用 CRTP 惯用法
     * @details 通过重载 operator new/delete 使继承类
     * 自动使用内存池分配。小对象使用 global_pool()，
     * 大对象直通系统堆。
     */
    template <typename T>
    class pooled_object
    {
    public:
        /**
         * @brief 重载单对象 new 操作符
         * @param count 待分配的字节数
         * @return 分配的内存指针
         * @details 小对象从 global_pool 分配，大对象直通
         * 系统堆。
         */
        void *operator new(const std::size_t count)
        {
            if (count <= policy::max_pool_size)
            {
                return system::global_pool()->allocate(count);
            }
            // 大对象直接走系统堆
            return ::operator new(count);
        }

        /**
         * @brief 重载单对象 delete 操作符
         * @param ptr 待释放的内存指针
         * @param count 待释放的字节数
         * @details 必须与 operator new 对应，归还到正确的
         * 位置。
         */
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

        /**
         * @brief 重载数组 new 操作符
         * @param count 待分配的字节数
         * @return 分配的内存指针
         */
        void *operator new[](const std::size_t count)
        {
            if (count <= policy::max_pool_size)
                return system::global_pool()->allocate(count);
            return ::operator new[](count);
        }

        /**
         * @brief 重载数组 delete 操作符
         * @param ptr 待释放的内存指针
         * @param count 待释放的字节数
         */
        void operator delete[](void *ptr, std::size_t count)
        {
            if (count <= policy::max_pool_size)
                system::global_pool()->deallocate(ptr, count);
            else
                ::operator delete[](ptr);
        }
    }; // class pooled_object

    /**
     * @class frame_arena
     * @brief 帧分配器或线性分配器
     * @details 使用栈上缓冲区和单调增长资源，提供极高
     * 的分配性能。适用于短生命周期、高频分配的场景。
     * 不可拷贝和移动，分配的内存必须在 reset() 或
     * 析构前使用。
     */
    class frame_arena
    {
        // 内部缓冲覆盖典型 mux 地址头，避免解析时穿透到上游池
        std::byte buffer_[512];
        monotonic_buffer resource_;

    public:
        /**
         * @brief 构造帧分配器
         * @details 使用栈缓冲区和线程局部池作为上游资源，
         * 实现无锁性能最大化。
         */
        frame_arena()
            : resource_(buffer_, sizeof(buffer_), system::thread_local_pool())
        {
        }

        // 禁止拷贝，确保 resource_ 指针有效性
        frame_arena(const frame_arena &) = delete;
        // 禁止赋值，确保 resource_ 指针有效性
        frame_arena &operator=(const frame_arena &) = delete;

        /**
         * @brief 获取内存资源指针
         * @return 内存资源指针，可用于创建 PMR 容器
         */
        resource_pointer get() { return &resource_; }

        /**
         * @brief 重置分配器
         * @details 释放所有已分配内存，重置游标到初始位置。
         * 调用后之前分配的所有内存均失效。
         */
        void reset() { resource_.release(); }
    }; // class frame_arena

} // namespace psm::memory
