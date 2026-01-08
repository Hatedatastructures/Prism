#pragma once

#include <mutex>
#include "forward-engine/memory/container.hpp"

namespace ngx::memory
{
    /**
     * @brief 内存策略配置
     * @warning 针对代理服务器负载优化的参数配置,不同情况下配置可能不同
     */
    struct policy
    {
        /**
         * @brief 每个 Chunk 包含的最大块数
         * 降低此值可减少内存峰值。
         * 256 * 16KB = 4MB (最大 Chunk 大小)，相比之前的 256MB 大幅降低了 OOM 风险。
         */
        static constexpr std::size_t max_blocks = 256;

        /**
         * @brief 最大池化阈值
         * 16KB 足以覆盖 HTTP Header、RPC 元数据和小型 Payload。
         * 大于此值的对象将直接走系统堆 (malloc)，避免长驻内存池。
         */
        static constexpr std::size_t max_pool_size = 16384;
    };

    /**
     * @brief 全局内存系统管理器
     */
    class system
    {
    public:
        /**
         * @brief 获取全局线程安全池 (Global Synchronized Pool)
         * @warning 适用于：跨线程传递的对象、生命周期不确定的对象 (pooled_object 默认使用此池)。
         * @note 线程安全，内部有细粒度锁和 Thread Cache。
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
         * @warning 适用于：frame_arena、局部临时计算、单线程处理逻辑。
         * @note 完全无锁 (Zero Lock)，性能极高，但绝对不可跨线程归还内存。
         */
        static unsynchronized_pool *thread_local_pool()
        {
            // thread_local 保证每个线程一份
            static thread_local auto *pool = []()
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
         */
        static void enable_global_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    };

    /**
     * @brief 对象池基类 (Mixin)
     * @warning 修正：为了安全，通用对象一律使用全局同步池。
     */
    template <typename T>
    class pooled_object
    {
    public:
        static void *operator new(const std::size_t count)
        {
            if (count <= policy::max_pool_size)
            {
                return system::global_pool()->allocate(count);
            }
            // 大对象直接走系统堆
            return ::operator new(count);
        }

        static void operator delete(void *ptr, const std::size_t count)
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
        static void *operator new[](const std::size_t count)
        {
            if (count <= policy::max_pool_size)
                return system::global_pool()->allocate(count);
            return ::operator new[](count);
        }
        static void operator delete[](void *ptr, std::size_t count)
        {
            if (count <= policy::max_pool_size)
                system::global_pool()->deallocate(ptr, count);
            else
                ::operator delete[](ptr);
        }
    };

    /**
     * @brief 帧分配器 / 线性分配器
     * 保持使用 thread_local_pool，因为它是栈上使用的，绝对安全。
     */
    class frame_arena
    {
    private:
        // 16KB 栈缓冲，覆盖 99% 的请求头，避免栈溢出
        std::byte buffer_[16 * 1024];
        monotonic_buffer resource_;

    public:
        frame_arena()
            // Upstream 使用 thread_local_pool (无锁)，性能最大化
            : buffer_{}, resource_(buffer_, sizeof(buffer_), system::thread_local_pool())
        {
        }

        // 禁止拷贝和移动，确保 resource_ 指针有效性
        frame_arena(const frame_arena &) = delete;
        frame_arena &operator=(const frame_arena &) = delete;

        resource_pointer get() { return &resource_; }
        void reset() { resource_.release(); }
    };

} // namespace ngx::memory
