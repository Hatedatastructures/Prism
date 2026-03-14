/**
 * @file pool.hpp
 * @brief 内存池系统定义
 * @details 提供全局和线程局部的内存池管理，以及基于内存池的对象分配基类
 * 和帧分配器。该模块是项目内存管理体系的核心，遵循性能军规中关于热路径
 * 无分配、线程封闭和大小分类的设计原则。
 *
 * 设计哲学包括四个核心原则。热路径无分配指网络 I/O、协议解析等热路径
 * 严禁使用 new 或 malloc。线程封闭通过线程局部池实现无锁并发。大小分类
 * 指小对象池化处理，大对象直通系统堆。生命周期管理区分全局池用于跨线程
 * 对象，线程局部池用于临时对象。
 *
 * 核心组件分为四个部分。策略配置 policy 提供内存池参数调优能力。系统
 * 管理器 system 提供全局和线程局部池访问接口。池化对象基类 pooled_object
 * 实现自动化内存池分配。帧分配器 frame_arena 提供栈缓冲加单调增长的
 * 极速分配能力。
 */
#pragma once

#include <forward-engine/memory/container.hpp>

namespace ngx::memory
{
    /**
     * @struct policy
     * @brief 内存策略配置结构体
     * @details 定义内存池的调优参数，针对代理服务器典型负载进行优化。
     * 这些参数基于实际性能分析和内存使用模式确定，旨在平衡内存利用率、
     * 分配速度和内存峰值。
     *
     * 调优目标包括三个方面。降低内存峰值通过限制单个 Chunk 大小来避免
     * 内存耗尽风险。减少内存碎片通过合理的块大小阈值来平衡内存利用率和
     * 分配速度。适应负载特征针对代理服务器的典型对象大小进行优化，包括
     * HTTP 头部、RPC 元数据和小型负载等场景。
     */
    struct policy
    {
        // 每个 Chunk 包含的最大块数。降低此值可减少内存峰值。
        // 256 乘以 16KB 等于 4MB 最大 Chunk 大小，相比之前的 256MB
        // 大幅降低了内存耗尽风险。
        static constexpr std::size_t max_blocks = 256;

        // 最大池化阈值，16KB 足以覆盖 HTTP Header、RPC 元数据和小型
        // Payload。大于此值的对象将直接走系统堆 malloc，避免长驻内存池。
        static constexpr std::size_t max_pool_size = 16384;

        // 小型缓冲区大小，8KB 适用于临时缓冲区、栈上数组等场景。
        static constexpr std::size_t small_buffer_size = 8192;
    };

    /**
     * @class system
     * @brief 全局内存系统管理器
     * @details 提供全局单例的内存池访问接口，管理三种关键内存池：全局同步池、
     * 线程局部池和热路径池。该类是内存系统的统一入口点，遵循性能军规中的
     * 分配器透传原则。所有方法均为静态方法，无需实例化此类。
     */
    class system
    {
    public:
        /**
         * @brief 获取全局线程安全池
         * @return 全局同步池指针，永不返回 nullptr
         *
         * @details 返回全局线程安全的内存池单例，适用于跨线程传递的对象和
         * 生命周期不确定的对象。该池使用 new 分配，确保在静态析构阶段后
         * 仍可用。返回的指针由静态单例管理，调用者不应尝试 delete。
         *
         * 适用场景包括跨线程共享的对象如 session 和 connection，生命周期
         * 不确定的长期对象如全局配置和共享缓存，以及 pooled_object 基类
         * 默认使用的池。
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
         *
         * @details 返回线程局部的无锁内存池单例，适用于临时计算和单线程处理
         * 逻辑。使用 thread_local 存储，确保每个线程独立实例。返回的指针
         * 由线程局部存储管理，调用者不应尝试 delete。
         *
         * 适用场景包括局部临时计算和中间结果，以及单线程处理流水线中的
         * 临时对象。技术特性包括完全无锁的零锁设计、每个线程独立实例的
         * 线程封闭机制，以及随线程销毁自动清理的生命周期管理。
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
         *
         * @details 返回热路径专用的内存池，是 thread_local_pool() 的语义化
         * 别名。该方法无额外开销，用于强调性能关键路径必须使用无锁分配器。
         * 热路径分配的对象生命周期必须与当前线程绑定，禁止跨线程传递。
         *
         * 适用场景包括网络 I/O 回调中的临时分配、协议解析和数据转发路径，
         * 以及协程切换和异步操作中的对象分配。提供语义化名称，强制开发者
         * 在热路径中使用无锁分配器，避免意外使用全局同步池。
         */
        static unsynchronized_pool *hot_path_pool()
        {
            return thread_local_pool();
        }

        /**
         * @brief 启用全局池化策略
         *
         * @details 将 C++ 标准库的默认内存资源设置为全局内存池。调用后，
         * 所有使用 std::pmr::polymorphic_allocator 且未指定显式内存资源的
         * 容器将自动使用 global_pool()。此设置是全局性的，影响整个进程，
         * 应在程序启动早期调用。
         *
         * 影响范围包括 std::pmr::vector、std::pmr::string、std::pmr::map
         * 等容器，使用 std::pmr::polymorphic_allocator 的自定义类型，以及
         * 通过 std::pmr::get_default_resource() 获取资源的代码。一旦启用，
         * 不应再修改默认资源，否则可能导致资源管理混乱。
         */
        static void enable_global_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    };

    /**
     * @class pooled_object
     * @brief 对象池基类模板
     * @tparam T 子类类型，使用 CRTP 惯用法
     *
     * @details 通过重载 operator new 和 operator delete，使继承类自动使用
     * 内存池进行分配和释放。该基类不提供自定义对齐支持，需要对齐的对象应
     * 单独处理。继承此类的对象自动获得池化能力，无需额外代码。
     *
     * 工作原理包括三个方面。重载 operator new 检查对象大小，小对象使用
     * global_pool()，大对象直通系统堆。重载 operator delete 对应地归还
     * 内存到正确位置。支持数组版本的 operator new[] 和 operator delete[]。
     *
     * 设计选择包括两个方面。使用全局池确保线程安全，通用对象使用全局同步
     * 池而非线程局部池。大小阈值遵循 policy::max_pool_size，大对象不走池化。
     */
    template <typename T>
    class pooled_object
    {
    public:
        /**
         * @brief 重载单对象 new 操作符
         * @param count 待分配的字节数
         * @return 分配的内存指针
         *
         * @details 如果对象大小不超过 max_pool_size，则从 global_pool 分配；
         * 否则直通系统堆。这确保小对象走池化路径，大对象走系统堆。
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
         *
         * @details 如果对象大小不超过 max_pool_size，则归还给 global_pool；
         * 否则使用系统堆释放。必须与 operator new 对应，归还到正确的位置。
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
         *
         * @details 数组版本的分配逻辑与单对象版本相同，根据大小选择池化或
         * 系统堆路径。
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
         *
         * @details 数组版本的释放逻辑与单对象版本相同，确保内存归还到
         * 正确的位置。
         */
        void operator delete[](void *ptr, std::size_t count)
        {
            if (count <= policy::max_pool_size)
                system::global_pool()->deallocate(ptr, count);
            else
                ::operator delete[](ptr);
        }
    };

    /**
     * @class frame_arena
     * @brief 帧分配器或线性分配器
     * @details 使用栈上缓冲区和单调增长资源，提供极高的分配性能。该分配器
     * 适用于短生命周期、高频分配的场景。设计为不可拷贝和移动，确保资源
     * 指针有效性。分配的内存必须在 reset() 或析构前使用，避免悬垂指针。
     *
     * 设计原理包括三个方面。栈缓冲区使用 128 字节栈上数组作为一级缓存，
     * 避免小分配穿透到堆。单调增长使用 std::pmr::monotonic_buffer_resource
     * 实现线性分配。无锁上游以 thread_local_pool() 作为后备资源，确保
     * 无锁性能。
     *
     * 适用场景包括函数调用帧内的临时对象、协议解析中的临时数据结构，
     * 以及短生命周期的中间计算结果。性能特性包括栈缓冲区内的极速分配、
     * 栈缓冲区用尽后自动使用线程局部池的自动回退，以及通过 reset() 一次性
     * 释放所有内存的批量释放能力。
     */
    class frame_arena
    {
        // 降低内部缓冲大小，避免 session 对象过大。
        // 大部分内存请求应直接透传给 thread_local_pool，无锁且高效。
        std::byte buffer_[128];
        monotonic_buffer resource_;

    public:
        /**
         * @brief 构造帧分配器
         *
         * @details 初始化单调资源，使用栈缓冲区和线程局部池作为上游资源。
         * 上游使用 thread_local_pool 实现无锁性能最大化。栈缓冲区无需
         * 初始化，反正会被覆盖，初始化反而浪费性能。
         */
        frame_arena()
            : resource_(buffer_, sizeof(buffer_), system::thread_local_pool())
        {
        }

        // 禁止拷贝和移动，确保 resource_ 指针有效性
        frame_arena(const frame_arena &) = delete;
        frame_arena &operator=(const frame_arena &) = delete;

        /**
         * @brief 获取内存资源指针
         * @return 内存资源指针
         *
         * @details 返回内部 monotonic_buffer_resource 的指针，可用于创建
         * PMR 容器或进行内存分配。
         */
        resource_pointer get() { return &resource_; }

        /**
         * @brief 重置分配器
         *
         * @details 释放所有已分配内存，重置游标到初始位置。调用后，
         * 之前分配的所有内存均失效，不应再访问。
         */
        void reset() { resource_.release(); }
    };

} // namespace ngx::memory
