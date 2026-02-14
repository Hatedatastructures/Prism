/**
 * @file pool.hpp
 * @brief 内存池系统
 * @details 提供全局和线程局部的内存池管理，以及基于内存池的对象分配基类和帧分配器。
 *
 * 设计哲学：
 * - 热路径无分配：网络 `I/O`、协议解析等热路径严禁 `new/malloc`；
 * - 线程封闭：通过线程局部池实现无锁并发（`Thread Confinement`）；
 * - 大小分类：小对象池化（≤16KB），大对象直通系统堆；
 * - 生命周期管理：全局池用于跨线程对象，线程局部池用于临时对象。
 *
 * 核心组件：
 * 1. 策略配置 (`policy`)：内存池参数调优；
 * 2. 系统管理器 (`system`)：全局和线程局部池访问；
 * 3. 池化对象基类 (`pooled_object`)：自动化内存池分配；
 * 4. 帧分配器 (`frame_arena`)：栈缓冲+单调增长的极速分配。
 *
 */
#pragma once

#include <forward-engine/memory/container.hpp>

namespace ngx::memory
{
    /**
     * @struct policy
     * @brief 内存策略配置
     * @details 定义内存池的调优参数，针对代理服务器典型负载进行优化。这些参数基于实际性能分析和内存使用模式确定。
     *
     * 调优目标：
     * @details - 降低内存峰值：限制单个 `Chunk` 大小，避免 `OOM`（内存耗尽）；
     * @details - 减少内存碎片：合理的块大小阈值，平衡内存利用率和分配速度；
     * @details - 适应负载特征：针对代理服务器的典型对象大小（`HTTP` 头部、`RPC` 元数据、小型负载）优化。
     *
     * @note 这些参数是经验值，可通过性能测试调整。
     * @warning 修改参数可能影响性能和内存使用模式，需重新进行性能评估。
     * @throws 无异常（仅包含静态常量）
     *
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
     * @class system
     * @brief 全局内存系统管理器
     * @note 所有方法都是静态的，无需实例化此类。
     * @warning 线程局部池分配的内存严禁跨线程使用或释放。
     * @throws 各方法可能抛出 `std::bad_alloc`（如果底层 `new` 失败）
     * @details 提供全局单例的内存池访问接口，管理三种关键内存池：全局同步池、线程局部池和热路径池。
     * 该类是内存系统的统一入口点，遵循"性能军规"中的分配器透传原则。
     * ```
     * // 使用示例：获取不同内存池
     * // 全局同步池（线程安全，用于跨线程对象）
     * auto* global = ngx::memory::system::global_pool();
     * // 线程局部池（无锁，高性能，用于临时对象）
     * auto* local = ngx::memory::system::thread_local_pool();
     * // 热路径池（无锁别名，用于性能关键路径）
     * auto* hot = ngx::memory::system::hot_path_pool();
     *
     * // 使用示例：启用全局池化
     * ngx::memory::system::enable_global_pooling();
     * // 此后，std::pmr::polymorphic_allocator 默认使用 global_pool
     * std::pmr::vector<int> vec;  // 自动使用 global_pool
     * ```
     *
     */
    class system
    {
    public:
        /**
         * @brief 获取全局线程安全池 (Global Synchronized Pool)
         * @return `synchronized_pool*` 全局同步池指针，永不返回 `nullptr`
         * @note 该池使用 `new` 分配，确保在静态析构阶段后仍可用。
         * @warning 不要手动 `delete` 返回的指针，它由静态单例管理。
         * @throws `std::bad_alloc` 如果内存不足，无法创建池实例
         * @details 返回全局线程安全的内存池单例，适用于跨线程传递的对象和生命周期不确定的对象。
         * 适用场景：
         * @details - 跨线程共享的对象（例如 `session`、`connection`）；
         * @details - 生命周期不确定的长期对象；如：全局配置、共享缓存等
         * @details - `pooled_object` 基类默认使用的池。
         *
         *
         * ```
         * // 使用示例：从全局池分配
         * auto* pool = ngx::memory::system::global_pool();
         * void* memory = pool->allocate(1024);  // 分配 1KB
         * pool->deallocate(memory, 1024);       // 释放
         *
         * // 使用示例：与 pooled_object 配合
         * class MyObject : public ngx::memory::pooled_object<MyObject>
         * {
         *     // 自动使用 global_pool
         * };
         * MyObject* obj = new MyObject();  // 从 global_pool 分配
         * delete obj;                      // 归还到 global_pool
         * ```
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
         * @return `unsynchronized_pool*` 线程局部池指针，永不返回 `nullptr`
         * @note 使用 `thread_local` 存储，确保每个线程独立实例。
         * @warning **绝对不可**跨线程归还内存，否则导致未定义行为。
         * @throws `std::bad_alloc` 如果内存不足，无法创建池实例
         * @details 返回线程局部的无锁内存池单例，适用于临时计算和单线程处理逻辑。
         *
         * 适用场景：
         * @details - 局部临时计算和中间结果；
         * @details - 单线程处理流水线中的临时对象。
         *
         * 技术特性：
         * @details - 完全无锁：`Zero Lock`，性能极高；
         * @details - 线程封闭：每个线程有独立实例，内存不共享；
         * @details - 线程生命周期：随线程销毁自动清理。
         *
         * ```
         * // 使用示例：线程局部分配
         * auto* pool = ngx::memory::system::thread_local_pool();
         * void* temp_buffer = pool->allocate(512);  // 分配临时缓冲区
         * // ... 使用缓冲区 ...
         * pool->deallocate(temp_buffer, 512);       // 在同一线程内释放
         *
         * // 错误示例：跨线程使用（禁止！）
         * // std::thread other_thread([pool]
         * // {
         * //   pool->deallocate(some_ptr, size);  // 未定义行为！
         * // });
         * ```
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
         * @brief 获取热路径内存池 (Hot-Path Pool)
         * @return `unsynchronized_pool*` 线程局部池指针（与 `thread_local_pool()` 相同）
         * @note 该方法是 `thread_local_pool()` 的简单包装，无额外开销。
         * @warning 热路径分配的对象生命周期必须与当前线程绑定，禁止跨线程传递。
         * @throws `std::bad_alloc` 如果内存不足，无法创建池实例
         * @details 返回热路径专用的内存池，是 `thread_local_pool()` 的语义化别名。
         * 用于强调性能关键路径（热路径）必须使用无锁分配器。
         *
         * 适用场景：
         * @details - 网络 `I/O` 回调中的临时分配；
         * @details - 协议解析和数据转发路径；
         * @details - 协程切换和异步操作中的对象分配。
         *
         * @details 提供语义化名称，强制开发者在热路径中使用无锁分配器，避免意外使用全局同步池。
         *
         * ```
         * // 使用示例：热路径分配
         * auto* hot_pool = ngx::memory::system::hot_path_pool();
         * void* hot_buffer = hot_pool->allocate(256);  // 热路径零锁分配
         * // ... 在热路径中使用 ...
         * hot_pool->deallocate(hot_buffer, 256);
         *
         * // 设计对比：明确区分使用场景
         * void process_packet()
         * {
         *     // 热路径：使用 hot_path_pool
         *     auto* temp = ngx::memory::system::hot_path_pool()->allocate(128);
         *     // 冷路径：可使用 global_pool
         *     auto* persistent = ngx::memory::system::global_pool()->allocate(1024);
         * }
         * ```
         */
        static unsynchronized_pool *hot_path_pool()
        {
            return thread_local_pool();
        }

        /**
         * @brief 启用全局池化策略
         * @note 此设置是全局性的，影响整个进程。
         * @warning 一旦启用，不应再修改默认资源，否则可能导致资源管理混乱。
         * @details 将 `C++` 标准库的默认内存资源设置为全局内存池。
         * 调用后，所有使用 `std::pmr::polymorphic_allocator` 且未指定显式内存资源的容器将自动使用 `global_pool()`。
         *
         * 影响范围：
         * @details - `std::pmr::vector`、`std::pmr::string`、`std::pmr::map` 等容器；
         * @details - 使用 `std::pmr::polymorphic_allocator` 的自定义类型；
         * @details - 通过 `std::pmr::get_default_resource()` 获取资源的代码。
         *
         * 使用时机：
         * @details 应在程序启动早期调用，确保所有后续分配使用内存池。
         *
         * ```
         * // 使用示例：程序初始化
         * int main()
         * {
         *     // 启用全局池化
         *     ngx::memory::system::enable_global_pooling();
         *
         *     // 此后，所有默认容器使用内存池
         *     std::pmr::vector<int> vec1;      // 使用 global_pool
         *     std::pmr::string str1;           // 使用 global_pool
         *
         *     // 仍可显式指定其他资源
         *     std::pmr::vector<int> vec2(ngx::memory::system::thread_local_pool());
         *
         *     return 0;
         * }
         * ```
         */
        static void enable_global_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    };

    /**
     * @class pooled_object
     * @brief 对象池基类 (Mixin)
     * @tparam T 子类类型（使用 `CRTP` 惯用法）
     * @note 继承此类的对象自动获得池化能力，无需额外代码。
     * @warning 该基类不提供自定义对齐支持，需要对齐的对象应单独处理。
     * @throws `operator new` 可能抛出 `std::bad_alloc`
     * @details 通过重载 `operator new` 和 `operator delete`，使继承类自动使用内存池进行分配和释放。
     *
     * 工作原理：
     * @details - 重载 `operator new`：检查对象大小，小对象（≤16KB）使用 `global_pool()`，大对象直通系统堆；
     * @details - 重载 `operator delete`：对应地归还内存到正确位置；
     * @details - 支持数组版本：`operator new[]` 和 `operator delete[]`。
     *
     * 设计选择：
     * @details - 使用全局池：为确保线程安全，通用对象使用全局同步池而非线程局部池；
     * @details - 大小阈值：遵循 `policy::max_pool_size` 阈值，大对象不走池化。
     *
     * ```
     * // 使用示例：创建池化对象
     * class Session : public ngx::memory::pooled_object<Session>
     * {
     *     // 类定义...
     * };
     *
     * // 分配和释放自动使用内存池
     * Session* session = new Session();  // 从 global_pool 分配（如果大小≤16KB）
     * delete session;                    // 归还到 global_pool
     *
     * // 数组版本也支持
     * Session* sessions = new Session[10];  // 数组分配
     * delete[] sessions;                    // 数组释放
     *
     * // 大对象示例
     * class LargeObject : public ngx::memory::pooled_object<LargeObject>
     * {
     *     char buffer[20000];  // 20KB > 16KB 阈值
     * };
     * LargeObject* large = new LargeObject();  // 直通系统堆（::operator new）
     * delete large;                            // 系统堆释放
     * ```
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
     * @class frame_arena
     * @brief 帧分配器 / 线性分配器
     * @note 设计为不可拷贝和移动，确保资源指针有效性。
     * @warning 分配的内存必须在 `reset()` 或析构前使用，避免悬垂指针。
     * @throws 分配操作可能抛出 `std::bad_alloc`（如果上游资源耗尽）
     * @details 使用栈上缓冲区和单调增长资源，提供极高的分配性能。该分配器适用于短生命周期、高频分配的场景。
     *
     * 设计原理：
     * @details - 栈缓冲区：128 字节栈上数组作为一级缓存，避免小分配穿透到堆；
     * @details - 单调增长：使用 `std::pmr::monotonic_buffer_resource` 实现线性分配；
     * @details - 无锁上游：以 `thread_local_pool()` 作为后备资源，确保无锁性能。
     *
     * 适用场景：
     * @details - 函数调用帧内的临时对象；
     * @details - 协议解析中的临时数据结构；
     * @details - 短生命周期的中间计算结果。
     *
     * 性能特性：
     * @details - 极速分配：栈缓冲区内的分配几乎零开销；
     * @details - 自动回退：栈缓冲区用尽后自动使用线程局部池；
     * @details - 批量释放：通过 `reset()` 一次性释放所有内存。
     *
     * ```
     * // 使用示例：帧内临时分配
     * ngx::memory::frame_arena arena;
     *
     * // 创建使用帧分配器的容器
     * std::pmr::vector<int> temp_vec(arena.get());
     * std::pmr::string temp_str(arena.get());
     *
     * // 批量操作
     * for (int i = 0; i < 100; ++i)
     * {
     *     temp_vec.push_back(i);  // 使用帧分配器
     * }
     *
     * // 重置释放所有内存
     * arena.reset();  // temp_vec 和 temp_str 内存被释放，但对象本身仍存在
     *
     * // 错误示例：在 reset 后使用
     * // temp_vec.push_back(42);  // 未定义行为！
     * ```
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
