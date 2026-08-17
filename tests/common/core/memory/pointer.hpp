/**
 * @file pointer.hpp
 * @brief 会话级内存指针体系
 * @details 对齐主项目 resource::session 的内存模型：
 * - frame_arena：会话级帧竞技场（栈缓冲 + 线程局部池上游），
 *   热路径零释放（arena 语义，随会话析构一次性回收）
 * - 资源指针（resource_pointer）在函数间传递（非拥有语义），
 *   由会话持有 arena，handler/conn 通过 arena.get() 分配临时对象
 * @note 生命周期规则（对齐 docs/ARCHITECTURE.md）：
 * - arena 由会话（conn 工厂）持有，随会话析构
 * - arena 分配的对象只能在会话存活期内使用（handler 内）
 * - 跨协程/跨会话的对象必须用 global_pool（preview/snapshot 规则）
 */

#pragma once

#include <cstddef>
#include <memory>
#include <system_error>
#include <memory_resource>

#include <common/core/memory/container.hpp>
#include <common/core/memory/pool.hpp>

namespace preview::memory
{

    /**
     * @concept restrict
     * @brief 会话内存策略约束
     * @details 描述可作为协议 conn 内存策略的类型契约：
     * - 提供容器类型别名 buffer<T> / dynamic_string
     * - 提供分配接口 arena() / make_buffer() / make_vector() / make_string()
     * 满足约束的类型可注入 conn 模板（Memory 参数），
     * 使 conn 不耦合具体分配器实现。
     */
    template <typename Memory>
    concept restrict = requires(Memory mem)
    {
        // 容器类型别名
        typename Memory::template buffer<std::uint8_t>;
        typename Memory::dynamic_string;

        // 分配接口（返回类型精确匹配）
        { mem.arena() } -> std::same_as<preview::memory::resource_pointer>;
        { mem.template make_buffer<std::uint8_t>(std::size_t{0}) }
            -> std::same_as<typename Memory::template buffer<std::uint8_t>>;
        { mem.template make_vector<std::uint8_t>() }
            -> std::same_as<typename Memory::template buffer<std::uint8_t>>;
        { mem.make_string(std::string_view{}) }
            -> std::same_as<typename Memory::dynamic_string>;
    };

    /**
     * @class frame_arena
     * @brief 会话级帧竞技场（模板化栈缓冲大小）
     * @details 提供会话生命周期内的零释放分配：
     * - 栈缓冲（默认 8KB）覆盖典型协议帧/地址解析，零堆分配
     * - 缓冲耗尽自动回退线程局部池（仍无锁）
     * - reset() 在会话边界调用，回收全部内存
     * @tparam ArenaSize 栈缓冲字节数（默认 8192；特殊协议可自定义）
     * @note 对齐主项目 preview::resource::session::arena
     */
    template <std::size_t ArenaSize = 8192>
    class frame_arena
    {
    public:
        /**
         * @brief 构造会话竞技场
         * @details 使用栈缓冲区 + 线程局部池作为上游资源，
         * 实现无锁性能最大化
         */
        frame_arena() : resource_(buffer_, ArenaSize, system::local_pool())
        {
        }

        frame_arena(const frame_arena &) = delete;
        auto operator=(const frame_arena &) -> frame_arena & = delete;

        /**
         * @brief 获取资源指针（供 PMR 容器/字符串使用）
         * @return 内存资源指针，非拥有
         */
        [[nodiscard]] auto get() noexcept
             -> resource_pointer
        {
            return &resource_;
        }

        /**
         * @brief 获取资源指针（const 版本）
         * @return 内存资源指针，非拥有
         */
        [[nodiscard]] auto get() const noexcept 
            -> resource_pointer
        {
            return &resource_;
        }

        /**
         * @brief 重置竞技场
         * @details 释放已分配内存（回到缓冲起点），
         * 之前分配的所有对象失效。会话边界调用。
         */
        void reset() noexcept
        {
            resource_.release();
        }

        /**
         * @brief 获取栈缓冲大小
         * @return 字节数
         */
        [[nodiscard]] static constexpr auto size() noexcept 
            -> std::size_t
        {
            return ArenaSize;
        }

    private:
        /// 栈缓冲：覆盖典型协议帧解析/地址序列化
        alignas(std::max_align_t) std::byte buffer_[ArenaSize];
        /// 单调增长资源（仅分配不释放，随 reset/析构回收）
        /// mutable：arena() 为 const 语义（不改变逻辑状态）
        mutable monotonic_buffer resource_;
    };

    /**
     * @class session_resource
     * @brief 会话级内存上下文（模板化栈缓冲大小）
     * @details 聚合 arena + 便捷分配接口：
     * - string()：arena 分配的字符串
     * - vector()：arena 分配的动态数组
     * - make_buffer()：分级（≤栈缓冲走 arena，超出走线程局部池）
     * @tparam ArenaSize 栈缓冲字节数（默认 8192；大帧协议可自定义）
     * @note 会话对象（conn）持有本上下文，内部临时分配走 arena
     */
    template <std::size_t ArenaSize = 8192>
    class session_resource
    {
    public:
        /**
         * @brief 容器类型别名（策略契约：供 conn 模板使用）
         * @tparam Type 元素类型
         */
        template <typename Type>
        using buffer = memory::vector<Type>;

        /// 字符串类型别名（策略契约）
        using dynamic_string = memory::string;

        /**
         * @brief 构造内存上下文（持有 arena）
         */
        session_resource() = default;

        session_resource(const session_resource &) = delete;
        auto operator=(const session_resource &) -> session_resource & = delete;

        /**
         * @brief 获取竞技场资源指针
         * @return 非拥有资源指针
         */
        [[nodiscard]] auto arena() noexcept 
            -> resource_pointer
        {
            return arena_.get();
        }

        /**
         * @brief 获取竞技场资源指针（const 版本）
         * @return 非拥有资源指针
         */
        [[nodiscard]] auto arena() const noexcept 
            -> resource_pointer
        {
            return arena_.get();
        }

        /**
         * @brief 获取栈缓冲大小
         * @return 字节数
         */
        [[nodiscard]] static constexpr auto arena_size() noexcept 
            -> std::size_t
        {
            return ArenaSize;
        }

        /**
         * @brief 重置竞技场（会话边界）
         */
        void reset() noexcept
        {
            arena_.reset();
        }

        /**
         * @brief 在竞技场上构造字符串
         * @param str 源字符串
         * @return 竞技场分配的字符串（会话生命周期）
         */
        [[nodiscard]] auto make_string(std::string_view str) 
            -> memory::string
        {
            return memory::string(str, arena_.get());
        }

        /**
         * @brief 在竞技场上构造动态数组
         * @tparam Type 元素类型
         * @return 竞技场分配的 vector（会话生命周期）
         */
        template <typename Type>
        [[nodiscard]] auto make_vector() 
            -> memory::vector<Type>
        {
            return memory::vector<Type>(arena_.get());
        }

        /**
         * @brief 分配会话级缓冲（分级：小对象走竞技场，大对象走线程局部池）
         * @tparam Type 元素类型（byte/uint8_t 等）
         * @param count 元素数
         * @return 缓冲（>栈缓冲大小自动回退 local_pool，避免耗尽竞技场）
         * @note 对齐主项目 pool 的 largest_required_pool_block=16KB：
         *       vmess/ss2022 加密缓冲（16KB+）走池，帧/地址（<8KB）走竞技场
         */
        template <typename Type>
        [[nodiscard]] auto make_buffer(const std::size_t count) 
            -> memory::vector<Type>
        {
            memory::vector<Type> buf;
            if (count * sizeof(Type) <= ArenaSize)
            {
                buf = memory::vector<Type>(arena_.get());
            }
            else
            {
                buf = memory::vector<Type>(system::local_pool());
            }
            buf.resize(count);
            return buf;
        }

    private:
        frame_arena<ArenaSize> arena_; ///< 帧竞技场（会话持有）
    };

    /**
     * @brief 便捷别名：会话内存共享指针（默认 8KB 栈缓冲）
     */
    using shared_session_resource = std::shared_ptr<session_resource<>>;

} // namespace preview::memory
