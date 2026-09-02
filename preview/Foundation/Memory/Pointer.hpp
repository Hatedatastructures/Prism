/**
 * @file Pointer.hpp
 * @brief 会话级内存指针体系
 * @details 对齐主项目 Resource::Session 的内存模型：
 * - FrameArena：会话级帧竞技场（栈缓冲 + 线程局部池上游），
 *   热路径零释放（Arena 语义，随会话析构一次性回收）
 * - 资源指针（ResourcePointer）在函数间传递（非拥有语义），
 *   由会话持有 Arena，handler/Conn 通过 Arena.get() 分配临时对象
 * @note 生命周期规则（对齐 docs/ARCHITECTURE.md）：
 * - Arena 由会话（Conn 工厂）持有，随会话析构
 * - Arena 分配的对象只能在会话存活期内使用（handler 内）
 * - 跨协程/跨会话的对象必须用 GlobalPool（Preview/Snapshot 规则）
 */

#pragma once

#include <cstddef>
#include <memory>
#include <system_error>
#include <memory_resource>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pool.hpp>

namespace Preview::Memory
{

    /**
     * @concept Restrict
     * @brief 会话内存策略约束
     * @details 描述可作为协议 Conn 内存策略的类型契约：
     * - 提供容器类型别名 Buffer<T> / DynamicString
     * - 提供分配接口 Arena() / MakeBuffer() / MakeVector() / MakeString()
     * 满足约束的类型可注入 Conn 模板（Memory 参数），
     * 使 Conn 不耦合具体分配器实现。
     */
    template <typename Memory>
    concept Restrict = requires(Memory mem)
    {
        // 容器类型别名
        typename Memory::template Buffer<std::uint8_t>;
        typename Memory::DynamicString;

        // 分配接口（返回类型精确匹配）
        { mem.Arena() } -> std::same_as<ResourcePointer>;
        { mem.template MakeBuffer<std::uint8_t>(std::size_t{0}) }
            -> std::same_as<typename Memory::template Buffer<std::uint8_t>>;
        { mem.template MakeVector<std::uint8_t>() }
            -> std::same_as<typename Memory::template Buffer<std::uint8_t>>;
        { mem.MakeString(std::string_view{}) }
            -> std::same_as<typename Memory::DynamicString>;
    };

    /**
     * @class FrameArena
     * @brief 会话级帧竞技场（模板化栈缓冲大小）
     * @details 提供会话生命周期内的零释放分配：
     * - 栈缓冲（默认 8KB）覆盖典型协议帧/地址解析，零堆分配
     * - 缓冲耗尽自动回退线程局部池（仍无锁）
     * - Reset() 在会话边界调用，回收全部内存
     * @tparam ArenaSize 栈缓冲字节数（默认 8192；特殊协议可自定义）
     * @note 对齐主项目 Preview::Resource::Session::Arena
     */
    template <std::size_t ArenaSize = 8192>
    class FrameArena
    {
    public:
        /**
         * @brief 构造会话竞技场
         * @details 使用栈缓冲区 + 线程局部池作为上游资源，
         * 实现无锁性能最大化
         */
        FrameArena() : Resource_(Buffer_, ArenaSize, System::LocalPool())
        {
        }

        FrameArena(const FrameArena &) = delete;
        auto operator=(const FrameArena &) -> FrameArena & = delete;

        /**
         * @brief 获取资源指针（供 PMR 容器/字符串使用）
         * @return 内存资源指针，非拥有
         */
        [[nodiscard]] auto Get() noexcept
             -> ResourcePointer
        {
            return &Resource_;
        }

        /**
         * @brief 获取资源指针（const 版本）
         * @return 内存资源指针，非拥有
         */
        [[nodiscard]] auto Get() const noexcept 
            -> ResourcePointer
        {
            return &Resource_;
        }

        /**
         * @brief 重置竞技场
         * @details 释放已分配内存（回到缓冲起点），
         * 之前分配的所有对象失效。会话边界调用。
         */
        void Reset() noexcept
        {
            Resource_.release();
        }

        /**
         * @brief 获取栈缓冲大小
         * @return 字节数
         */
        [[nodiscard]] static constexpr auto Size() noexcept 
            -> std::size_t
        {
            return ArenaSize;
        }

    private:
        /// 栈缓冲：覆盖典型协议帧解析/地址序列化
        alignas(std::max_align_t) std::byte Buffer_[ArenaSize];
        /// 单调增长资源（仅分配不释放，随 Reset/析构回收）
        /// mutable：Arena() 为 const 语义（不改变逻辑状态）
        mutable MonotonicBuffer Resource_;
    };

    /**
     * @class SessionResource
     * @brief 会话级内存上下文（模板化栈缓冲大小）
     * @details 聚合 Arena + 便捷分配接口：
     * - string()：Arena 分配的字符串
     * - vector()：Arena 分配的动态数组
     * - MakeBuffer()：分级（≤栈缓冲走 Arena，超出走线程局部池）
     * @tparam ArenaSize 栈缓冲字节数（默认 8192；大帧协议可自定义）
     * @note 会话对象（Conn）持有本上下文，内部临时分配走 Arena
     */
    template <std::size_t ArenaSize = 8192>
    class SessionResource
    {
    public:
        /**
         * @brief 容器类型别名（策略契约：供 Conn 模板使用）
         * @tparam Type 元素类型
         */
        template <typename Type>
        using Buffer = std::pmr::vector<Type>; ///< 容器类型别名（策略契约：PMR 向量，绑定点 Arena）

        /// 字符串类型别名（策略契约：PMR 字符串，绑定点 Arena）
        using DynamicString = std::pmr::string;

        /**
         * @brief 构造内存上下文（持有 Arena）
         */
        SessionResource() = default;

        SessionResource(const SessionResource &) = delete;
        auto operator=(const SessionResource &) -> SessionResource & = delete;

        /**
         * @brief 获取竞技场资源指针
         * @return 非拥有资源指针
         */
        [[nodiscard]] auto Arena() noexcept 
            -> ResourcePointer
        {
            return Arena_.Get();
        }

        /**
         * @brief 获取竞技场资源指针（const 版本）
         * @return 非拥有资源指针
         */
        [[nodiscard]] auto Arena() const noexcept 
            -> ResourcePointer
        {
            return Arena_.Get();
        }

        /**
         * @brief 获取栈缓冲大小
         * @return 字节数
         */
        [[nodiscard]] static constexpr auto GetArenaSize() noexcept 
            -> std::size_t
        {
            return ArenaSize;
        }

        /**
         * @brief 重置竞技场（会话边界）
         */
        void Reset() noexcept
        {
            Arena_.Reset();
        }

        /**
         * @brief 在竞技场上构造字符串
         * @param str 源字符串
         * @return 竞技场分配的字符串（会话生命周期）
         */
        [[nodiscard]] auto MakeString(std::string_view str)
            -> DynamicString
        {
            return DynamicString(str, Arena_.Get());
        }

        /**
         * @brief 在竞技场上构造动态数组
         * @tparam Type 元素类型
         * @return 竞技场分配的 vector（会话生命周期）
         */
        template <typename Type>
        [[nodiscard]] auto MakeVector()
            -> std::pmr::vector<Type>
        {
            return std::pmr::vector<Type>(Arena_.Get());
        }

        /**
         * @brief 分配会话级缓冲（分级：小对象走竞技场，大对象走线程局部池）
         * @tparam Type 元素类型（byte/uint8_t 等）
         * @param Count 元素数
         * @return 缓冲（>栈缓冲大小自动回退 LocalPool，避免耗尽竞技场）
         * @note 对齐主项目 pool 的 largest_required_pool_block=16KB：
         *       vmess/ss2022 加密缓冲（16KB+）走池，帧/地址（<8KB）走竞技场
         */
        template <typename Type>
        [[nodiscard]] auto MakeBuffer(const std::size_t Count)
            -> std::pmr::vector<Type>
        {
            const bool FitsArena = sizeof(Type) != 0 && Count <= ArenaSize / sizeof(Type);
            auto *Resource = FitsArena ? Arena_.Get() : System::LocalPool();
            std::pmr::vector<Type> buf(Resource);
            buf.resize(Count);
            return buf;
        }

    private:
        FrameArena<ArenaSize> Arena_; ///< 帧竞技场（会话持有）
    };

    /**
     * @brief 便捷别名：会话内存共享指针（默认 8KB 栈缓冲）
     */
    using SharedSessionResource = std::shared_ptr<SessionResource<>>;

} // namespace Preview::Memory
