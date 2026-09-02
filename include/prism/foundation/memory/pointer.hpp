/**
 * @file pointer.hpp
 * @brief 帧分配器资源指针
 * @details 提供固定 512B 栈缓冲和线程局部池上游的线性分配器。
 *          该类型不拥有跨会话资源，调用方必须在 arena 存活期间使用
 *          get() 返回的资源指针。
 */
#pragma once

#include <prism/foundation/memory/pool.hpp>

#include <cstddef>

namespace psm::memory
{

    /**
     * @class frame_arena
     * @brief 帧分配器或线性分配器
     * @details 使用栈上缓冲区和单调增长资源，适用于短生命周期、高频分配。
     */
    class frame_arena
    {
    public:
        /**
         * @brief 构造帧分配器
         */
        explicit frame_arena() : resource_(buffer_, sizeof(buffer_), system::local_pool())
        {
        }

        /**
         * @brief 获取内存资源指针
         * @return 内存资源指针
         */
        [[nodiscard]] auto get() -> resource_pointer
        {
            return &resource_;
        }

        /**
         * @brief 重置分配器
         */
        void reset()
        {
            resource_.release();
        }

    private:
        std::byte buffer_[512];
        monotonic_buffer resource_;

        frame_arena(const frame_arena &) = delete;
        auto operator=(const frame_arena &) -> frame_arena & = delete;
    };

} // namespace psm::memory
