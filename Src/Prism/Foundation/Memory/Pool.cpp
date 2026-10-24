/**
 * @file Pool.cpp
 * @brief 进程级与线程级 PMR pool 初始化和资源选择入口。
 */
#include <Prism/Foundation/Memory/Pool.hpp>

namespace Prism::Memory
{
    auto System::GlobalPool() -> SynchronizedPool*
    {
        static auto* Pool = []()
        {
            std::pmr::pool_options Options;
            Options.largest_required_pool_block = Policy::MaxSize;
            Options.max_blocks_per_chunk = Policy::MaxBlocks;

            // new 出来的资源随进程销毁，避免静态析构顺序问题
            return new SynchronizedPool(Options, std::pmr::new_delete_resource());
        }();
        return Pool;
    }

    auto System::LocalPool() -> UnsynchronizedPool*
    {
        // thread_local 保证每个线程一份
        thread_local auto* Pool = []()
        {
            std::pmr::pool_options Options;
            Options.largest_required_pool_block = Policy::MaxSize;
            Options.max_blocks_per_chunk = Policy::MaxBlocks;

            return new UnsynchronizedPool(Options, std::pmr::new_delete_resource());
        }();
        return Pool;
    }

    auto System::HotPool() -> UnsynchronizedPool*
    {
        return LocalPool();
    }

    auto System::EnablePooling() -> void
    {
        std::pmr::set_default_resource(GlobalPool());
    }
}
