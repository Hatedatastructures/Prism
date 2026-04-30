/**
 * @file MemoryArena.cpp
 * @brief 帧分配器 (frame_arena) 单元测试
 * @details 验证 psm::memory::frame_arena 的核心功能，包括：
 * 1. 构造与资源指针有效性
 * 2. 分配、重置、再分配生命周期
 * 3. 内部栈缓冲区 (512 字节) 小分配行为
 * 4. 连续多次 reset() 调用的正确性
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <cstddef>
#include <cstring>
#include <format>
#include <string_view>

namespace
{
    psm::testing::TestRunner runner("MemoryArena");
}

/**
 * @brief 测试 frame_arena 构造与 get() 返回值
 */
void TestArenaConstruction()
{
    runner.LogInfo("=== Testing frame_arena construction ===");

    psm::memory::frame_arena arena;

    // get() 必须返回非空资源指针
    runner.Check(arena.get() != nullptr, "arena.get() returns non-null resource pointer");

    // 验证资源指针可创建 PMR 容器
    psm::memory::string str(arena.get());
    str = "hello arena";
    runner.Check(str == "hello arena", "pmr::string constructed with arena resource works");

    psm::memory::vector<int> vec(arena.get());
    vec.push_back(42);
    vec.push_back(17);
    runner.Check(vec.size() == 2 && vec[0] == 42 && vec[1] == 17,
                 "pmr::vector<int> constructed with arena resource works");

    runner.LogPass("frame_arena construction");
}

/**
 * @brief 测试 frame_arena 分配、reset、再分配
 */
void TestArenaReset()
{
    runner.LogInfo("=== Testing frame_arena reset ===");

    psm::memory::frame_arena arena;
    psm::memory::resource_pointer res = arena.get();

    // 第一次分配
    auto *buf1 = res->allocate(64, alignof(std::max_align_t));
    runner.Check(buf1 != nullptr, "first allocate returns non-null pointer");
    std::memcpy(buf1, "first allocation data", 22);

    // 重置分配器
    arena.reset();

    // 重置后重新分配，应正常工作
    psm::memory::resource_pointer res2 = arena.get();
    runner.Check(res2 != nullptr, "arena.get() still valid after reset");

    auto *buf2 = res2->allocate(128, alignof(std::max_align_t));
    runner.Check(buf2 != nullptr, "allocate after reset returns non-null pointer");
    const char *msg = "after reset";
    const std::size_t msg_len = std::strlen(msg);
    std::memcpy(buf2, msg, msg_len);

    // 验证新分配的数据可正确写入和读取
    char check_buf[128];
    std::memcpy(check_buf, buf2, msg_len);
    runner.Check(std::string_view(check_buf, msg_len) == "after reset",
                 "data written after reset is readable and correct");

    runner.LogPass("frame_arena reset and reallocate");
}

/**
 * @brief 测试小分配使用内部栈缓冲区 (512 字节)
 */
void TestArenaStackBuffer()
{
    runner.LogInfo("=== Testing arena stack buffer (512 bytes) ===");

    psm::memory::frame_arena arena;
    psm::memory::resource_pointer res = arena.get();

    // 分配一个 100 字节的小块，应在内部栈缓冲区内
    auto *small1 = res->allocate(100, alignof(std::max_align_t));
    runner.Check(small1 != nullptr, "small allocate (100 bytes) succeeds");

    // 再分配 200 字节，累计 300 字节，仍在 512 字节栈缓冲区内
    auto *small2 = res->allocate(200, alignof(std::max_align_t));
    runner.Check(small2 != nullptr, "second small allocate (200 bytes) succeeds");

    // 两个分配地址不同
    runner.Check(small1 != small2, "two allocations return different addresses");

    // 分配 100 字节并写入数据，验证可用性
    std::memset(small1, 0xAB, 100);
    auto *ptr = static_cast<unsigned char *>(small1);
    bool pattern_ok = true;
    for (int i = 0; i < 100; ++i)
    {
        if (ptr[i] != 0xAB)
        {
            pattern_ok = false;
            break;
        }
    }
    runner.Check(pattern_ok, "stack buffer allocation is writable and readable");

    // 使用 pmr::string 验证小字符串在栈缓冲区内分配
    psm::memory::string str(res);
    str.reserve(64);
    str = "stack buffer test string for arena";
    runner.Check(str.size() == 34, "pmr::string small allocation in stack buffer works");

    runner.LogPass("arena stack buffer small allocations");
}

/**
 * @brief 测试连续多次 reset() 调用
 */
void TestArenaMultipleReset()
{
    runner.LogInfo("=== Testing multiple consecutive resets ===");

    psm::memory::frame_arena arena;

    // 连续 5 次 reset + allocate 循环
    constexpr int iterations = 5;
    bool all_ok = true;

    for (int i = 0; i < iterations; ++i)
    {
        arena.reset();
        psm::memory::resource_pointer res = arena.get();
        if (res == nullptr)
        {
            runner.LogFail(std::format("reset #{}: arena.get() returned nullptr", i + 1));
            all_ok = false;
            break;
        }

        auto *buf = res->allocate(32, alignof(std::max_align_t));
        if (buf == nullptr)
        {
            runner.LogFail(std::format("reset #{}: allocate returned nullptr", i + 1));
            all_ok = false;
            break;
        }

        std::memset(buf, i, 32);
        auto *p = static_cast<unsigned char *>(buf);
        for (int j = 0; j < 32; ++j)
        {
            if (p[j] != static_cast<unsigned char>(i))
            {
                runner.LogFail(std::format("reset #{}: memory pattern mismatch at byte {}", i + 1, j));
                all_ok = false;
                break;
            }
        }
        if (!all_ok)
        {
            break;
        }
    }

    runner.Check(all_ok, "5 consecutive reset+allocate cycles all succeed with correct data");

    // 额外测试：空 arena 上连续 reset 不会崩溃
    psm::memory::frame_arena arena2;
    for (int i = 0; i < 10; ++i)
    {
        arena2.reset();
    }
    runner.Check(arena2.get() != nullptr, "10 consecutive resets on empty arena do not crash");

    runner.LogPass("multiple consecutive resets");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行构造、重置、
 * 栈缓冲区、多次重置等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting MemoryArena tests...");

    TestArenaConstruction();
    TestArenaReset();
    TestArenaStackBuffer();
    TestArenaMultipleReset();

    runner.LogInfo("MemoryArena tests completed.");

    return runner.Summary();
}
