/**
 * @file gtest_main.cpp
 * @brief Google Test 全局入口 — 初始化 PMR 内存池 + spdlog 日志
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

int main(int argc, char **argv)
{
    psm::memory::system::enable_pooling();
    psm::trace::init({});
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
