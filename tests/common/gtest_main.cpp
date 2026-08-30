/**
 * @file gtest_main.cpp
 * @brief Google Test 全局入口 — 初始化 PMR 内存池 + spdlog 日志
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>

#include <gtest/gtest.h>

int main(int argc, char **argv)
{
    psm::memory::system::enable_pooling();
    psm::diagnose::config test_trace{};
    test_trace.enable_file = false;
    psm::diagnose::init(test_trace);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
