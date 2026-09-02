/**
 * @file PreviewGtestMain.cpp
 * @brief 不依赖生产 psm 的 Preview GoogleTest 入口
 */

#include <gtest/gtest.h>

auto main(int argc, char **argv) -> int
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
