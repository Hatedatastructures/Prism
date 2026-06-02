/**
 * @file fixtures.hpp
 * @brief Google Test fixture 基类 — PrismTest（通用）/ AsyncTest（协程）
 */

#pragma once

#include <gtest/gtest.h>
#include <boost/asio.hpp>

namespace psm::testing
{

    /// @brief 通用测试 fixture（当前为空壳，预留扩展点）
    class PrismTest : public ::testing::Test
    {
    };

    /// @brief 协程测试 fixture — 提供独立 io_context
    class AsyncTest : public ::testing::Test
    {
    protected:
        boost::asio::io_context ioc;
    };

} // namespace psm::testing
