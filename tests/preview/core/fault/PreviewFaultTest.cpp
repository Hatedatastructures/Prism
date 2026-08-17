/**
 * @file PreviewFaultTest.cpp
 * @brief preview 流程错误码体系测试（core/fault）
 * @details 覆盖 fault::code 枚举与标准库兼容：
 * 1. describe/cached_message 错误描述
 * 2. fault_category 分类器
 * 3. fault::code 与 std/boost error_code 双向转换
 * 4. succeeded/failed 统一检查
 * 5. hash 特化
 */

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>

#include <boost/system/error_code.hpp>

#include <common/core/fault/code.hpp>
#include <common/core/fault/compatible.hpp>
#include <common/core/fault/handling.hpp>

namespace
{

    TEST(PreviewFault, Describe)
    {
        EXPECT_FALSE(preview::fault::describe(preview::fault::code::success).empty());
        EXPECT_FALSE(preview::fault::describe(preview::fault::code::bad_message).empty());
        EXPECT_FALSE(preview::fault::describe(preview::fault::code::timeout).empty());
    }

    TEST(PreviewFault, CachedMessage)
    {
        EXPECT_FALSE(preview::fault::cached_message(preview::fault::code::io_error).empty());
        // 缓存引用稳定
        const auto &a = preview::fault::cached_message(preview::fault::code::io_error);
        const auto &b = preview::fault::cached_message(preview::fault::code::io_error);
        EXPECT_EQ(&a, &b);
    }

    TEST(PreviewFault, Category)
    {
        EXPECT_STREQ(preview::fault::category().name(), "preview::fault");
        EXPECT_FALSE(preview::fault::category().message(static_cast<int>(preview::fault::code::generic_error)).empty());
    }

    TEST(PreviewFault, StdConversion)
    {
        const std::error_code ec = preview::fault::code::bad_message;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::bad_message));
        EXPECT_EQ(ec.category(), preview::fault::category());
    }

    TEST(PreviewFault, BoostConversion)
    {
        const boost::system::error_code ec = boost::system::make_error_code(preview::fault::code::timeout);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::timeout));
    }

    TEST(PreviewFault, SucceededFailed)
    {
        EXPECT_TRUE(preview::fault::succeeded(preview::fault::code::success));
        EXPECT_FALSE(preview::fault::failed(preview::fault::code::success));

        EXPECT_TRUE(preview::fault::failed(preview::fault::code::io_error));
        EXPECT_FALSE(preview::fault::succeeded(preview::fault::code::io_error));

        // std::error_code 分支
        const std::error_code ok;
        EXPECT_TRUE(preview::fault::succeeded(ok));
        EXPECT_FALSE(preview::fault::failed(ok));

        const std::error_code err = preview::fault::code::canceled;
        EXPECT_TRUE(preview::fault::failed(err));

        // boost::system::error_code 分支
        const boost::system::error_code bok;
        EXPECT_TRUE(preview::fault::succeeded(bok));
        const boost::system::error_code berr = boost::system::make_error_code(preview::fault::code::auth_failed);
        EXPECT_TRUE(preview::fault::failed(berr));
    }

    TEST(PreviewFault, Hash)
    {
        std::unordered_set<preview::fault::code> set;
        set.insert(preview::fault::code::success);
        set.insert(preview::fault::code::io_error);
        EXPECT_EQ(set.size(), 2U);
        EXPECT_NE(set.find(preview::fault::code::io_error), set.end());
    }

} // namespace