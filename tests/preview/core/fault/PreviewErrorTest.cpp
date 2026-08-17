/**
 * @file PreviewErrorTest.cpp
 * @brief preview 编解码错误体系测试（core/error.hpp）
 * @details 覆盖 preview::error 枚举与 Boost.System 集成：
 * 1. error_category 分类器（name/message）
 * 2. make_error_code 构造
 * 3. std::error_code / boost::system::error_code 双向兼容
 * 4. protocol_ec 别名
 */

#include <gtest/gtest.h>

#include <string>
#include <system_error>

#include <boost/system/error_code.hpp>

#include <common/core/error.hpp>

namespace
{

    TEST(PreviewError, CategoryName)
    {
        EXPECT_STREQ(preview::error_category().name(), "preview.protocol");
    }

    TEST(PreviewError, MakeErrorCode)
    {
        const auto ec = preview::make_error_code(preview::error::bad_length);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::bad_length));
        EXPECT_EQ(ec.category(), preview::error_category());
    }

    TEST(PreviewError, Message)
    {
        EXPECT_FALSE(preview::error_category().message(static_cast<int>(preview::error::none)).empty());
        EXPECT_FALSE(preview::error_category().message(static_cast<int>(preview::error::need_more)).empty());
        EXPECT_FALSE(preview::error_category().message(static_cast<int>(preview::error::bad_auth)).empty());
        EXPECT_FALSE(preview::error_category().message(static_cast<int>(preview::error::io_error)).empty());
        // 未知值返回兜底消息
        EXPECT_FALSE(preview::error_category().message(9999).empty());
    }

    TEST(PreviewError, BoostConversion)
    {
        // is_error_code_enum 特化支持隐式转换
        const boost::system::error_code ec = preview::error::timeout;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::timeout));
        EXPECT_EQ(ec.category(), preview::error_category());
    }

    TEST(PreviewError, StdConversion)
    {
        // std::error_code 场景（is_error_code_enum 特化）
        const std::error_code ec = preview::error::canceled;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::canceled));
    }

    TEST(PreviewError, ProtocolEcAlias)
    {
        preview::protocol_ec ec = preview::make_error_code(preview::error::broken_pipe);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::broken_pipe));
    }

    TEST(PreviewError, SuccessIsZero)
    {
        const auto ec = preview::make_error_code(preview::error::none);
        EXPECT_FALSE(ec);
        EXPECT_EQ(ec.value(), 0);
    }

} // namespace