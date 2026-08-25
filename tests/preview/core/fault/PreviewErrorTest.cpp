/**
 * @file PreviewErrorTest.cpp
 * @brief make_error_code 编解码错误体系测试（core/Error.hpp）
 * @details 覆盖 std::Error 枚举与 Boost.System 集成：
 * 1. ErrorCategory 分类器（Name/Message）
 * 2. make_error_code 构造
 * 3. std::error_code / boost::system::error_code 双向兼容
 * 4. ProtocolEc 别名
 */

#include <gtest/gtest.h>

#include <string>
#include <system_error>

#include <boost/system/error_code.hpp>

#include <common/Core/Error.hpp>

namespace
{

    TEST(PreviewError, CategoryName)
    {
        EXPECT_STREQ(std::ErrorCategory().name(), "preview.protocol");
    }

    TEST(PreviewError, make_error_code)
    {
        const auto ec = std::make_error_code(std::Error::bad_length);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::bad_length));
        EXPECT_EQ(ec.category(), std::ErrorCategory());
    }

    TEST(PreviewError, Message)
    {
        EXPECT_FALSE(std::ErrorCategory().message(static_cast<int>(std::Error::none)).empty());
        EXPECT_FALSE(std::ErrorCategory().message(static_cast<int>(std::Error::need_more)).empty());
        EXPECT_FALSE(std::ErrorCategory().message(static_cast<int>(std::Error::bad_auth)).empty());
        EXPECT_FALSE(std::ErrorCategory().message(static_cast<int>(std::Error::io_error)).empty());
        // 未知值返回兜底消息
        EXPECT_FALSE(std::ErrorCategory().message(9999).empty());
    }

    TEST(PreviewError, BoostConversion)
    {
        // IsErrorCodeEnum 特化支持隐式转换
        const boost::system::error_code ec = std::Error::timeout;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::timeout));
        EXPECT_EQ(ec.category(), std::ErrorCategory());
    }

    TEST(PreviewError, StdConversion)
    {
        // std::error_code 场景（IsErrorCodeEnum 特化）
        const std::error_code ec = std::Error::canceled;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::canceled));
    }

    TEST(PreviewError, ProtocolEcAlias)
    {
        std::ProtocolEc ec = std::make_error_code(std::Error::broken_pipe);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::broken_pipe));
    }

    TEST(PreviewError, SuccessIsZero)
    {
        const auto ec = std::make_error_code(std::Error::none);
        EXPECT_FALSE(ec);
        EXPECT_EQ(ec.value(), 0);
    }

} // namespace