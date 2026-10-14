/**
 * @file PreviewErrorTest.cpp
 * @brief make_error_code 编解码错误体系测试（core/Error.hpp）
 * @details 覆盖 Preview::Error 枚举与 Boost.System 集成：
 * 1. ErrorCategory 分类器（Name/Message）
 * 2. make_error_code 构造
 * 3. std::error_code / boost::system::error_code 双向兼容
 * 4. ProtocolEc 别名
 */

#include <gtest/gtest.h>

#include <string>
#include <system_error>

#include <boost/system/error_code.hpp>

#include <Preview/Foundation/Error.hpp>

namespace
{

    TEST(PreviewError, CategoryName)
    {
        EXPECT_STREQ(Preview::ErrorCategory().name(), "prism.protocol");
    }

    TEST(PreviewError, MakeErrorCode)
    {
        const auto ErrorCode = Preview::make_error_code(Preview::Error::BadLength);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Preview::Error::BadLength));
        EXPECT_EQ(ErrorCode.category(), Preview::ErrorCategory());
    }

    TEST(PreviewError, Message)
    {
        EXPECT_FALSE(Preview::ErrorCategory().message(static_cast<int>(Preview::Error::None)).empty());
        EXPECT_FALSE(Preview::ErrorCategory().message(static_cast<int>(Preview::Error::NeedMore)).empty());
        EXPECT_FALSE(Preview::ErrorCategory().message(static_cast<int>(Preview::Error::BadAuth)).empty());
        EXPECT_FALSE(Preview::ErrorCategory().message(static_cast<int>(Preview::Error::IoError)).empty());
        // 未知值返回兜底消息
        EXPECT_FALSE(Preview::ErrorCategory().message(9999).empty());
    }

    TEST(PreviewError, BoostConversion)
    {
        // IsErrorCodeEnum 特化支持隐式转换
        const boost::system::error_code ErrorCode = Preview::Error::Timeout;
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Preview::Error::Timeout));
        EXPECT_EQ(ErrorCode.category(), Preview::ErrorCategory());
    }

    TEST(PreviewError, StdConversion)
    {
        // std::error_code 场景（IsErrorCodeEnum 特化）
        const std::error_code ErrorCode = Preview::Error::Canceled;
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Preview::Error::Canceled));
    }

    TEST(PreviewError, ProtocolEcAlias)
    {
        Preview::ProtocolEc ProtocolErrorCode = Preview::make_error_code(Preview::Error::BrokenPipe);
        EXPECT_TRUE(ProtocolErrorCode);
        EXPECT_EQ(ProtocolErrorCode.value(), static_cast<int>(Preview::Error::BrokenPipe));
    }

    TEST(PreviewError, SuccessIsZero)
    {
        const auto ErrorCode = Preview::make_error_code(Preview::Error::None);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), 0);
    }

} // namespace
