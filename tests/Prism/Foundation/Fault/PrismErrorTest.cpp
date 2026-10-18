/**
 * @file PrismErrorTest.cpp
 * @brief make_error_code 编解码错误体系测试（core/Error.hpp）
 * @details 覆盖 Prism::Error 枚举与 Boost.System 集成：
 * 1. ErrorCategory 分类器（Name/Message）
 * 2. make_error_code 构造
 * 3. std::error_code / boost::system::error_code 双向兼容
 * 4. ProtocolEc 别名
 */

#include <gtest/gtest.h>

#include <string>
#include <system_error>

#include <boost/system/error_code.hpp>

#include <Prism/Foundation/Error.hpp>

namespace
{

    TEST(PrismError, CategoryName)
    {
        EXPECT_STREQ(Prism::ErrorCategory().name(), "prism.protocol");
    }

    TEST(PrismError, MakeErrorCode)
    {
        const auto ErrorCode = Prism::make_error_code(Prism::Error::BadLength);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Error::BadLength));
        EXPECT_EQ(ErrorCode.category(), Prism::ErrorCategory());
    }

    TEST(PrismError, Message)
    {
        EXPECT_FALSE(Prism::ErrorCategory().message(static_cast<int>(Prism::Error::None)).empty());
        EXPECT_FALSE(Prism::ErrorCategory().message(static_cast<int>(Prism::Error::NeedMore)).empty());
        EXPECT_FALSE(Prism::ErrorCategory().message(static_cast<int>(Prism::Error::BadAuth)).empty());
        EXPECT_FALSE(Prism::ErrorCategory().message(static_cast<int>(Prism::Error::IoError)).empty());
        // 未知值返回兜底消息
        EXPECT_FALSE(Prism::ErrorCategory().message(9999).empty());
    }

    TEST(PrismError, BoostConversion)
    {
        // IsErrorCodeEnum 特化支持隐式转换
        const boost::system::error_code ErrorCode = Prism::Error::Timeout;
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Error::Timeout));
        EXPECT_EQ(ErrorCode.category(), Prism::ErrorCategory());
    }

    TEST(PrismError, StdConversion)
    {
        // std::error_code 场景（IsErrorCodeEnum 特化）
        const std::error_code ErrorCode = Prism::Error::Canceled;
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Error::Canceled));
    }

    TEST(PrismError, ProtocolEcAlias)
    {
        Prism::ProtocolEc ProtocolErrorCode = Prism::make_error_code(Prism::Error::BrokenPipe);
        EXPECT_TRUE(ProtocolErrorCode);
        EXPECT_EQ(ProtocolErrorCode.value(), static_cast<int>(Prism::Error::BrokenPipe));
    }

    TEST(PrismError, SuccessIsZero)
    {
        const auto ErrorCode = Prism::make_error_code(Prism::Error::None);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), 0);
    }

} // namespace
