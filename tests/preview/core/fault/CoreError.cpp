/**
 * @file CoreError.cpp
 * @brief tests/common/Core/Error.hpp 单元测试
 * @details 覆盖 Preview::Error 协议错误码体系：
 * 1. ErrorCategory() 分类器单例与 Name()
 * 2. Message() 全部 19 个枚举 case 分支 + default 分支
 * 3. make_error_code() 显式构造
 * 4. std / boost 双路 IsErrorCodeEnum 特化与隐式转换
 */

#include <common/Core/Error.hpp>

#include <boost/system/error_code.hpp>

#include <string>
#include <string_view>
#include <type_traits>

#include <gtest/gtest.h>

namespace
{
    TEST(CoreError, CategoryName)
    {
        // 分类器单例：多次调用返回同一实例
        const auto &cat = Preview::ErrorCategory();
        EXPECT_EQ(&cat, &Preview::ErrorCategory());
        EXPECT_EQ(std::string_view(cat.name()), "preview.protocol");
    }

    TEST(CoreError, Messages)
    {
        // 遍历全部枚举值，逐个验证 Message() 精确描述（覆盖全部 case 分支）
        struct expected
        {
            Preview::Error Code;
            const char *text;
        };
        const expected Table[] = {
            {Preview::Error::None, "no Error"},
            {Preview::Error::NeedMore, "need more Data"},
            {Preview::Error::UnexpectedEof, "unexpected end of Stream"},
            {Preview::Error::BadLength, "bad Message length"},
            {Preview::Error::BadMagic, "bad magic or version"},
            {Preview::Error::BadAuth, "authentication Failed"},
            {Preview::Error::AuthFailed, "authentication Failed"},
            {Preview::Error::VersionMismatch, "version mismatch"},
            {Preview::Error::NotSupported, "not supported"},
            {Preview::Error::BadMessage, "malformed Message"},
            {Preview::Error::BadAddress, "invalid Target Address"},
            {Preview::Error::NotOpen, "Stream not Open"},
            {Preview::Error::Canceled, "operation canceled"},
            {Preview::Error::Timeout, "operation timed out"},
            {Preview::Error::BrokenPipe, "broken pipe"},
            {Preview::Error::ProtocolError, "Protocol State Error"},
            {Preview::Error::KdfError, "key derivation Failed"},
            {Preview::Error::Unsupported, "unsupported feature"},
            {Preview::Error::IoError, "io Error"},
        };
        for (const auto &[Code, text] : Table)
        {
            EXPECT_EQ(Preview::ErrorCategory().message(static_cast<int>(Code)), text)
                << "Message(" << static_cast<int>(Code) << ") mismatch";
        }
    }

    TEST(CoreError, UnknownMessage)
    {
        // default 分支：正数/负数越界均返回 "unknown Protocol Error"
        EXPECT_EQ(Preview::ErrorCategory().message(1000), "unknown Protocol Error");
        EXPECT_EQ(Preview::ErrorCategory().message(-1), "unknown Protocol Error");
    }

    TEST(CoreError, make_error_code)
    {
        // 显式构造：value 与 Category 精确匹配
        const boost::system::error_code ec = Preview::make_error_code(Preview::Error::NeedMore);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Error::NeedMore));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview.protocol");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";

        // 零值错误码判为成功
        const boost::system::error_code Ok = Preview::make_error_code(Preview::Error::None);
        EXPECT_FALSE(Ok);
        EXPECT_EQ(Ok.value(), 0);
    }

    TEST(CoreError, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 IsErrorCodeEnum 均为 true
        static_assert(std::is_error_code_enum<Preview::Error>::value);
        static_assert(boost::system::is_error_code_enum<Preview::Error>::value);

        // std::error_code 隐式转换（经 make_error_code → boost → std 转换链）
        const std::error_code ec = Preview::Error::BadLength;
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Error::BadLength));
        EXPECT_EQ(ec.message(), "bad Message length");

        // boost::system::error_code 隐式转换（boost 特化直接生效）
        const boost::system::error_code bec = Preview::Error::Timeout;
        EXPECT_EQ(bec.value(), static_cast<int>(Preview::Error::Timeout));
        EXPECT_EQ(bec.message(), "operation timed out");
    }
} // namespace
