/**
 * @file CoreError.cpp
 * @brief tests/common/Core/Error.hpp 单元测试
 * @details 覆盖 std::Error 协议错误码体系：
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
        const auto &cat = std::ErrorCategory();
        EXPECT_EQ(&cat, &std::ErrorCategory());
        EXPECT_EQ(std::string_view(cat.name()), "preview.protocol");
    }

    TEST(CoreError, Messages)
    {
        // 遍历全部枚举值，逐个验证 Message() 精确描述（覆盖全部 case 分支）
        struct expected
        {
            std::Error Code;
            const char *text;
        };
        const expected Table[] = {
            {std::Error::none, "no Error"},
            {std::Error::need_more, "need more Data"},
            {std::Error::unexpected_eof, "unexpected end of Stream"},
            {std::Error::bad_length, "bad Message length"},
            {std::Error::bad_magic, "bad magic or version"},
            {std::Error::bad_auth, "authentication Failed"},
            {std::Error::auth_failed, "authentication Failed"},
            {std::Error::version_mismatch, "version mismatch"},
            {std::Error::not_supported, "not supported"},
            {std::Error::bad_message, "malformed Message"},
            {std::Error::bad_address, "invalid Target Address"},
            {std::Error::not_open, "Stream not Open"},
            {std::Error::canceled, "operation canceled"},
            {std::Error::timeout, "operation timed out"},
            {std::Error::broken_pipe, "broken pipe"},
            {std::Error::protocol_error, "Protocol State Error"},
            {std::Error::kdf_error, "key derivation Failed"},
            {std::Error::unsupported, "unsupported feature"},
            {std::Error::io_error, "io Error"},
        };
        for (const auto &[Code, text] : Table)
        {
            EXPECT_EQ(std::ErrorCategory().message(static_cast<int>(Code)), text)
                << "Message(" << static_cast<int>(Code) << ") mismatch";
        }
    }

    TEST(CoreError, UnknownMessage)
    {
        // default 分支：正数/负数越界均返回 "unknown Protocol Error"
        EXPECT_EQ(std::ErrorCategory().message(1000), "unknown Protocol Error");
        EXPECT_EQ(std::ErrorCategory().message(-1), "unknown Protocol Error");
    }

    TEST(CoreError, make_error_code)
    {
        // 显式构造：value 与 Category 精确匹配
        const boost::system::error_code ec = std::make_error_code(std::Error::need_more);
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::need_more));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview.protocol");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";

        // 零值错误码判为成功
        const boost::system::error_code Ok = std::make_error_code(std::Error::none);
        EXPECT_FALSE(Ok);
        EXPECT_EQ(Ok.value(), 0);
    }

    TEST(CoreError, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 IsErrorCodeEnum 均为 true
        static_assert(std::is_error_code_enum<std::Error>::value);
        static_assert(boost::system::is_error_code_enum<std::Error>::value);

        // std::error_code 隐式转换（经 make_error_code → boost → std 转换链）
        const std::error_code ec = std::Error::bad_length;
        EXPECT_EQ(ec.value(), static_cast<int>(std::Error::bad_length));
        EXPECT_EQ(ec.message(), "bad Message length");

        // boost::system::error_code 隐式转换（boost 特化直接生效）
        const boost::system::error_code bec = std::Error::timeout;
        EXPECT_EQ(bec.value(), static_cast<int>(std::Error::timeout));
        EXPECT_EQ(bec.message(), "operation timed out");
    }
} // namespace
