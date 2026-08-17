/**
 * @file CoreError.cpp
 * @brief tests/common/core/error.hpp 单元测试
 * @details 覆盖 preview::error 协议错误码体系：
 * 1. error_category() 分类器单例与 name()
 * 2. message() 全部 19 个枚举 case 分支 + default 分支
 * 3. make_error_code() 显式构造
 * 4. std / boost 双路 is_error_code_enum 特化与隐式转换
 */

#include <common/core/error.hpp>

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
        const auto &cat = preview::error_category();
        EXPECT_EQ(&cat, &preview::error_category());
        EXPECT_EQ(std::string_view(cat.name()), "preview.protocol");
    }

    TEST(CoreError, Messages)
    {
        // 遍历全部枚举值，逐个验证 message() 精确描述（覆盖全部 case 分支）
        struct expected
        {
            preview::error code;
            const char *text;
        };
        const expected table[] = {
            {preview::error::none, "no error"},
            {preview::error::need_more, "need more data"},
            {preview::error::unexpected_eof, "unexpected end of stream"},
            {preview::error::bad_length, "bad message length"},
            {preview::error::bad_magic, "bad magic or version"},
            {preview::error::bad_auth, "authentication failed"},
            {preview::error::auth_failed, "authentication failed"},
            {preview::error::version_mismatch, "version mismatch"},
            {preview::error::not_supported, "not supported"},
            {preview::error::bad_message, "malformed message"},
            {preview::error::bad_address, "invalid target address"},
            {preview::error::not_open, "stream not open"},
            {preview::error::canceled, "operation canceled"},
            {preview::error::timeout, "operation timed out"},
            {preview::error::broken_pipe, "broken pipe"},
            {preview::error::protocol_error, "protocol state error"},
            {preview::error::kdf_error, "key derivation failed"},
            {preview::error::unsupported, "unsupported feature"},
            {preview::error::io_error, "io error"},
        };
        for (const auto &[code, text] : table)
        {
            EXPECT_EQ(preview::error_category().message(static_cast<int>(code)), text)
                << "message(" << static_cast<int>(code) << ") mismatch";
        }
    }

    TEST(CoreError, UnknownMessage)
    {
        // default 分支：正数/负数越界均返回 "unknown protocol error"
        EXPECT_EQ(preview::error_category().message(1000), "unknown protocol error");
        EXPECT_EQ(preview::error_category().message(-1), "unknown protocol error");
    }

    TEST(CoreError, MakeErrorCode)
    {
        // 显式构造：value 与 category 精确匹配
        const boost::system::error_code ec = preview::make_error_code(preview::error::need_more);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::need_more));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview.protocol");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";

        // 零值错误码判为成功
        const boost::system::error_code ok = preview::make_error_code(preview::error::none);
        EXPECT_FALSE(ok);
        EXPECT_EQ(ok.value(), 0);
    }

    TEST(CoreError, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 is_error_code_enum 均为 true
        static_assert(std::is_error_code_enum<preview::error>::value);
        static_assert(boost::system::is_error_code_enum<preview::error>::value);

        // std::error_code 隐式转换（经 make_error_code → boost → std 转换链）
        const std::error_code ec = preview::error::bad_length;
        EXPECT_EQ(ec.value(), static_cast<int>(preview::error::bad_length));
        EXPECT_EQ(ec.message(), "bad message length");

        // boost::system::error_code 隐式转换（boost 特化直接生效）
        const boost::system::error_code bec = preview::error::timeout;
        EXPECT_EQ(bec.value(), static_cast<int>(preview::error::timeout));
        EXPECT_EQ(bec.message(), "operation timed out");
    }
} // namespace
