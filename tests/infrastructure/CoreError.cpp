/**
 * @file CoreError.cpp
 * @brief tests/common/core/error.hpp 单元测试
 * @details 覆盖 psmtest::error 协议错误码体系：
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
        const auto &cat = psmtest::error_category();
        EXPECT_EQ(&cat, &psmtest::error_category());
        EXPECT_EQ(std::string_view(cat.name()), "psmtest.protocol");
    }

    TEST(CoreError, Messages)
    {
        // 遍历全部枚举值，逐个验证 message() 精确描述（覆盖全部 case 分支）
        struct expected
        {
            psmtest::error code;
            const char *text;
        };
        const expected table[] = {
            {psmtest::error::none, "no error"},
            {psmtest::error::need_more, "need more data"},
            {psmtest::error::unexpected_eof, "unexpected end of stream"},
            {psmtest::error::bad_length, "bad message length"},
            {psmtest::error::bad_magic, "bad magic or version"},
            {psmtest::error::bad_auth, "authentication failed"},
            {psmtest::error::auth_failed, "authentication failed"},
            {psmtest::error::version_mismatch, "version mismatch"},
            {psmtest::error::not_supported, "not supported"},
            {psmtest::error::bad_message, "malformed message"},
            {psmtest::error::bad_address, "invalid target address"},
            {psmtest::error::not_open, "stream not open"},
            {psmtest::error::canceled, "operation canceled"},
            {psmtest::error::timeout, "operation timed out"},
            {psmtest::error::broken_pipe, "broken pipe"},
            {psmtest::error::protocol_error, "protocol state error"},
            {psmtest::error::kdf_error, "key derivation failed"},
            {psmtest::error::unsupported, "unsupported feature"},
            {psmtest::error::io_error, "io error"},
        };
        for (const auto &[code, text] : table)
        {
            EXPECT_EQ(psmtest::error_category().message(static_cast<int>(code)), text)
                << "message(" << static_cast<int>(code) << ") mismatch";
        }
    }

    TEST(CoreError, UnknownMessage)
    {
        // default 分支：正数/负数越界均返回 "unknown protocol error"
        EXPECT_EQ(psmtest::error_category().message(1000), "unknown protocol error");
        EXPECT_EQ(psmtest::error_category().message(-1), "unknown protocol error");
    }

    TEST(CoreError, MakeErrorCode)
    {
        // 显式构造：value 与 category 精确匹配
        const boost::system::error_code ec = psmtest::make_error_code(psmtest::error::need_more);
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::error::need_more));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest.protocol");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";

        // 零值错误码判为成功
        const boost::system::error_code ok = psmtest::make_error_code(psmtest::error::none);
        EXPECT_FALSE(ok);
        EXPECT_EQ(ok.value(), 0);
    }

    TEST(CoreError, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 is_error_code_enum 均为 true
        static_assert(std::is_error_code_enum<psmtest::error>::value);
        static_assert(boost::system::is_error_code_enum<psmtest::error>::value);

        // std::error_code 隐式转换（经 make_error_code → boost → std 转换链）
        const std::error_code ec = psmtest::error::bad_length;
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::error::bad_length));
        EXPECT_EQ(ec.message(), "bad message length");

        // boost::system::error_code 隐式转换（boost 特化直接生效）
        const boost::system::error_code bec = psmtest::error::timeout;
        EXPECT_EQ(bec.value(), static_cast<int>(psmtest::error::timeout));
        EXPECT_EQ(bec.message(), "operation timed out");
    }
} // namespace
