/**
 * @file Fault.cpp
 * @brief 错误码系统单元测试
 * @details 验证 psm::fault 模块的核心功能，包括：
 * 1. 所有错误码描述字符串的非空性
 * 2. succeeded/failed 语义正确性
 * 3. cached_message 与 describe 一致性
 * 4. std::error_code 构造与隐式转换
 * 5. boost::system::error_code 构造
 * 6. boost 错误码双向转换 (to_code)
 * 7. std 错误码双向转换 (to_code)
 */

#include <prism/core/fault/code.hpp>
#include <prism/core/fault/compatible.hpp>
#include <prism/core/fault/handling.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <system_error>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

namespace
{
    TEST(FaultTest, DescribeAllCodes)
    {
        // 遍历全部错误码，确保每个都有非空描述
        constexpr int count = static_cast<int>(psm::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<psm::fault::code>(i);
            const std::string_view desc = psm::fault::describe(c);
            ASSERT_FALSE(desc.empty())
                << "describe(code=" << i << ") returned empty string";
        }

        // success 码：代表操作成功的唯一正例
        EXPECT_TRUE(psm::fault::describe(psm::fault::code::success) == "success")
            << "describe(success) != 'success'";

        // eof 码：代表连接正常关闭（对端 EOF）
        EXPECT_TRUE(psm::fault::describe(psm::fault::code::eof) == "eof")
            << "describe(eof) != 'eof'";

        // timeout 码：代表异步操作超时
        EXPECT_TRUE(psm::fault::describe(psm::fault::code::timeout) == "timeout")
            << "describe(timeout) != 'timeout'";
    }

    TEST(FaultTest, SucceededFailed)
    {
        // success 是唯一使 succeeded 返回 true 的码
        EXPECT_TRUE(psm::fault::succeeded(psm::fault::code::success))
            << "succeeded(success) should be true";
        // success 不应被视为失败
        EXPECT_FALSE(psm::fault::failed(psm::fault::code::success))
            << "failed(success) should be false";

        // eof 属于失败码，表示非正常结束
        EXPECT_FALSE(psm::fault::succeeded(psm::fault::code::eof))
            << "succeeded(eof) should be false";
        EXPECT_TRUE(psm::fault::failed(psm::fault::code::eof))
            << "failed(eof) should be true";

        // parse_error 属于失败码，表示协议解析出错
        EXPECT_FALSE(psm::fault::succeeded(psm::fault::code::parse_error))
            << "succeeded(parse_error) should be false";
        EXPECT_TRUE(psm::fault::failed(psm::fault::code::parse_error))
            << "failed(parse_error) should be true";
    }

    TEST(FaultTest, CachedMessageConsistency)
    {
        // 确保缓存版本与实时描述完全一致
        constexpr int count = static_cast<int>(psm::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<psm::fault::code>(i);
            const std::string_view desc = psm::fault::describe(c);
            const std::string &cached = psm::fault::cached_message(c);

            EXPECT_TRUE(desc == cached)
                << "cached_message(code=" << i << ")='" << cached << "' != describe()='" << desc << "'";
        }
    }

    TEST(FaultTest, MakeErrorCodeStd)
    {
        // 显式构造：eof 的数值应为 3，类别名为 psm::fault
        const std::error_code ec = psm::fault::make_error_code(psm::fault::code::eof);
        EXPECT_TRUE(ec.value() == 3)
            << "make_error_code(eof).value()=" << ec.value() << ", expected 3";
        EXPECT_TRUE(std::string_view(ec.category().name()) == "psm::fault")
            << "category name='" << ec.category().name() << "', expected 'psm::fault'";

        // 隐式转换：code 枚举应能直接赋值给 std::error_code
        const std::error_code ec2 = psm::fault::code::timeout;
        EXPECT_TRUE(ec2.value() == 11)
            << "implicit conversion: timeout value=" << ec2.value() << ", expected 11";
    }

    TEST(FaultTest, MakeErrorCodeBoost)
    {
        // 验证 Boost 错误码的数值和类别与 std 版本一致
        const boost::system::error_code ec = boost::system::make_error_code(psm::fault::code::eof);
        EXPECT_TRUE(ec.value() == 3)
            << "boost make_error_code(eof).value()=" << ec.value() << ", expected 3";
        EXPECT_TRUE(std::string_view(ec.category().name()) == "psm::fault")
            << "boost category name='" << ec.category().name() << "', expected 'psm::fault'";
    }

    TEST(FaultTest, ToCodeBoostRoundTrip)
    {
        // 正向+反向转换：code -> boost ec -> 还原为 code
        const psm::fault::code c = psm::fault::code::timeout;
        const boost::system::error_code ec = boost::system::make_error_code(c);
        const psm::fault::code back = psm::fault::to_code(ec);
        EXPECT_TRUE(back == psm::fault::code::timeout)
            << "boost round trip: expected timeout, got " << static_cast<int>(back);

        // 将 asio::eof 映射为 fault::eof，统一 EOF 语义
        const psm::fault::code eof_code = psm::fault::to_code(boost::asio::error::eof);
        EXPECT_TRUE(eof_code == psm::fault::code::eof)
            << "asio::eof -> code=" << static_cast<int>(eof_code)
            << ", expected eof(" << static_cast<int>(psm::fault::code::eof) << ")";

        // 将 asio::operation_aborted 映射为 fault::canceled
        const psm::fault::code abort_code = psm::fault::to_code(boost::asio::error::operation_aborted);
        EXPECT_TRUE(abort_code == psm::fault::code::canceled)
            << "asio::operation_aborted -> code=" << static_cast<int>(abort_code)
            << ", expected canceled(" << static_cast<int>(psm::fault::code::canceled) << ")";
    }

    TEST(FaultTest, ToCodeStdRoundTrip)
    {
        // 正向+反向转换：code -> std ec -> 还原为 code
        const psm::fault::code c = psm::fault::code::connection_refused;
        const std::error_code ec = psm::fault::make_error_code(c);
        const psm::fault::code back = psm::fault::to_code(ec);
        EXPECT_TRUE(back == psm::fault::code::connection_refused)
            << "std round trip: expected connection_refused, got " << static_cast<int>(back);

        // 将 std 超时错误映射为 fault::timeout
        const psm::fault::code timeout_code = psm::fault::to_code(std::make_error_code(std::errc::timed_out));
        EXPECT_TRUE(timeout_code == psm::fault::code::timeout)
            << "errc::timed_out -> code=" << static_cast<int>(timeout_code)
            << ", expected timeout(" << static_cast<int>(psm::fault::code::timeout) << ")";

        // 将 std 取消错误映射为 fault::canceled
        const psm::fault::code cancel_code = psm::fault::to_code(std::make_error_code(std::errc::operation_canceled));
        EXPECT_TRUE(cancel_code == psm::fault::code::canceled)
            << "errc::operation_canceled -> code=" << static_cast<int>(cancel_code)
            << ", expected canceled(" << static_cast<int>(psm::fault::code::canceled) << ")";
    }
} // namespace
