/**
 * @file CoreFault.cpp
 * @brief tests/Prism/Fault 模块单元测试
 * @details 覆盖 Prism::Fault 错误码体系的三层头文件：
 * 1. Code.hpp —— Describe() 全部 64 个枚举分支 + default、Succeeded/Failed
 * 2. compatible.hpp —— CachedMessage 正常/越界、std/boost 双分类器、
 *    make_error_code、std::hash 特化、隐式转换
 * 3. handling.hpp —— Succeeded/Failed 模板三类型分发、
 *    ToCode(boost) 全部映射分支、ToCode(std) 全部映射分支
 */

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <gtest/gtest.h>

namespace
{
    // ────────────────────────── Code.hpp ──────────────────────────

    TEST(CoreFault, DescribeEveryCode)
    {
        // 遍历全部枚举值，确保每个 case 分支都有非空描述
        constexpr int Count = static_cast<int>(Prism::Fault::Code::Count);
        for (int Index = 0; Index < Count; ++Index)
        {
            const auto CodeValue = static_cast<Prism::Fault::Code>(Index);
            const std::string_view Description = Prism::Fault::Describe(CodeValue);
            ASSERT_FALSE(Description.empty()) << "Describe(Code=" << Index << ") returned Empty string";
        }

        // 抽查关键错误码的精确描述
        EXPECT_EQ(Prism::Fault::Describe(Prism::Fault::Code::Success), "success");
        EXPECT_EQ(Prism::Fault::Describe(Prism::Fault::Code::Eof), "eof");
        EXPECT_EQ(Prism::Fault::Describe(Prism::Fault::Code::Timeout), "timeout");
        EXPECT_EQ(Prism::Fault::Describe(Prism::Fault::Code::CryptoError), "crypto_error");
        EXPECT_EQ(Prism::Fault::Describe(Prism::Fault::Code::Badcfg), "badcfg");

        // Describe 为 constexpr，可在编译期求值
        static_assert(Prism::Fault::Describe(Prism::Fault::Code::Timeout) == "timeout");
        static_assert(Prism::Fault::Describe(Prism::Fault::Code::Success) == "success");
    }

    TEST(CoreFault, DescribeUnknown)
    {
        // default 分支：正数越界与负数越界均返回 "unknown"
        // 注意：Describe 为 constexpr，常量参数会被编译期折叠，须用运行时变量触发
        volatile int HighValue = 9999;
        volatile int LowValue = -1;
        EXPECT_EQ(Prism::Fault::Describe(static_cast<Prism::Fault::Code>(HighValue)), "unknown");
        EXPECT_EQ(Prism::Fault::Describe(static_cast<Prism::Fault::Code>(LowValue)), "unknown");
    }

    TEST(CoreFault, SucceededFailed)
    {
        // success 是唯一使 Succeeded 返回 true 的码
        EXPECT_TRUE(Prism::Fault::Succeeded(Prism::Fault::Code::Success));
        EXPECT_FALSE(Prism::Fault::Failed(Prism::Fault::Code::Success));

        // 非 success 码：Succeeded 为 false、Failed 为 true
        EXPECT_FALSE(Prism::Fault::Succeeded(Prism::Fault::Code::Timeout));
        EXPECT_TRUE(Prism::Fault::Failed(Prism::Fault::Code::Timeout));
        EXPECT_FALSE(Prism::Fault::Succeeded(Prism::Fault::Code::CryptoError));
        EXPECT_TRUE(Prism::Fault::Failed(Prism::Fault::Code::CryptoError));
        EXPECT_FALSE(Prism::Fault::Succeeded(Prism::Fault::Code::Eof));
        EXPECT_TRUE(Prism::Fault::Failed(Prism::Fault::Code::Eof));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(CoreFault, CachedMessageValid)
    {
        // 缓存消息与 Describe 完全一致（首次调用触发静态数组构造）
        constexpr int Count = static_cast<int>(Prism::Fault::Code::Count);
        for (int Index = 0; Index < Count; ++Index)
        {
            const auto CodeValue = static_cast<Prism::Fault::Code>(Index);
            EXPECT_EQ(Prism::Fault::CachedMessage(CodeValue), Prism::Fault::Describe(CodeValue));
        }
    }

    TEST(CoreFault, CachedMessageOutOfRange)
    {
        // 越界索引（>= _count 或负数）返回 "unknown"
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Prism::Fault::Code>(Prism::Fault::Code::Count)), "unknown");
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Prism::Fault::Code>(-5)), "unknown");
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Prism::Fault::Code>(100000)), "unknown");
    }

    TEST(CoreFault, StdCategory)
    {
        const auto &ErrorCategory = Prism::Fault::Category();

        // Name() 返回分类名
        EXPECT_EQ(std::string_view(ErrorCategory.name()), "Prism::fault");

        // 单例：多次调用返回同一实例
        EXPECT_EQ(&ErrorCategory, &Prism::Fault::Category());

        // Message(int) 委托 CachedMessage：有效码返回描述、越界返回 unknown
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Prism::Fault::Code::Eof)), "eof");
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Prism::Fault::Code::Count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeStd)
    {
        const std::error_code ErrorCode = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::Eof));
        EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");
        EXPECT_TRUE(ErrorCode) << "非零错误码应判为失败";
    }

    TEST(CoreFault, ImplicitConversionStd)
    {
        // IsErrorCodeEnum 特化支持隐式转换
        const std::error_code ErrorCode = Prism::Fault::Code::Timeout;
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::Timeout));
        EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");
    }

    TEST(CoreFault, HashSpecialization)
    {
        // Hash 特化委托 std::hash<int>
        std::hash<Prism::Fault::Code> Hasher;
        const auto CodeValue = Prism::Fault::Code::Eof;
        EXPECT_EQ(Hasher(CodeValue), std::hash<int>{}(static_cast<int>(CodeValue)));
        EXPECT_EQ(Hasher(Prism::Fault::Code::Success), std::hash<int>{}(0));
    }

    TEST(CoreFault, BoostCategory)
    {
        const auto &ErrorCategory = boost::system::Category();

        EXPECT_EQ(std::string_view(ErrorCategory.name()), "Prism::fault");

        // 单例
        EXPECT_EQ(&ErrorCategory, &boost::system::Category());

        // Message(int) 委托 CachedMessage
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Prism::Fault::Code::Eof)), "eof");
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Prism::Fault::Code::Count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeBoost)
    {
        const boost::system::error_code ErrorCode = boost::system::make_error_code(Prism::Fault::Code::Eof);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::Eof));
        EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");
        EXPECT_TRUE(ErrorCode);
    }

    TEST(CoreFault, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 IsErrorCodeEnum 均为 true
        static_assert(std::is_error_code_enum<Prism::Fault::Code>::value);
        static_assert(boost::system::is_error_code_enum<Prism::Fault::Code>::value);

        // std 侧隐式转换正常
        const std::error_code ErrorCode = Prism::Fault::Code::Timeout;
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::Timeout));
        EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");

        // boost 侧经 boost::system::make_error_code 显式转换
        const boost::system::error_code BoostErrorCode = boost::system::make_error_code(Prism::Fault::Code::Timeout);
        EXPECT_EQ(BoostErrorCode.value(), static_cast<int>(Prism::Fault::Code::Timeout));
        EXPECT_EQ(std::string_view(BoostErrorCode.category().name()), "Prism::fault");
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(CoreFault, SucceededFailedTemplate)
    {
        // Fault::Code 类型分发
        EXPECT_TRUE(Prism::Fault::Succeeded(Prism::Fault::Code::Success));
        EXPECT_FALSE(Prism::Fault::Succeeded(Prism::Fault::Code::Eof));
        EXPECT_FALSE(Prism::Fault::Failed(Prism::Fault::Code::Success));
        EXPECT_TRUE(Prism::Fault::Failed(Prism::Fault::Code::Eof));

        // std::error_code 类型分发
        EXPECT_TRUE(Prism::Fault::Succeeded(std::error_code{}));
        EXPECT_FALSE(Prism::Fault::Succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(Prism::Fault::Failed(std::error_code{}));
        EXPECT_TRUE(Prism::Fault::Failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型分发
        EXPECT_TRUE(Prism::Fault::Succeeded(boost::system::error_code{}));
        EXPECT_FALSE(
            Prism::Fault::Succeeded(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
        EXPECT_FALSE(Prism::Fault::Failed(boost::system::error_code{}));
        EXPECT_TRUE(Prism::Fault::Failed(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
    }

    TEST(CoreFault, ToCodeBoostSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(Prism::Fault::ToCode(boost::system::error_code{}), Prism::Fault::Code::Success);
    }

    TEST(CoreFault, ToCodeBoostPsmCategory)
    {
        // Prism::Fault 分类：范围内值还原为原码
        const boost::system::error_code ErrorCode = boost::system::make_error_code(Prism::Fault::Code::Kexfail);
        EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), Prism::Fault::Code::Kexfail);

        // Prism::Fault 分类：越界值 → generic_error
        const boost::system::error_code OutOfRangeCode{9999, boost::system::Category()};
        EXPECT_EQ(Prism::Fault::ToCode(OutOfRangeCode), Prism::Fault::Code::GenericError);
    }

    TEST(CoreFault, ToCodeBoostMappings)
    {
        // 逐个验证 Asio 错误 → fault 错误映射
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::eof), Prism::Fault::Code::Eof);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::operation_aborted), Prism::Fault::Code::Canceled);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::timed_out), Prism::Fault::Code::Timeout);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_refused), Prism::Fault::Code::ConnectionRefused);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_reset), Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_aborted), Prism::Fault::Code::ConnectionAborted);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::host_unreachable), Prism::Fault::Code::HostNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::network_unreachable), Prism::Fault::Code::NetNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::no_buffer_space), Prism::Fault::Code::ResourceUnavailable);
    }

    TEST(CoreFault, ToCodeBoostUnknown)
    {
        // 未映射的错误 → io_error
        const boost::system::error_code ErrorCode{static_cast<int>(boost::system::errc::invalid_argument),
                                           boost::system::generic_category()};
        EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), Prism::Fault::Code::IoError);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::broken_pipe), Prism::Fault::Code::IoError);
    }

    TEST(CoreFault, ToCodeStdSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(Prism::Fault::ToCode(std::error_code{}), Prism::Fault::Code::Success);
    }

    TEST(CoreFault, ToCodeStdPsmCategory)
    {
        // Prism::Fault 分类：范围内值还原为原码
        const std::error_code ErrorCode = Prism::Fault::make_error_code(Prism::Fault::Code::Badsni);
        EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), Prism::Fault::Code::Badsni);

        // Prism::Fault 分类：越界值 → generic_error
        const std::error_code OutOfRangeCode{9999, Prism::Fault::Category()};
        EXPECT_EQ(Prism::Fault::ToCode(OutOfRangeCode), Prism::Fault::Code::GenericError);
    }

    TEST(CoreFault, ToCodeStdMappings)
    {
        // 逐个验证 std::errc 错误 → fault 错误映射
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_refused)),
                  Prism::Fault::Code::ConnectionRefused);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_reset)),
                  Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_aborted)),
                  Prism::Fault::Code::ConnectionAborted);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::timed_out)), Prism::Fault::Code::Timeout);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::host_unreachable)),
                  Prism::Fault::Code::HostNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::network_unreachable)),
                  Prism::Fault::Code::NetNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::operation_canceled)),
                  Prism::Fault::Code::Canceled);
    }

    TEST(CoreFault, ToCodeStdUnknown)
    {
        // 未映射的错误 → io_error
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::invalid_argument)),
                  Prism::Fault::Code::IoError);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::no_such_file_or_directory)),
                  Prism::Fault::Code::IoError);
    }
} // namespace
