/**
 * @file FaultCoverage.cpp
 * @brief Prism::Fault 模块覆盖率补全测试
 * @details 针对 tests/Prism/Fault 三层头文件做穷举式覆盖：
 * 1. Code.hpp —— Describe() 全部 64 个枚举分支（含边界值、default）
 *    及 Succeeded()/Failed() 全码遍历
 * 2. compatible.hpp —— 双分类器 Name/Message、CachedMessage 全码、
 *    make_error_code 往返、std::hash 特化、隐式转换
 * 3. handling.hpp —— ToCode() 的 boost/std 双路转换全部分支
 *    （空码、自有分类、越界、Asio/errc 映射、未知码）及三类型
 *    Succeeded()/Failed() 模板分发
 */

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Error.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    using Prism::Fault::Code;

    constexpr auto CodeCount = static_cast<int>(Code::Count);

    // ────────────────────────── Code.hpp ──────────────────────────

    TEST(FaultCoverage, DescribeAllEnumBranches)
    {
        // 遍历全部枚举值，逐一调用 Describe()，确保 switch 每个 case 均被覆盖
        // 使用运行时变量避免 constexpr 编译期折叠
        volatile int Cursor = 0;
        for (; Cursor < CodeCount; ++Cursor)
        {
            const auto CodeValue = static_cast<Code>(Cursor);
            const std::string_view Description = Prism::Fault::Describe(CodeValue);
            ASSERT_FALSE(Description.empty()) << "Describe(Code=" << Cursor << ") 返回空串";
        }

        // 边界值：首个枚举（success = 0）与最后一个枚举（badcfg = 63）
        EXPECT_EQ(Prism::Fault::Describe(Code::Success), "success");
        EXPECT_EQ(Prism::Fault::Describe(Code::GenericError), "generic_error");
        EXPECT_EQ(Prism::Fault::Describe(Code::Badcfg), "badcfg");

        // 枚举总数不变式：0..63 共 64 个，_count 仅用于统计
        EXPECT_EQ(CodeCount, 64);
        EXPECT_EQ(static_cast<int>(Code::Success), 0);
    }

    TEST(FaultCoverage, DescribeUnknownBranch)
    {
        // default 分支：正负越界均返回 "unknown"，须用运行时变量触发
        volatile int HighValue = 9999;
        volatile int LowValue = -1;
        EXPECT_EQ(Prism::Fault::Describe(static_cast<Code>(HighValue)), "unknown");
        EXPECT_EQ(Prism::Fault::Describe(static_cast<Code>(LowValue)), "unknown");
    }

    TEST(FaultCoverage, SucceededFailedEveryCode)
    {
        // 唯一成功码：Succeeded 为 true、Failed 为 false
        EXPECT_TRUE(Prism::Fault::Succeeded(Code::Success));
        EXPECT_FALSE(Prism::Fault::Failed(Code::Success));

        // 全部错误码：Succeeded 为 false、Failed 为 true
        volatile int Cursor = 0;
        for (; Cursor < CodeCount; ++Cursor)
        {
            const auto CodeValue = static_cast<Code>(Cursor);
            if (CodeValue == Code::Success)
            {
                continue;
            }
            EXPECT_FALSE(Prism::Fault::Succeeded(CodeValue)) << "Succeeded(Code=" << Cursor << ") 应为 false";
            EXPECT_TRUE(Prism::Fault::Failed(CodeValue)) << "Failed(Code=" << Cursor << ") 应为 true";
        }

        // 越界值同样视为失败
        EXPECT_FALSE(Prism::Fault::Succeeded(static_cast<Code>(-1)));
        EXPECT_TRUE(Prism::Fault::Failed(static_cast<Code>(100000)));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(FaultCoverage, CachedMessageEveryCode)
    {
        // 缓存消息与 Describe 全码一致
        volatile int Cursor = 0;
        for (; Cursor < CodeCount; ++Cursor)
        {
            const auto CodeValue = static_cast<Code>(Cursor);
            EXPECT_EQ(Prism::Fault::CachedMessage(CodeValue), Prism::Fault::Describe(CodeValue));
        }

        // 越界索引回落 "unknown"
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Code>(Code::Count)), "unknown");
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Code>(-3)), "unknown");
        EXPECT_EQ(Prism::Fault::CachedMessage(static_cast<Code>(65536)), "unknown");
    }

    TEST(FaultCoverage, StdCategoryNameAndMessage)
    {
        const auto &ErrorCategory = Prism::Fault::Category();

        // Name() 非空且固定
        EXPECT_FALSE(std::string_view(ErrorCategory.name()).empty());
        EXPECT_EQ(std::string_view(ErrorCategory.name()), "Prism::fault");

        // 单例：多次调用同一实例
        EXPECT_EQ(&ErrorCategory, &Prism::Fault::Category());

        // Message() 对全部已知码非空
        volatile int Cursor = 0;
        for (; Cursor < CodeCount; ++Cursor)
        {
            const std::string Message = ErrorCategory.message(Cursor);
            EXPECT_FALSE(Message.empty()) << "Category.message(" << Cursor << ") 返回空串";
        }
        EXPECT_EQ(ErrorCategory.message(0), "success");
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Code::Count)), "unknown");
    }

    TEST(FaultCoverage, BoostCategoryNameAndMessage)
    {
        const auto &ErrorCategory = boost::system::Category();

        EXPECT_FALSE(std::string_view(ErrorCategory.name()).empty());
        EXPECT_EQ(std::string_view(ErrorCategory.name()), "Prism::fault");
        EXPECT_EQ(&ErrorCategory, &boost::system::Category());

        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Code::Eof)), "eof");
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Code::Success)), "success");
        EXPECT_EQ(ErrorCategory.message(static_cast<int>(Code::Count)), "unknown");
        EXPECT_EQ(ErrorCategory.message(-7), "unknown");
    }

    TEST(FaultCoverage, MakeErrorCodeStdRoundTrip)
    {
        // 覆盖首、中、尾三类代表性错误码
        const Code Samples[] = {Code::Success, Code::GenericError, Code::Timeout,
                                Code::Verifyfail, Code::Badcfg};
        for (const auto CodeValue : Samples)
        {
            const std::error_code ErrorCode = Prism::Fault::make_error_code(CodeValue);
            EXPECT_EQ(ErrorCode.value(), static_cast<int>(CodeValue));
            EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");
            EXPECT_FALSE(ErrorCode.message().empty());
            EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), CodeValue) << "make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, MakeErrorCodeBoostRoundTrip)
    {
        const Code Samples[] = {Code::Success, Code::Eof, Code::ConnectionRefused, Code::Badcfg};
        for (const auto CodeValue : Samples)
        {
            const boost::system::error_code ErrorCode = boost::system::make_error_code(CodeValue);
            EXPECT_EQ(ErrorCode.value(), static_cast<int>(CodeValue));
            EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");
            EXPECT_FALSE(ErrorCode.message().empty());
            EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), CodeValue) << "boost make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, ImplicitConversionBothSides)
    {
        // IsErrorCodeEnum 特化：std 侧支持隐式转换
        const std::error_code ErrorCode = Code::Timeout;
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Code::Timeout));
        EXPECT_EQ(std::string_view(ErrorCode.category().name()), "Prism::fault");

        // boost 侧隐式转换存在缺陷（见 logs/issues.md B-31，ADL 命中
        // Prism::Fault::make_error_code 返回 std::error_code 导致垃圾值），
        // 此处仅验证显式构造路径
        const boost::system::error_code BoostErrorCode = boost::system::make_error_code(Code::Eof);
        EXPECT_EQ(BoostErrorCode.value(), static_cast<int>(Code::Eof));
        EXPECT_EQ(std::string_view(BoostErrorCode.category().name()), "Prism::fault");
    }

    TEST(FaultCoverage, HashSpecialization)
    {
        // 哈希特化委托 std::hash<int>
        std::hash<Code> Hasher;
        const Code Samples[] = {Code::Success, Code::GenericError, Code::Timeout, Code::Badcfg};
        for (const auto CodeValue : Samples)
        {
            EXPECT_EQ(Hasher(CodeValue), std::hash<int>{}(static_cast<int>(CodeValue)));
        }
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(FaultCoverage, SucceededFailedHelpers)
    {
        // Fault::Code 类型
        EXPECT_TRUE(Prism::Fault::Succeeded(Code::Success));
        EXPECT_FALSE(Prism::Fault::Succeeded(Code::Badcfg));
        EXPECT_FALSE(Prism::Fault::Failed(Code::Success));
        EXPECT_TRUE(Prism::Fault::Failed(Code::Badcfg));

        // std::error_code 类型
        EXPECT_TRUE(Prism::Fault::Succeeded(std::error_code{}));
        EXPECT_FALSE(Prism::Fault::Succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(Prism::Fault::Failed(std::error_code{}));
        EXPECT_TRUE(Prism::Fault::Failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型
        EXPECT_TRUE(Prism::Fault::Succeeded(boost::system::error_code{}));
        EXPECT_FALSE(Prism::Fault::Failed(boost::system::error_code{}));
        const boost::system::error_code BoostErrorCode{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_FALSE(Prism::Fault::Succeeded(BoostErrorCode));
        EXPECT_TRUE(Prism::Fault::Failed(BoostErrorCode));
    }

    TEST(FaultCoverage, ToCodeBoostEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(Prism::Fault::ToCode(boost::system::error_code{}), Code::Success);
    }

    TEST(FaultCoverage, ToCodeBoostAsioMappings)
    {
        // 全部 Asio → fault 映射分支
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::eof), Code::Eof);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::operation_aborted), Code::Canceled);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::timed_out), Code::Timeout);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_refused),
                  Code::ConnectionRefused);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_reset), Code::ConnectionReset);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::connection_aborted),
                  Code::ConnectionAborted);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::host_unreachable), Code::HostNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::network_unreachable), Code::NetNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::no_buffer_space),
                  Code::ResourceUnavailable);
    }

    TEST(FaultCoverage, ToCodeBoostOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const Code Samples[] = {Code::Success, Code::Kexfail, Code::Badcfg};
        for (const auto CodeValue : Samples)
        {
            const boost::system::error_code ErrorCode = boost::system::make_error_code(CodeValue);
            EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), CodeValue);
        }

        // 自有分类：正负越界值 → generic_error
        const boost::system::error_code HighValue{9999, boost::system::Category()};
        const boost::system::error_code LowValue{-1, boost::system::Category()};
        EXPECT_EQ(Prism::Fault::ToCode(HighValue), Code::GenericError);
        EXPECT_EQ(Prism::Fault::ToCode(LowValue), Code::GenericError);
    }

    TEST(FaultCoverage, ToCodeBoostProtocolCategoryMappings)
    {
        const std::pair<Prism::Error, Code> Cases[] = {
            {Prism::Error::None, Code::Success},
            {Prism::Error::NeedMore, Code::WouldBlock},
            {Prism::Error::UnexpectedEof, Code::Eof},
            {Prism::Error::BadLength, Code::BadMessage},
            {Prism::Error::BadMagic, Code::BadMessage},
            {Prism::Error::BadAuth, Code::AuthFailed},
            {Prism::Error::BadMessage, Code::BadMessage},
            {Prism::Error::BadAddress, Code::UnsupportedAddress},
            {Prism::Error::NotOpen, Code::IoError},
            {Prism::Error::Canceled, Code::Canceled},
            {Prism::Error::Timeout, Code::Timeout},
            {Prism::Error::BrokenPipe, Code::IoError},
            {Prism::Error::ProtocolError, Code::ProtocolError},
            {Prism::Error::KdfError, Code::GenericError},
            {Prism::Error::Unsupported, Code::NotSupported},
            {Prism::Error::IoError, Code::IoError},
            {Prism::Error::CryptoError, Code::GenericError},
        };

        for (const auto &[ErrorValue, Expected] : Cases)
        {
            EXPECT_EQ(Prism::Fault::ToCode(Prism::make_error_code(ErrorValue)), Expected)
                << "协议错误映射错误值=" << static_cast<int>(ErrorValue);
        }
    }

    TEST(FaultCoverage, ToCodeBoostUnknown)
    {
        // 未映射的系统错误 → io_error
        const boost::system::error_code ErrorCode{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), Code::IoError);
        EXPECT_EQ(Prism::Fault::ToCode(boost::asio::error::broken_pipe), Code::IoError);
    }

    TEST(FaultCoverage, ToCodeStdEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(Prism::Fault::ToCode(std::error_code{}), Code::Success);
    }

    TEST(FaultCoverage, ToCodeStdErrcMappings)
    {
        // 全部 std::errc → fault 映射分支
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_refused)),
                  Code::ConnectionRefused);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_reset)),
                  Code::ConnectionReset);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::connection_aborted)),
                  Code::ConnectionAborted);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::timed_out)), Code::Timeout);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::host_unreachable)),
                  Code::HostNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::network_unreachable)),
                  Code::NetNoreply);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::operation_canceled)),
                  Code::Canceled);
    }

    TEST(FaultCoverage, ToCodeStdOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const Code Samples[] = {Code::Success, Code::Badsni, Code::Badcfg};
        for (const auto CodeValue : Samples)
        {
            const std::error_code ErrorCode = Prism::Fault::make_error_code(CodeValue);
            EXPECT_EQ(Prism::Fault::ToCode(ErrorCode), CodeValue);
        }

        // 自有分类：正负越界值 → generic_error
        const std::error_code HighValue{9999, Prism::Fault::Category()};
        const std::error_code LowValue{-1, Prism::Fault::Category()};
        EXPECT_EQ(Prism::Fault::ToCode(HighValue), Code::GenericError);
        EXPECT_EQ(Prism::Fault::ToCode(LowValue), Code::GenericError);
    }

    TEST(FaultCoverage, ToCodeStdUnknown)
    {
        // 未映射的标准错误 → io_error
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::invalid_argument)),
                  Code::IoError);
        EXPECT_EQ(Prism::Fault::ToCode(std::make_error_code(std::errc::no_such_file_or_directory)),
                  Code::IoError);
    }
} // namespace
