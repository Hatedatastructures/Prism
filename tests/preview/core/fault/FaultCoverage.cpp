/**
 * @file FaultCoverage.cpp
 * @brief Preview::Fault 模块覆盖率补全测试
 * @details 针对 tests/common/core/fault 三层头文件做穷举式覆盖：
 * 1. Code.hpp —— Describe() 全部 64 个枚举分支（含边界值、default）
 *    及 Succeeded()/Failed() 全码遍历
 * 2. compatible.hpp —— 双分类器 Name/Message、CachedMessage 全码、
 *    make_error_code 往返、std::hash 特化、隐式转换
 * 3. handling.hpp —— ToCode() 的 boost/std 双路转换全部分支
 *    （空码、自有分类、越界、Asio/errc 映射、未知码）及三类型
 *    Succeeded()/Failed() 模板分发
 */

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Compatible.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Foundation/Error.hpp>

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
    using Preview::Fault::Code;

    constexpr auto code_count = static_cast<int>(Code::_count);

    // ────────────────────────── Code.hpp ──────────────────────────

    TEST(FaultCoverage, DescribeAllEnumBranches)
    {
        // 遍历全部枚举值，逐一调用 Describe()，确保 switch 每个 case 均被覆盖
        // 使用运行时变量避免 constexpr 编译期折叠
        volatile int Cursor = 0;
        for (; Cursor < code_count; ++Cursor)
        {
            const auto c = static_cast<Code>(Cursor);
            const std::string_view desc = Preview::Fault::Describe(c);
            ASSERT_FALSE(desc.empty()) << "Describe(Code=" << Cursor << ") 返回空串";
        }

        // 边界值：首个枚举（success = 0）与最后一个枚举（badcfg = 63）
        EXPECT_EQ(Preview::Fault::Describe(Code::Success), "success");
        EXPECT_EQ(Preview::Fault::Describe(Code::GenericError), "generic_error");
        EXPECT_EQ(Preview::Fault::Describe(Code::Badcfg), "badcfg");

        // 枚举总数不变式：0..63 共 64 个，_count 仅用于统计
        EXPECT_EQ(code_count, 64);
        EXPECT_EQ(static_cast<int>(Code::Success), 0);
    }

    TEST(FaultCoverage, DescribeUnknownBranch)
    {
        // default 分支：正负越界均返回 "unknown"，须用运行时变量触发
        volatile int hi = 9999;
        volatile int lo = -1;
        EXPECT_EQ(Preview::Fault::Describe(static_cast<Code>(hi)), "unknown");
        EXPECT_EQ(Preview::Fault::Describe(static_cast<Code>(lo)), "unknown");
    }

    TEST(FaultCoverage, SucceededFailedEveryCode)
    {
        // 唯一成功码：Succeeded 为 true、Failed 为 false
        EXPECT_TRUE(Preview::Fault::Succeeded(Code::Success));
        EXPECT_FALSE(Preview::Fault::Failed(Code::Success));

        // 全部错误码：Succeeded 为 false、Failed 为 true
        volatile int Cursor = 0;
        for (; Cursor < code_count; ++Cursor)
        {
            const auto c = static_cast<Code>(Cursor);
            if (c == Code::Success)
            {
                continue;
            }
            EXPECT_FALSE(Preview::Fault::Succeeded(c)) << "Succeeded(Code=" << Cursor << ") 应为 false";
            EXPECT_TRUE(Preview::Fault::Failed(c)) << "Failed(Code=" << Cursor << ") 应为 true";
        }

        // 越界值同样视为失败
        EXPECT_FALSE(Preview::Fault::Succeeded(static_cast<Code>(-1)));
        EXPECT_TRUE(Preview::Fault::Failed(static_cast<Code>(100000)));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(FaultCoverage, CachedMessageEveryCode)
    {
        // 缓存消息与 Describe 全码一致
        volatile int Cursor = 0;
        for (; Cursor < code_count; ++Cursor)
        {
            const auto c = static_cast<Code>(Cursor);
            EXPECT_EQ(Preview::Fault::CachedMessage(c), Preview::Fault::Describe(c));
        }

        // 越界索引回落 "unknown"
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Code>(Code::_count)), "unknown");
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Code>(-3)), "unknown");
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Code>(65536)), "unknown");
    }

    TEST(FaultCoverage, StdCategoryNameAndMessage)
    {
        const auto &cat = Preview::Fault::Category();

        // Name() 非空且固定
        EXPECT_FALSE(std::string_view(cat.name()).empty());
        EXPECT_EQ(std::string_view(cat.name()), "Preview::fault");

        // 单例：多次调用同一实例
        EXPECT_EQ(&cat, &Preview::Fault::Category());

        // Message() 对全部已知码非空
        volatile int Cursor = 0;
        for (; Cursor < code_count; ++Cursor)
        {
            const std::string msg = cat.message(Cursor);
            EXPECT_FALSE(msg.empty()) << "Category.message(" << Cursor << ") 返回空串";
        }
        EXPECT_EQ(cat.message(0), "success");
        EXPECT_EQ(cat.message(static_cast<int>(Code::_count)), "unknown");
    }

    TEST(FaultCoverage, BoostCategoryNameAndMessage)
    {
        const auto &cat = boost::system::Category();

        EXPECT_FALSE(std::string_view(cat.name()).empty());
        EXPECT_EQ(std::string_view(cat.name()), "Preview::fault");
        EXPECT_EQ(&cat, &boost::system::Category());

        EXPECT_EQ(cat.message(static_cast<int>(Code::Eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(Code::Success)), "success");
        EXPECT_EQ(cat.message(static_cast<int>(Code::_count)), "unknown");
        EXPECT_EQ(cat.message(-7), "unknown");
    }

    TEST(FaultCoverage, make_error_codeStdRoundTrip)
    {
        // 覆盖首、中、尾三类代表性错误码
        const Code samples[] = {Code::Success, Code::GenericError, Code::Timeout,
                                Code::Verifyfail, Code::Badcfg};
        for (const auto c : samples)
        {
            const std::error_code ec = Preview::Fault::make_error_code(c);
            EXPECT_EQ(ec.value(), static_cast<int>(c));
            EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
            EXPECT_FALSE(ec.message().empty());
            EXPECT_EQ(Preview::Fault::ToCode(ec), c) << "make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, make_error_codeBoostRoundTrip)
    {
        const Code samples[] = {Code::Success, Code::Eof, Code::ConnectionRefused, Code::Badcfg};
        for (const auto c : samples)
        {
            const boost::system::error_code ec = boost::system::make_error_code(c);
            EXPECT_EQ(ec.value(), static_cast<int>(c));
            EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
            EXPECT_FALSE(ec.message().empty());
            EXPECT_EQ(Preview::Fault::ToCode(ec), c) << "boost make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, ImplicitConversionBothSides)
    {
        // IsErrorCodeEnum 特化：std 侧支持隐式转换
        const std::error_code ec = Code::Timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(Code::Timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");

        // boost 侧隐式转换存在缺陷（见 logs/issues.md B-31，ADL 命中
        // Preview::Fault::make_error_code 返回 std::error_code 导致垃圾值），
        // 此处仅验证显式构造路径
        const boost::system::error_code bec = boost::system::make_error_code(Code::Eof);
        EXPECT_EQ(bec.value(), static_cast<int>(Code::Eof));
        EXPECT_EQ(std::string_view(bec.category().name()), "Preview::fault");
    }

    TEST(FaultCoverage, HashSpecialization)
    {
        // 哈希特化委托 std::hash<int>
        std::hash<Code> hasher;
        const Code samples[] = {Code::Success, Code::GenericError, Code::Timeout, Code::Badcfg};
        for (const auto c : samples)
        {
            EXPECT_EQ(hasher(c), std::hash<int>{}(static_cast<int>(c)));
        }
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(FaultCoverage, SucceededFailedHelpers)
    {
        // Fault::Code 类型
        EXPECT_TRUE(Preview::Fault::Succeeded(Code::Success));
        EXPECT_FALSE(Preview::Fault::Succeeded(Code::Badcfg));
        EXPECT_FALSE(Preview::Fault::Failed(Code::Success));
        EXPECT_TRUE(Preview::Fault::Failed(Code::Badcfg));

        // std::error_code 类型
        EXPECT_TRUE(Preview::Fault::Succeeded(std::error_code{}));
        EXPECT_FALSE(Preview::Fault::Succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(Preview::Fault::Failed(std::error_code{}));
        EXPECT_TRUE(Preview::Fault::Failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型
        EXPECT_TRUE(Preview::Fault::Succeeded(boost::system::error_code{}));
        EXPECT_FALSE(Preview::Fault::Failed(boost::system::error_code{}));
        const boost::system::error_code bec{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_FALSE(Preview::Fault::Succeeded(bec));
        EXPECT_TRUE(Preview::Fault::Failed(bec));
    }

    TEST(FaultCoverage, ToCodeBoostEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(Preview::Fault::ToCode(boost::system::error_code{}), Code::Success);
    }

    TEST(FaultCoverage, ToCodeBoostAsioMappings)
    {
        // 全部 Asio → fault 映射分支
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::eof), Code::Eof);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::operation_aborted), Code::Canceled);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::timed_out), Code::Timeout);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_refused),
                  Code::ConnectionRefused);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_reset), Code::ConnectionReset);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_aborted),
                  Code::ConnectionAborted);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::host_unreachable), Code::HostNoreply);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::network_unreachable), Code::NetNoreply);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::no_buffer_space),
                  Code::ResourceUnavailable);
    }

    TEST(FaultCoverage, ToCodeBoostOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const Code samples[] = {Code::Success, Code::Kexfail, Code::Badcfg};
        for (const auto c : samples)
        {
            const boost::system::error_code ec = boost::system::make_error_code(c);
            EXPECT_EQ(Preview::Fault::ToCode(ec), c);
        }

        // 自有分类：正负越界值 → generic_error
        const boost::system::error_code hi{9999, boost::system::Category()};
        const boost::system::error_code lo{-1, boost::system::Category()};
        EXPECT_EQ(Preview::Fault::ToCode(hi), Code::GenericError);
        EXPECT_EQ(Preview::Fault::ToCode(lo), Code::GenericError);
    }

    TEST(FaultCoverage, ToCodeBoostProtocolCategoryMappings)
    {
        const std::pair<Preview::Error, Code> Cases[] = {
            {Preview::Error::None, Code::Success},
            {Preview::Error::NeedMore, Code::WouldBlock},
            {Preview::Error::UnexpectedEof, Code::Eof},
            {Preview::Error::BadLength, Code::BadMessage},
            {Preview::Error::BadMagic, Code::BadMessage},
            {Preview::Error::BadAuth, Code::AuthFailed},
            {Preview::Error::AuthFailed, Code::AuthFailed},
            {Preview::Error::VersionMismatch, Code::BadMessage},
            {Preview::Error::NotSupported, Code::NotSupported},
            {Preview::Error::BadMessage, Code::BadMessage},
            {Preview::Error::BadAddress, Code::UnsupportedAddress},
            {Preview::Error::NotOpen, Code::IoError},
            {Preview::Error::Canceled, Code::Canceled},
            {Preview::Error::Timeout, Code::Timeout},
            {Preview::Error::BrokenPipe, Code::IoError},
            {Preview::Error::ProtocolError, Code::ProtocolError},
            {Preview::Error::KdfError, Code::GenericError},
            {Preview::Error::Unsupported, Code::NotSupported},
            {Preview::Error::IoError, Code::IoError},
        };

        for (const auto &[ErrorValue, Expected] : Cases)
        {
            EXPECT_EQ(Preview::Fault::ToCode(Preview::make_error_code(ErrorValue)), Expected)
                << "协议错误映射错误值=" << static_cast<int>(ErrorValue);
        }
    }

    TEST(FaultCoverage, ToCodeBoostUnknown)
    {
        // 未映射的系统错误 → io_error
        const boost::system::error_code ec{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_EQ(Preview::Fault::ToCode(ec), Code::IoError);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::broken_pipe), Code::IoError);
    }

    TEST(FaultCoverage, ToCodeStdEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(Preview::Fault::ToCode(std::error_code{}), Code::Success);
    }

    TEST(FaultCoverage, ToCodeStdErrcMappings)
    {
        // 全部 std::errc → fault 映射分支
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_refused)),
                  Code::ConnectionRefused);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_reset)),
                  Code::ConnectionReset);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_aborted)),
                  Code::ConnectionAborted);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::timed_out)), Code::Timeout);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::host_unreachable)),
                  Code::HostNoreply);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::network_unreachable)),
                  Code::NetNoreply);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::operation_canceled)),
                  Code::Canceled);
    }

    TEST(FaultCoverage, ToCodeStdOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const Code samples[] = {Code::Success, Code::Badsni, Code::Badcfg};
        for (const auto c : samples)
        {
            const std::error_code ec = Preview::Fault::make_error_code(c);
            EXPECT_EQ(Preview::Fault::ToCode(ec), c);
        }

        // 自有分类：正负越界值 → generic_error
        const std::error_code hi{9999, Preview::Fault::Category()};
        const std::error_code lo{-1, Preview::Fault::Category()};
        EXPECT_EQ(Preview::Fault::ToCode(hi), Code::GenericError);
        EXPECT_EQ(Preview::Fault::ToCode(lo), Code::GenericError);
    }

    TEST(FaultCoverage, ToCodeStdUnknown)
    {
        // 未映射的标准错误 → io_error
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::invalid_argument)),
                  Code::IoError);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::no_such_file_or_directory)),
                  Code::IoError);
    }
} // namespace
