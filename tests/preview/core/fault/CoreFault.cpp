/**
 * @file CoreFault.cpp
 * @brief tests/common/core/fault 模块单元测试
 * @details 覆盖 Preview::Fault 错误码体系的三层头文件：
 * 1. Code.hpp —— Describe() 全部 64 个枚举分支 + default、Succeeded/Failed
 * 2. compatible.hpp —— CachedMessage 正常/越界、std/boost 双分类器、
 *    make_error_code、std::hash 特化、隐式转换
 * 3. handling.hpp —— Succeeded/Failed 模板三类型分发、
 *    ToCode(boost) 全部映射分支、ToCode(std) 全部映射分支
 */

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Compatible.hpp>
#include <common/Core/Fault/Handling.hpp>

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
        constexpr int Count = static_cast<int>(Preview::Fault::Code::_count);
        for (int i = 0; i < Count; ++i)
        {
            const auto c = static_cast<Preview::Fault::Code>(i);
            const std::string_view desc = Preview::Fault::Describe(c);
            ASSERT_FALSE(desc.empty()) << "Describe(Code=" << i << ") returned Empty string";
        }

        // 抽查关键错误码的精确描述
        EXPECT_EQ(Preview::Fault::Describe(Preview::Fault::Code::success), "success");
        EXPECT_EQ(Preview::Fault::Describe(Preview::Fault::Code::eof), "eof");
        EXPECT_EQ(Preview::Fault::Describe(Preview::Fault::Code::timeout), "timeout");
        EXPECT_EQ(Preview::Fault::Describe(Preview::Fault::Code::crypto_error), "crypto_error");
        EXPECT_EQ(Preview::Fault::Describe(Preview::Fault::Code::badcfg), "badcfg");

        // Describe 为 constexpr，可在编译期求值
        static_assert(Preview::Fault::Describe(Preview::Fault::Code::timeout) == "timeout");
        static_assert(Preview::Fault::Describe(Preview::Fault::Code::success) == "success");
    }

    TEST(CoreFault, DescribeUnknown)
    {
        // default 分支：正数越界与负数越界均返回 "unknown"
        // 注意：Describe 为 constexpr，常量参数会被编译期折叠，须用运行时变量触发
        volatile int hi = 9999;
        volatile int lo = -1;
        EXPECT_EQ(Preview::Fault::Describe(static_cast<Preview::Fault::Code>(hi)), "unknown");
        EXPECT_EQ(Preview::Fault::Describe(static_cast<Preview::Fault::Code>(lo)), "unknown");
    }

    TEST(CoreFault, SucceededFailed)
    {
        // success 是唯一使 Succeeded 返回 true 的码
        EXPECT_TRUE(Preview::Fault::Succeeded(Preview::Fault::Code::success));
        EXPECT_FALSE(Preview::Fault::Failed(Preview::Fault::Code::success));

        // 非 success 码：Succeeded 为 false、Failed 为 true
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::timeout));
        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::timeout));
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::crypto_error));
        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::crypto_error));
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::eof));
        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::eof));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(CoreFault, CachedMessageValid)
    {
        // 缓存消息与 Describe 完全一致（首次调用触发静态数组构造）
        constexpr int Count = static_cast<int>(Preview::Fault::Code::_count);
        for (int i = 0; i < Count; ++i)
        {
            const auto c = static_cast<Preview::Fault::Code>(i);
            EXPECT_EQ(Preview::Fault::CachedMessage(c), Preview::Fault::Describe(c));
        }
    }

    TEST(CoreFault, CachedMessageOutOfRange)
    {
        // 越界索引（>= _count 或负数）返回 "unknown"
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Preview::Fault::Code>(Preview::Fault::Code::_count)), "unknown");
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Preview::Fault::Code>(-5)), "unknown");
        EXPECT_EQ(Preview::Fault::CachedMessage(static_cast<Preview::Fault::Code>(100000)), "unknown");
    }

    TEST(CoreFault, StdCategory)
    {
        const auto &cat = Preview::Fault::category();

        // Name() 返回分类名
        EXPECT_EQ(std::string_view(cat.name()), "Preview::fault");

        // 单例：多次调用返回同一实例
        EXPECT_EQ(&cat, &Preview::Fault::category());

        // Message(int) 委托 CachedMessage：有效码返回描述、越界返回 unknown
        EXPECT_EQ(cat.message(static_cast<int>(Preview::Fault::Code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(Preview::Fault::Code::_count)), "unknown");
    }

    TEST(CoreFault, make_error_codeStd)
    {
        const std::error_code ec = Preview::Fault::make_error_code(Preview::Fault::Code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";
    }

    TEST(CoreFault, ImplicitConversionStd)
    {
        // IsErrorCodeEnum 特化支持隐式转换
        const std::error_code ec = Preview::Fault::Code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
    }

    TEST(CoreFault, HashSpecialization)
    {
        // Hash 特化委托 std::hash<int>
        std::hash<Preview::Fault::Code> hasher;
        const auto c = Preview::Fault::Code::eof;
        EXPECT_EQ(hasher(c), std::hash<int>{}(static_cast<int>(c)));
        EXPECT_EQ(hasher(Preview::Fault::Code::success), std::hash<int>{}(0));
    }

    TEST(CoreFault, BoostCategory)
    {
        const auto &cat = boost::system::category();

        EXPECT_EQ(std::string_view(cat.name()), "Preview::fault");

        // 单例
        EXPECT_EQ(&cat, &boost::system::category());

        // Message(int) 委托 CachedMessage
        EXPECT_EQ(cat.message(static_cast<int>(Preview::Fault::Code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(Preview::Fault::Code::_count)), "unknown");
    }

    TEST(CoreFault, make_error_codeBoost)
    {
        const boost::system::error_code ec = boost::system::make_error_code(Preview::Fault::Code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
        EXPECT_TRUE(ec);
    }

    TEST(CoreFault, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 IsErrorCodeEnum 均为 true
        static_assert(std::is_error_code_enum<Preview::Fault::Code>::value);
        static_assert(boost::system::is_error_code_enum<Preview::Fault::Code>::value);

        // std 侧隐式转换正常
        const std::error_code ec = Preview::Fault::Code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");

        // boost 侧经 boost::system::make_error_code 显式转换
        const boost::system::error_code bec = boost::system::make_error_code(Preview::Fault::Code::timeout);
        EXPECT_EQ(bec.value(), static_cast<int>(Preview::Fault::Code::timeout));
        EXPECT_EQ(std::string_view(bec.category().name()), "Preview::fault");
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(CoreFault, SucceededFailedTemplate)
    {
        // Fault::Code 类型分发
        EXPECT_TRUE(Preview::Fault::Succeeded(Preview::Fault::Code::success));
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::eof));
        EXPECT_FALSE(Preview::Fault::Failed(Preview::Fault::Code::success));
        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::eof));

        // std::error_code 类型分发
        EXPECT_TRUE(Preview::Fault::Succeeded(std::error_code{}));
        EXPECT_FALSE(Preview::Fault::Succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(Preview::Fault::Failed(std::error_code{}));
        EXPECT_TRUE(Preview::Fault::Failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型分发
        EXPECT_TRUE(Preview::Fault::Succeeded(boost::system::error_code{}));
        EXPECT_FALSE(
            Preview::Fault::Succeeded(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
        EXPECT_FALSE(Preview::Fault::Failed(boost::system::error_code{}));
        EXPECT_TRUE(Preview::Fault::Failed(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
    }

    TEST(CoreFault, ToCodeBoostSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(Preview::Fault::ToCode(boost::system::error_code{}), Preview::Fault::Code::success);
    }

    TEST(CoreFault, ToCodeBoostPsmCategory)
    {
        // Preview::Fault 分类：范围内值还原为原码
        const boost::system::error_code ec = boost::system::make_error_code(Preview::Fault::Code::kexfail);
        EXPECT_EQ(Preview::Fault::ToCode(ec), Preview::Fault::Code::kexfail);

        // Preview::Fault 分类：越界值 → generic_error
        const boost::system::error_code out{9999, boost::system::category()};
        EXPECT_EQ(Preview::Fault::ToCode(out), Preview::Fault::Code::generic_error);
    }

    TEST(CoreFault, ToCodeBoostMappings)
    {
        // 逐个验证 Asio 错误 → fault 错误映射
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::eof), Preview::Fault::Code::eof);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::operation_aborted), Preview::Fault::Code::canceled);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::timed_out), Preview::Fault::Code::timeout);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_refused), Preview::Fault::Code::connection_refused);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_reset), Preview::Fault::Code::connection_reset);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::connection_aborted), Preview::Fault::Code::connection_aborted);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::host_unreachable), Preview::Fault::Code::host_noreply);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::network_unreachable), Preview::Fault::Code::net_noreply);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::no_buffer_space), Preview::Fault::Code::resource_unavailable);
    }

    TEST(CoreFault, ToCodeBoostUnknown)
    {
        // 未映射的错误 → io_error
        const boost::system::error_code ec{static_cast<int>(boost::system::errc::invalid_argument),
                                           boost::system::generic_category()};
        EXPECT_EQ(Preview::Fault::ToCode(ec), Preview::Fault::Code::io_error);
        EXPECT_EQ(Preview::Fault::ToCode(boost::asio::error::broken_pipe), Preview::Fault::Code::io_error);
    }

    TEST(CoreFault, ToCodeStdSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(Preview::Fault::ToCode(std::error_code{}), Preview::Fault::Code::success);
    }

    TEST(CoreFault, ToCodeStdPsmCategory)
    {
        // Preview::Fault 分类：范围内值还原为原码
        const std::error_code ec = Preview::Fault::make_error_code(Preview::Fault::Code::badsni);
        EXPECT_EQ(Preview::Fault::ToCode(ec), Preview::Fault::Code::badsni);

        // Preview::Fault 分类：越界值 → generic_error
        const std::error_code out{9999, Preview::Fault::category()};
        EXPECT_EQ(Preview::Fault::ToCode(out), Preview::Fault::Code::generic_error);
    }

    TEST(CoreFault, ToCodeStdMappings)
    {
        // 逐个验证 std::errc 错误 → fault 错误映射
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_refused)),
                  Preview::Fault::Code::connection_refused);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_reset)),
                  Preview::Fault::Code::connection_reset);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::connection_aborted)),
                  Preview::Fault::Code::connection_aborted);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::timed_out)), Preview::Fault::Code::timeout);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::host_unreachable)),
                  Preview::Fault::Code::host_noreply);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::network_unreachable)),
                  Preview::Fault::Code::net_noreply);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::operation_canceled)),
                  Preview::Fault::Code::canceled);
    }

    TEST(CoreFault, ToCodeStdUnknown)
    {
        // 未映射的错误 → io_error
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::invalid_argument)),
                  Preview::Fault::Code::io_error);
        EXPECT_EQ(Preview::Fault::ToCode(std::make_error_code(std::errc::no_such_file_or_directory)),
                  Preview::Fault::Code::io_error);
    }
} // namespace
