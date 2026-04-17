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

#include <prism/fault/code.hpp>
#include <prism/fault/compatible.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/test_runner.hpp"

#include <string>
#include <string_view>
#include <system_error>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

namespace
{
    psm::testing::TestRunner runner("FaultTest");
}

/**
 * @brief 测试所有错误码描述字符串
 */
void TestDescribeAllCodes()
{
    runner.LogInfo("=== Testing describe() for all codes ===");

    // 遍历全部错误码，确保每个都有非空描述
    constexpr int count = static_cast<int>(psm::fault::code::_count);
    for (int i = 0; i < count; ++i)
    {
        const auto c = static_cast<psm::fault::code>(i);
        const std::string_view desc = psm::fault::describe(c);
        if (desc.empty())
        {
            runner.LogFail(std::format("describe(code={}) returned empty string", i));
            return;
        }
    }

    // success 码：代表操作成功的唯一正例
    if (psm::fault::describe(psm::fault::code::success) != "success")
    {
        runner.LogFail("describe(success) != 'success'");
        return;
    }

    // eof 码：代表连接正常关闭（对端 EOF）
    if (psm::fault::describe(psm::fault::code::eof) != "eof")
    {
        runner.LogFail("describe(eof) != 'eof'");
        return;
    }

    // timeout 码：代表异步操作超时
    if (psm::fault::describe(psm::fault::code::timeout) != "timeout")
    {
        runner.LogFail("describe(timeout) != 'timeout'");
        return;
    }

    runner.LogPass("describe() for all codes");
}

/**
 * @brief 测试 succeeded/failed 语义
 */
void TestSucceededFailed()
{
    runner.LogInfo("=== Testing succeeded/failed semantics ===");

    // success 是唯一使 succeeded 返回 true 的码
    if (!psm::fault::succeeded(psm::fault::code::success))
    {
        runner.LogFail("succeeded(success) should be true");
        return;
    }
    // success 不应被视为失败
    if (psm::fault::failed(psm::fault::code::success))
    {
        runner.LogFail("failed(success) should be false");
        return;
    }

    // eof 属于失败码，表示非正常结束
    if (psm::fault::succeeded(psm::fault::code::eof))
    {
        runner.LogFail("succeeded(eof) should be false");
        return;
    }
    if (!psm::fault::failed(psm::fault::code::eof))
    {
        runner.LogFail("failed(eof) should be true");
        return;
    }

    // parse_error 属于失败码，表示协议解析出错
    if (psm::fault::succeeded(psm::fault::code::parse_error))
    {
        runner.LogFail("succeeded(parse_error) should be false");
        return;
    }
    if (!psm::fault::failed(psm::fault::code::parse_error))
    {
        runner.LogFail("failed(parse_error) should be true");
        return;
    }

    runner.LogPass("succeeded/failed semantics");
}

/**
 * @brief 测试 cached_message 与 describe 一致性
 */
void TestCachedMessageConsistency()
{
    runner.LogInfo("=== Testing cached_message consistency ===");

    // 确保缓存版本与实时描述完全一致
    constexpr int count = static_cast<int>(psm::fault::code::_count);
    for (int i = 0; i < count; ++i)
    {
        const auto c = static_cast<psm::fault::code>(i);
        const std::string_view desc = psm::fault::describe(c);
        const std::string &cached = psm::fault::cached_message(c);

        if (desc != cached)
        {
            runner.LogFail(std::format("cached_message(code={})='{}' != describe()='{}'", i, cached, desc));
            return;
        }
    }

    runner.LogPass("cached_message consistency");
}

/**
 * @brief 测试 std::error_code 构造与隐式转换
 */
void TestMakeErrorCodeStd()
{
    runner.LogInfo("=== Testing std::error_code construction ===");

    // 显式构造：eof 的数值应为 3，类别名为 psm::fault
    const std::error_code ec = psm::fault::make_error_code(psm::fault::code::eof);
    if (ec.value() != 3)
    {
        runner.LogFail(std::format("make_error_code(eof).value()={}, expected 3", ec.value()));
        return;
    }
    if (std::string_view(ec.category().name()) != "psm::fault")
    {
        runner.LogFail(std::format("category name='{}', expected 'psm::fault'", ec.category().name()));
        return;
    }

    // 隐式转换：code 枚举应能直接赋值给 std::error_code
    const std::error_code ec2 = psm::fault::code::timeout;
    if (ec2.value() != 11)
    {
        runner.LogFail(std::format("implicit conversion: timeout value={}, expected 11", ec2.value()));
        return;
    }

    runner.LogPass("std::error_code construction");
}

/**
 * @brief 测试 boost::system::error_code 构造
 */
void TestMakeErrorCodeBoost()
{
    runner.LogInfo("=== Testing boost::system::error_code construction ===");

    // 验证 Boost 错误码的数值和类别与 std 版本一致
    const boost::system::error_code ec = boost::system::make_error_code(psm::fault::code::eof);
    if (ec.value() != 3)
    {
        runner.LogFail(std::format("boost make_error_code(eof).value()={}, expected 3", ec.value()));
        return;
    }
    if (std::string_view(ec.category().name()) != "psm::fault")
    {
        runner.LogFail(std::format("boost category name='{}', expected 'psm::fault'", ec.category().name()));
        return;
    }

    runner.LogPass("boost::system::error_code construction");
}

/**
 * @brief 测试 boost 错误码双向转换
 */
void TestToCodeBoostRoundTrip()
{
    runner.LogInfo("=== Testing to_code boost round trip ===");

    // 正向+反向转换：code -> boost ec -> 还原为 code
    const psm::fault::code c = psm::fault::code::timeout;
    const boost::system::error_code ec = boost::system::make_error_code(c);
    const psm::fault::code back = psm::fault::to_code(ec);
    if (back != psm::fault::code::timeout)
    {
        runner.LogFail(std::format("boost round trip: expected timeout, got {}", static_cast<int>(back)));
        return;
    }

    // 将 asio::eof 映射为 fault::eof，统一 EOF 语义
    const psm::fault::code eof_code = psm::fault::to_code(boost::asio::error::eof);
    if (eof_code != psm::fault::code::eof)
    {
        runner.LogFail(std::format("asio::eof -> code={}, expected eof({})", static_cast<int>(eof_code),
                             static_cast<int>(psm::fault::code::eof)));
        return;
    }

    // 将 asio::operation_aborted 映射为 fault::canceled
    const psm::fault::code abort_code = psm::fault::to_code(boost::asio::error::operation_aborted);
    if (abort_code != psm::fault::code::canceled)
    {
        runner.LogFail(std::format("asio::operation_aborted -> code={}, expected canceled({})",
                             static_cast<int>(abort_code), static_cast<int>(psm::fault::code::canceled)));
        return;
    }

    runner.LogPass("to_code boost round trip");
}

/**
 * @brief 测试 std 错误码双向转换
 */
void TestToCodeStdRoundTrip()
{
    runner.LogInfo("=== Testing to_code std round trip ===");

    // 正向+反向转换：code -> std ec -> 还原为 code
    const psm::fault::code c = psm::fault::code::connection_refused;
    const std::error_code ec = psm::fault::make_error_code(c);
    const psm::fault::code back = psm::fault::to_code(ec);
    if (back != psm::fault::code::connection_refused)
    {
        runner.LogFail(std::format("std round trip: expected connection_refused, got {}", static_cast<int>(back)));
        return;
    }

    // 将 std 超时错误映射为 fault::timeout
    const psm::fault::code timeout_code = psm::fault::to_code(std::make_error_code(std::errc::timed_out));
    if (timeout_code != psm::fault::code::timeout)
    {
        runner.LogFail(std::format("errc::timed_out -> code={}, expected timeout({})", static_cast<int>(timeout_code),
                             static_cast<int>(psm::fault::code::timeout)));
        return;
    }

    // 将 std 取消错误映射为 fault::canceled
    const psm::fault::code cancel_code = psm::fault::to_code(std::make_error_code(std::errc::operation_canceled));
    if (cancel_code != psm::fault::code::canceled)
    {
        runner.LogFail(std::format("errc::operation_canceled -> code={}, expected canceled({})",
                             static_cast<int>(cancel_code), static_cast<int>(psm::fault::code::canceled)));
        return;
    }

    runner.LogPass("to_code std round trip");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行错误码描述、succeeded/failed 语义、
 * cached_message 一致性、std/boost error_code 构造及双向转换等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池，热路径容器依赖此调用
    psm::memory::system::enable_global_pooling();
    // 使用默认配置初始化 spdlog 日志系统
    psm::trace::init({});

    runner.LogInfo("Starting fault tests...");

    TestDescribeAllCodes();
    TestSucceededFailed();
    TestCachedMessageConsistency();
    TestMakeErrorCodeStd();
    TestMakeErrorCodeBoost();
    TestToCodeBoostRoundTrip();
    TestToCodeStdRoundTrip();

    runner.LogInfo("Fault tests completed.");

    return runner.Summary();
}
