/**
 * @file Exception.cpp
 * @brief 异常体系单元测试
 * @details 验证 psm::exception 模块的核心功能，包括：
 * 1. 基于错误码构造异常
 * 2. 基于字符串构造异常
 * 3. 格式化构造异常
 * 4. 源码位置捕获
 * 5. dump() 格式化输出
 * 6. 派生类类型标识 (network/protocol/security)
 */

#include <prism/exception.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <string>
#include <string_view>

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    void log_info(const std::string_view msg)
    {
        psm::trace::info("[ExceptionTest] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[ExceptionTest] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[ExceptionTest] FAIL: {}", msg);
    }

    /**
     * @brief 在字符串中查找子串
     * @param haystack 被搜索的字符串
     * @param needle 要查找的子串
     * @return 找到返回 true，否则返回 false
     */
    bool contains(const std::string &haystack, const std::string_view needle)
    {
        return haystack.find(needle) != std::string::npos;
    }
}

/**
 * @brief 测试基于错误码构造异常
 */
void TestDeviantConstructWithCode()
{
    log_info("=== Testing construct with error code ===");

    // network 继承自 deviant，表示网络层异常
    try
    {
        throw psm::exception::network(psm::fault::code::eof);
    }
    catch (const psm::exception::network &ex)
    {
        // 验证错误码值被正确保留（eof = 3）
        if (ex.error_code().value() != 3)
        {
            log_fail(std::format("error_code().value()={}, expected 3", ex.error_code().value()));
            return;
        }

        // 验证 what() 消息中包含错误码描述
        const std::string what = ex.what();
        if (!contains(what, "eof"))
        {
            log_fail(std::format("what()='{}' does not contain 'eof'", what));
            return;
        }

        log_pass("construct with error code");
        return;
    }

    log_fail("exception not caught as network");
}

/**
 * @brief 测试基于字符串构造异常
 */
void TestDeviantConstructWithString()
{
    log_info("=== Testing construct with string ===");

    // 使用字符串消息构造时，错误码默认为 generic_error
    try
    {
        throw psm::exception::network("test error message");
    }
    catch (const psm::exception::network &ex)
    {
        const std::string what = ex.what();
        if (!contains(what, "test error message"))
        {
            log_fail(std::format("what()='{}' does not contain 'test error message'", what));
            return;
        }

        // 未指定错误码时应回退到 generic_error
        const int expected_value = static_cast<int>(psm::fault::code::generic_error);
        if (ex.error_code().value() != expected_value)
        {
            log_fail(std::format("error_code().value()={}, expected {} (generic_error)",
                                 ex.error_code().value(), expected_value));
            return;
        }

        log_pass("construct with string");
        return;
    }

    log_fail("exception not caught as network");
}

/**
 * @brief 测试格式化构造异常
 */
void TestDeviantConstructFormatted()
{
    log_info("=== Testing construct with format string ===");

    // 验证格式化参数被正确替换到消息中
    try
    {
        throw psm::exception::network("formatted msg {}", 42);
    }
    catch (const psm::exception::network &ex)
    {
        const std::string what = ex.what();
        if (!contains(what, "formatted msg 42"))
        {
            log_fail(std::format("what()='{}' does not contain 'formatted msg 42'", what));
            return;
        }

        log_pass("construct with format string");
        return;
    }

    log_fail("exception not caught as network");
}

/**
 * @brief 测试源码位置捕获
 */
void TestDeviantLocation()
{
    log_info("=== Testing source location capture ===");

    // 异常自动捕获 throw 语句的源码位置
    try
    {
        throw psm::exception::network(psm::fault::code::eof);
    }
    catch (const psm::exception::network &ex)
    {
        const auto &loc = ex.location();

        // 文件名不应为空，表明 source_location 生效
        if (!loc.file_name() || std::string_view(loc.file_name()).empty())
        {
            log_fail("location().file_name() is empty");
            return;
        }

        // filename() 应返回纯文件名，不含目录分隔符
        const std::string fname = ex.filename();
        if (fname.find('/') != std::string::npos || fname.find('\\') != std::string::npos)
        {
            log_fail(std::format("filename()='{}' contains directory separators", fname));
            return;
        }
        if (fname.find("Exception") == std::string::npos)
        {
            log_fail(std::format("filename()='{}' does not contain 'Exception'", fname));
            return;
        }

        // 行号必须大于 0，证明捕获了真实源码位置
        if (loc.line() <= 0)
        {
            log_fail(std::format("location().line()={}, expected > 0", loc.line()));
            return;
        }

        log_pass("source location capture");
        return;
    }

    log_fail("exception not caught as network");
}

/**
 * @brief 测试 dump() 格式化输出
 */
void TestDeviantDump()
{
    log_info("=== Testing dump() output ===");

    // protocol 继承自 deviant，表示协议层异常
    try
    {
        throw psm::exception::protocol(psm::fault::code::parse_error, "bad request");
    }
    catch (const psm::exception::protocol &ex)
    {
        const std::string dump = ex.dump();

        // dump 应包含类型名称 "PROTOCOL"
        if (!contains(dump, "PROTOCOL"))
        {
            log_fail(std::format("dump()='{}' does not contain 'PROTOCOL'", dump));
            return;
        }

        // parse_error 的枚举值为 2，dump 中应体现
        if (!contains(dump, "2"))
        {
            log_fail(std::format("dump()='{}' does not contain '2' (parse_error value)", dump));
            return;
        }

        // 用户附加的描述信息应出现在 dump 输出中
        if (!contains(dump, "bad request"))
        {
            log_fail(std::format("dump()='{}' does not contain 'bad request'", dump));
            return;
        }

        // dump 格式应为 [filename:line] [TYPE:value] description
        if (!contains(dump, "[") || !contains(dump, "]"))
        {
            log_fail(std::format("dump()='{}' does not match expected format", dump));
            return;
        }

        log_pass("dump() output");
        return;
    }

    log_fail("exception not caught as protocol");
}

/**
 * @brief 测试派生类类型标识
 */
void TestDerivedTypes()
{
    log_info("=== Testing derived type names ===");

    // network：继承自 deviant，代表网络 I/O 层异常
    {
        try
        {
            throw psm::exception::network(psm::fault::code::eof);
        }
        catch (const psm::exception::network &ex)
        {
            const std::string dump = ex.dump();
            if (!contains(dump, "NETWORK"))
            {
                log_fail(std::format("network dump()='{}' does not contain 'NETWORK'", dump));
                return;
            }
        }
    }

    // protocol：继承自 deviant，代表协议解析异常
    {
        try
        {
            throw psm::exception::protocol(psm::fault::code::parse_error);
        }
        catch (const psm::exception::protocol &ex)
        {
            const std::string dump = ex.dump();
            if (!contains(dump, "PROTOCOL"))
            {
                log_fail(std::format("protocol dump()='{}' does not contain 'PROTOCOL'", dump));
                return;
            }
        }
    }

    // security：继承自 deviant，代表认证/安全层异常
    {
        try
        {
            throw psm::exception::security(psm::fault::code::auth_failed);
        }
        catch (const psm::exception::security &ex)
        {
            const std::string dump = ex.dump();
            if (!contains(dump, "SECURITY"))
            {
                log_fail(std::format("security dump()='{}' does not contain 'SECURITY'", dump));
                return;
            }
        }
    }

    log_pass("derived type names");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行异常构造（错误码/字符串/格式化）、
 * 源码位置捕获、dump() 格式化输出及派生类类型标识（network/protocol/security）等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    log_info("Starting exception tests...");

    TestDeviantConstructWithCode();
    TestDeviantConstructWithString();
    TestDeviantConstructFormatted();
    TestDeviantLocation();
    TestDeviantDump();
    TestDerivedTypes();

    log_info("Exception tests completed.");

    psm::trace::info("[ExceptionTest] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
