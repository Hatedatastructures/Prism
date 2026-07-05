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

#include <prism/foundation/foundation.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace
{
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

    TEST(Exception, DeviantConstructWithCode)
    {
        // network 继承自 deviant，表示网络层异常
        try
        {
            throw psm::exception::network(psm::fault::code::eof);
        }
        catch (const psm::exception::network &ex)
        {
            // 验证错误码值被正确保留（eof = 3）
            ASSERT_TRUE(ex.error_code().value() == 3)
                << "error_code().value()=" << ex.error_code().value() << ", expected 3";

            // 验证 what() 消息中包含错误码描述
            const std::string what = ex.what();
            ASSERT_TRUE(contains(what, "eof"))
                << "what()='" << what << "' does not contain 'eof'";

            return;
        }

        FAIL() << "exception not caught as network";
    }

    TEST(Exception, DeviantConstructWithString)
    {
        // 使用字符串消息构造时，错误码默认为 generic_error
        try
        {
            throw psm::exception::network("test error message");
        }
        catch (const psm::exception::network &ex)
        {
            const std::string what = ex.what();
            ASSERT_TRUE(contains(what, "test error message"))
                << "what()='" << what << "' does not contain 'test error message'";

            // 未指定错误码时应回退到 generic_error
            const int expected_value = static_cast<int>(psm::fault::code::generic_error);
            ASSERT_TRUE(ex.error_code().value() == expected_value)
                << "error_code().value()=" << ex.error_code().value() << ", expected " << expected_value << " (generic_error)";

            return;
        }

        FAIL() << "exception not caught as network";
    }

    TEST(Exception, DeviantConstructFormatted)
    {
        // 验证格式化参数被正确替换到消息中
        try
        {
            throw psm::exception::network("formatted msg {}", 42);
        }
        catch (const psm::exception::network &ex)
        {
            const std::string what = ex.what();
            ASSERT_TRUE(contains(what, "formatted msg 42"))
                << "what()='" << what << "' does not contain 'formatted msg 42'";

            return;
        }

        FAIL() << "exception not caught as network";
    }

    TEST(Exception, DeviantLocation)
    {
        // 异常自动捕获 throw 语句的源码位置
        try
        {
            throw psm::exception::network(psm::fault::code::eof);
        }
        catch (const psm::exception::network &ex)
        {
            const auto &loc = ex.location();

            // 文件名不应为空，表明 source_location 生效
            ASSERT_TRUE(loc.file_name() && !std::string_view(loc.file_name()).empty())
                << "location().file_name() is empty";

            // filename() 应返回纯文件名，不含目录分隔符
            const std::string fname = ex.filename();
            ASSERT_TRUE(fname.find('/') == std::string::npos && fname.find('\\') == std::string::npos)
                << "filename()='" << fname << "' contains directory separators";
            ASSERT_TRUE(fname.find("Exception") != std::string::npos)
                << "filename()='" << fname << "' does not contain 'Exception'";

            // 行号必须大于 0，证明捕获了真实源码位置
            ASSERT_TRUE(loc.line() > 0)
                << "location().line()=" << loc.line() << ", expected > 0";

            return;
        }

        FAIL() << "exception not caught as network";
    }

    TEST(Exception, DeviantDump)
    {
        // protocol 继承自 deviant，表示协议层异常
        try
        {
            throw psm::exception::protocol(psm::fault::code::parse_error, "bad request");
        }
        catch (const psm::exception::protocol &ex)
        {
            const std::string dump = ex.dump();

            // dump 应包含类型名称 "PROTOCOL"
            ASSERT_TRUE(contains(dump, "PROTOCOL"))
                << "dump()='" << dump << "' does not contain 'PROTOCOL'";

            // parse_error 的枚举值为 2，dump 中应体现
            ASSERT_TRUE(contains(dump, "2"))
                << "dump()='" << dump << "' does not contain '2' (parse_error value)";

            // 用户附加的描述信息应出现在 dump 输出中
            ASSERT_TRUE(contains(dump, "bad request"))
                << "dump()='" << dump << "' does not contain 'bad request'";

            // dump 格式应为 [filename:line] [TYPE:value] description
            ASSERT_TRUE(contains(dump, "[") && contains(dump, "]"))
                << "dump()='" << dump << "' does not match expected format";

            return;
        }

        FAIL() << "exception not caught as protocol";
    }

    TEST(Exception, DerivedTypes)
    {
        // network：继承自 deviant，代表网络 I/O 层异常
        {
            try
            {
                throw psm::exception::network(psm::fault::code::eof);
            }
            catch (const psm::exception::network &ex)
            {
                const std::string dump = ex.dump();
                ASSERT_TRUE(contains(dump, "NETWORK"))
                    << "network dump()='" << dump << "' does not contain 'NETWORK'";
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
                ASSERT_TRUE(contains(dump, "PROTOCOL"))
                    << "protocol dump()='" << dump << "' does not contain 'PROTOCOL'";
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
                ASSERT_TRUE(contains(dump, "SECURITY"))
                    << "security dump()='" << dump << "' does not contain 'SECURITY'";
            }
        }
    }
} // namespace
