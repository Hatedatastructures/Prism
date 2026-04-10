/**
 * @file DnsRules.cpp
 * @brief DNS 规则引擎测试
 * @details 测试以下 DNS 解析模块组件：
 * 1. domain_trie：反转域名基数树的精确匹配、通配符匹配和大小写不敏感特性
 * 2. rules_engine：规则引擎的地址规则、否定规则、CNAME 规则及优先级合并
 * 3. parse_port：端口号解析工具函数的边界值和异常输入处理
 * 4. transparent_hash / transparent_equal：透明哈希与跨类型相等比较器的确定性
 * @note 当前 wildcard 断言以仓库现实现行为为准：`*.example.com` 也会命中 `example.com`。
 */

#include <prism/resolve/rules.hpp>
#include <prism/resolve/utility.hpp>
#include <prism/resolve/transparent.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <any>
#include <cstdint>
#include <optional>
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
        psm::trace::info("[DnsRules] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[DnsRules] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[DnsRules] FAIL: {}", msg);
    }
}

// ---------------------------------------------------------------------------
// domain_trie 测试 (5)
// ---------------------------------------------------------------------------

/**
 * @brief 测试 domain_trie 精确匹配
 */
void TestTrieExactMatch()
{
    log_info("=== TestTrieExactMatch ===");

    psm::resolve::domain_trie trie;

    // 插入精确域名，绑定整数值 42
    trie.insert("example.com", 42);

    {
        // 查询已插入的域名，应返回绑定值
        auto result = trie.search("example.com");
        if (!result.has_value())
        {
            log_fail("search(\"example.com\") should return a value");
            return;
        }

        // 从 std::any 中还原实际类型
        auto val = std::any_cast<int>(result.value());
        if (val != 42)
        {
            log_fail("search(\"example.com\") should return 42");
            return;
        }
    }

    {
        // 查询未插入的域名，应返回空
        auto result = trie.search("other.com");
        if (result.has_value())
        {
            log_fail("search(\"other.com\") should return nullopt");
            return;
        }
    }

    log_pass("TestTrieExactMatch");
}

/**
 * @brief 测试 domain_trie 通配符匹配
 */
void TestTrieWildcardMatch()
{
    log_info("=== TestTrieWildcardMatch ===");

    psm::resolve::domain_trie trie;

    // 插入通配符规则，匹配所有 example.com 子域
    trie.insert("*.example.com", 100);

    {
        // www.example.com 是典型子域，应命中
        auto result = trie.search("www.example.com");
        if (!result.has_value())
        {
            log_fail("search(\"www.example.com\") should match *.example.com");
            return;
        }

        auto val = std::any_cast<int>(result.value());
        if (val != 100)
        {
            log_fail("search(\"www.example.com\") should return 100");
            return;
        }
    }

    {
        // 当前实现中 *.example.com 也命中裸域
        auto result = trie.search("example.com");
        if (!result.has_value())
        {
            log_fail("search(\"example.com\") should match *.example.com under current trie semantics");
            return;
        }

        auto val = std::any_cast<int>(result.value());
        if (val != 100)
        {
            log_fail("search(\"example.com\") should return 100");
            return;
        }
    }

    {
        // 多级子域 sub.example.com 也应命中
        auto result = trie.search("sub.example.com");
        if (!result.has_value())
        {
            log_fail("search(\"sub.example.com\") should match *.example.com");
            return;
        }

        auto val = std::any_cast<int>(result.value());
        if (val != 100)
        {
            log_fail("search(\"sub.example.com\") should return 100");
            return;
        }
    }

    log_pass("TestTrieWildcardMatch");
}

/**
 * @brief 测试 domain_trie 大小写不敏感
 */
void TestTrieCaseInsensitive()
{
    log_info("=== TestTrieCaseInsensitive ===");

    psm::resolve::domain_trie trie;

    // 以大写形式插入域名
    trie.insert("Example.COM", 77);

    {
        // 以全小写查询，应能匹配
        auto result = trie.search("example.com");
        if (!result.has_value())
        {
            log_fail("search(\"example.com\") should match inserted \"Example.COM\"");
            return;
        }

        auto val = std::any_cast<int>(result.value());
        if (val != 77)
        {
            log_fail("search(\"example.com\") should return 77");
            return;
        }
    }

    log_pass("TestTrieCaseInsensitive");
}

/**
 * @brief 测试 domain_trie 无匹配情况
 */
void TestTrieNoMatch()
{
    log_info("=== TestTrieNoMatch ===");

    // 空 trie 的查询应返回空
    {
        psm::resolve::domain_trie trie;

        auto result = trie.search("anything");
        if (result.has_value())
        {
            log_fail("search on empty trie should return nullopt");
            return;
        }
    }

    // 不同域名不应互相匹配
    {
        psm::resolve::domain_trie trie;
        trie.insert("a.com", 1);

        auto result = trie.search("b.com");
        if (result.has_value())
        {
            log_fail("search(\"b.com\") should return nullopt when only \"a.com\" is inserted");
            return;
        }
    }

    log_pass("TestTrieNoMatch");
}

/**
 * @brief 测试 domain_trie::match 布尔接口
 */
void TestTrieMatchBoolean()
{
    log_info("=== TestTrieMatchBoolean ===");

    psm::resolve::domain_trie trie;
    trie.insert("test.com", 99);

    // match() 只关心是否存在匹配，不返回值
    if (!trie.match("test.com"))
    {
        log_fail("match(\"test.com\") should return true");
        return;
    }

    // 未插入的域名应返回 false
    if (trie.match("other.com"))
    {
        log_fail("match(\"other.com\") should return false");
        return;
    }

    log_pass("TestTrieMatchBoolean");
}

// ---------------------------------------------------------------------------
// rules_engine 测试 (4)
// ---------------------------------------------------------------------------

/**
 * @brief 测试 rules_engine 地址规则
 */
void TestRulesAddressRule()
{
    log_info("=== TestRulesAddressRule ===");

    psm::resolve::rules_engine engine;

    // 为域名添加静态 IP 地址规则（DNS 劫持/静态解析）
    {
        namespace net = boost::asio;

        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("1.2.3.4"));

        engine.add_address_rule("blocked.com", ips);
    }

    {
        // 匹配后应返回预设的 IP 地址
        auto result = engine.match("blocked.com");
        if (!result.has_value())
        {
            log_fail("match(\"blocked.com\") should return a result");
            return;
        }

        if (result->addresses.empty())
        {
            log_fail("addresses should not be empty");
            return;
        }

        auto addr = result->addresses[0].to_string();
        if (addr != "1.2.3.4")
        {
            log_fail("addresses[0] should be \"1.2.3.4\", got " + addr);
            return;
        }
    }

    log_pass("TestRulesAddressRule");
}

/**
 * @brief 测试 rules_engine 否定规则
 */
void TestRulesNegativeRule()
{
    log_info("=== TestRulesNegativeRule ===");

    psm::resolve::rules_engine engine;

    // 添加否定规则（屏蔽/阻止域名）
    engine.add_negative_rule("evil.com");

    {
        auto result = engine.match("evil.com");
        if (!result.has_value())
        {
            log_fail("match(\"evil.com\") should return a result");
            return;
        }

        // blocked 标志应被置为 true
        if (!result->blocked)
        {
            log_fail("blocked should be true for negative rule");
            return;
        }
    }

    log_pass("TestRulesNegativeRule");
}

/**
 * @brief 测试 rules_engine CNAME 规则
 */
void TestRulesCnameRule()
{
    log_info("=== TestRulesCnameRule ===");

    psm::resolve::rules_engine engine;

    // 添加 CNAME 别名规则：alias.com → real.com
    engine.add_cname_rule("alias.com", "real.com");

    {
        auto result = engine.match("alias.com");
        if (!result.has_value())
        {
            log_fail("match(\"alias.com\") should return a result");
            return;
        }

        // 应返回 CNAME 目标域名
        if (result->cname != "real.com")
        {
            log_fail("cname should be \"real.com\"");
            return;
        }
    }

    log_pass("TestRulesCnameRule");
}

/**
 * @brief 测试 rules_engine 地址规则优先级高于 CNAME 规则
 */
void TestRulesCombinedPriority()
{
    log_info("=== TestRulesCombinedPriority ===");

    psm::resolve::rules_engine engine;

    // 先添加地址规则：test.com → 10.0.0.1
    {
        namespace net = boost::asio;

        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("10.0.0.1"));

        engine.add_address_rule("test.com", ips);
    }

    // 再添加 CNAME 规则：test.com → fallback.com
    engine.add_cname_rule("test.com", "fallback.com");

    {
        // 地址规则优先级更高，应返回地址而非 CNAME
        auto result = engine.match("test.com");
        if (!result.has_value())
        {
            log_fail("match(\"test.com\") should return a result");
            return;
        }

        if (result->addresses.empty())
        {
            log_fail("address rule should take priority — addresses should be non-empty");
            return;
        }
    }

    log_pass("TestRulesCombinedPriority");
}

// ---------------------------------------------------------------------------
// parse_port 测试 (3)
// ---------------------------------------------------------------------------

/**
 * @brief 测试 parse_port 合法输入
 */
void TestParsePortValid()
{
    log_info("=== TestParsePortValid ===");

    // HTTP 标准端口
    {
        auto r = psm::resolve::parse_port("80");
        if (!r || *r != 80)
        {
            log_fail("parse_port(\"80\") should return 80");
            return;
        }
    }

    // HTTPS 标准端口
    {
        auto r = psm::resolve::parse_port("443");
        if (!r || *r != 443)
        {
            log_fail("parse_port(\"443\") should return 443");
            return;
        }
    }

    // 端口 0（通常用于系统分配）
    {
        auto r = psm::resolve::parse_port("0");
        if (!r || *r != 0)
        {
            log_fail("parse_port(\"0\") should return 0");
            return;
        }
    }

    // 最大有效端口号
    {
        auto r = psm::resolve::parse_port("65535");
        if (!r || *r != 65535)
        {
            log_fail("parse_port(\"65535\") should return 65535");
            return;
        }
    }

    log_pass("TestParsePortValid");
}

/**
 * @brief 测试 parse_port 非法输入
 */
void TestParsePortInvalid()
{
    log_info("=== TestParsePortInvalid ===");

    // 空串不是有效端口号
    if (psm::resolve::parse_port("").has_value())
    {
        log_fail("parse_port(\"\") should return nullopt");
        return;
    }

    // 非数字字符
    if (psm::resolve::parse_port("abc").has_value())
    {
        log_fail("parse_port(\"abc\") should return nullopt");
        return;
    }

    // 超出 16 位范围（65535 + 1）
    if (psm::resolve::parse_port("65536").has_value())
    {
        log_fail("parse_port(\"65536\") should return nullopt");
        return;
    }

    // 负数
    if (psm::resolve::parse_port("-1").has_value())
    {
        log_fail("parse_port(\"-1\") should return nullopt");
        return;
    }

    // 超长数字（>5 位）
    if (psm::resolve::parse_port("123456").has_value())
    {
        log_fail("parse_port(\"123456\") should return nullopt (>5 chars)");
        return;
    }

    log_pass("TestParsePortInvalid");
}

/**
 * @brief 测试 parse_port 边界值
 */
void TestParsePortBoundary()
{
    log_info("=== TestParsePortBoundary ===");

    // 上边界：65535 是最大合法端口
    {
        auto r = psm::resolve::parse_port("65535");
        if (!r || *r != 65535)
        {
            log_fail("parse_port(\"65535\") should return 65535 (valid boundary)");
            return;
        }
    }

    // 越界：65536 不合法
    {
        auto r = psm::resolve::parse_port("65536");
        if (r.has_value())
        {
            log_fail("parse_port(\"65536\") should return nullopt (invalid boundary)");
            return;
        }
    }

    log_pass("TestParsePortBoundary");
}

// ---------------------------------------------------------------------------
// transparent_hash / transparent_equal 测试 (2)
// ---------------------------------------------------------------------------

/**
 * @brief 测试 transparent_hash 确定性
 */
void TestTransparentHashDeterminism()
{
    log_info("=== TestTransparentHashDeterminism ===");

    psm::resolve::transparent_hash h;

    // 相同内容多次哈希结果应一致
    auto v1 = h(std::string_view("test"));
    auto v2 = h(std::string_view("test"));

    if (v1 != v2)
    {
        log_fail("hash(string_view) should be deterministic across calls");
        return;
    }

    // 跨类型哈希：string_view 与 memory::string 结果应相同
    psm::memory::string ms("test");
    auto v3 = h(ms);

    if (v1 != v3)
    {
        log_fail("hash(string_view) should equal hash(memory::string) for same content");
        return;
    }

    log_pass("TestTransparentHashDeterminism");
}

/**
 * @brief 测试 transparent_equal 跨类型比较
 */
void TestTransparentEqualCrossType()
{
    log_info("=== TestTransparentEqualCrossType ===");

    psm::resolve::transparent_equal eq;

    std::string_view sv("hello");
    psm::memory::string ms("hello");

    // 同类型 string_view 比较
    if (!eq(sv, sv))
    {
        log_fail("eq(string_view, string_view) should be true");
        return;
    }

    // memory::string 与 string_view 交叉比较
    if (!eq(ms, sv))
    {
        log_fail("eq(memory::string, string_view) should be true");
        return;
    }

    // 反向交叉比较
    if (!eq(sv, ms))
    {
        log_fail("eq(string_view, memory::string) should be true");
        return;
    }

    // 同类型 memory::string 比较
    if (!eq(ms, ms))
    {
        log_fail("eq(memory::string, memory::string) should be true");
        return;
    }

    // 不同内容应返回 false
    if (eq(sv, std::string_view("world")))
    {
        log_fail("eq(\"hello\", \"world\") should be false");
        return;
    }

    log_pass("TestTransparentEqualCrossType");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 domain_trie（精确/通配符/大小写不敏感匹配）、
 * rules_engine（地址/否定/CNAME 规则及优先级合并）、parse_port 边界值、
 * transparent_hash/transparent_equal 确定性等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    log_info("Starting DNS rules tests...");

    // domain_trie
    TestTrieExactMatch();
    TestTrieWildcardMatch();
    TestTrieCaseInsensitive();
    TestTrieNoMatch();
    TestTrieMatchBoolean();

    // rules_engine
    TestRulesAddressRule();
    TestRulesNegativeRule();
    TestRulesCnameRule();
    TestRulesCombinedPriority();

    // parse_port
    TestParsePortValid();
    TestParsePortInvalid();
    TestParsePortBoundary();

    // transparent_hash / transparent_equal
    TestTransparentHashDeterminism();
    TestTransparentEqualCrossType();

    log_info("DNS rules tests completed.");

    psm::trace::info("[DnsRules] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
