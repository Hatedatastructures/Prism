/**
 * @file AnytlsScheme.cpp
 * @brief AnyTLS 方案纯函数单元测试
 * @details 通过 #include 源文件直接测试 anonymous namespace 中的
 *          parse_socks_target、build_user_map、verify_user 纯函数，
 *          以及公开接口 name/tier/unique/category。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/config.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 拉入源文件中 anonymous namespace 的函数定义
// 注意：必须在所有头文件之后 include
// anonymous namespace 函数在 psm::stealth::anytls 命名空间中可见
#include "../src/prism/stealth/stack/anytls/scheme.cpp"

using namespace psm::stealth::anytls;

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief 测试 parse_socks_target 解析 IPv4 地址
     * @details 构造 atyp=0x01 的 SOCKS5 目标地址帧，
     *          包含 4 字节 IPv4 地址 127.0.0.1 和 2 字节端口 80。
     */
    void TestParseSocksTargetIPv4(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x01}); // atyp IPv4
        buf.push_back(std::byte{127});  // 127.0.0.1
        buf.push_back(std::byte{0});
        buf.push_back(std::byte{0});
        buf.push_back(std::byte{1});
        buf.push_back(std::byte{0});    // port 80 (big-endian)
        buf.push_back(std::byte{80});

        auto [ec, target] = parse_socks_target(buf, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success,
                     "parse_socks_target: IPv4 成功");
        runner.Check(target.host == "127.0.0.1",
                     "parse_socks_target: IPv4 地址正确");
        runner.Check(target.port == "80",
                     "parse_socks_target: IPv4 端口正确");
    }

    /**
     * @brief 测试 parse_socks_target 解析域名地址
     * @details 构造 atyp=0x03 的 SOCKS5 目标地址帧，
     *          包含 1 字节长度 + 域名 "example.com" + 2 字节端口 443。
     */
    void TestParseSocksTargetDomain(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x03}); // atyp domain
        buf.push_back(std::byte{11});   // length
        for (auto c : std::string_view("example.com"))
        {
            buf.push_back(std::byte(static_cast<unsigned char>(c)));
        }
        buf.push_back(std::byte{0x01}); // port 443 (big-endian)
        buf.push_back(std::byte{0xBB});

        auto [ec, target] = parse_socks_target(buf, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success,
                     "parse_socks_target: domain 成功");
        runner.Check(target.host == "example.com",
                     "parse_socks_target: domain 地址正确");
        runner.Check(target.port == "443",
                     "parse_socks_target: domain 端口正确");
    }

    /**
     * @brief 测试 parse_socks_target 解析 IPv6 地址
     * @details 构造 atyp=0x04 的 SOCKS5 目标地址帧，
     *          包含 16 字节 IPv6 地址 ::1 和 2 字节端口 443。
     */
    void TestParseSocksTargetIPv6(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x04}); // atyp IPv6
        // ::1 — 前 15 字节全零，最后一字节为 1
        for (int i = 0; i < 15; ++i)
        {
            buf.push_back(std::byte{0});
        }
        buf.push_back(std::byte{1});
        buf.push_back(std::byte{0x01}); // port 443 (big-endian)
        buf.push_back(std::byte{0xBB});

        auto [ec, target] = parse_socks_target(buf, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success,
                     "parse_socks_target: IPv6 成功");
        runner.Check(target.port == "443",
                     "parse_socks_target: IPv6 端口正确");
    }

    /**
     * @brief 测试 parse_socks_target 处理空输入
     * @details 传入空 span，应返回 bad_message 错误码。
     */
    void TestParseSocksTargetEmpty(TestRunner &runner)
    {
        std::span<const std::byte> empty_span;
        auto [ec, target] = parse_socks_target(empty_span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::bad_message,
                     "parse_socks_target: 空输入 → bad_message");
    }

    /**
     * @brief 测试 parse_socks_target 处理无效 atyp
     * @details 传入 atyp=0x05（不在 0x01/0x03/0x04 范围内），
     *          应返回 bad_message 错误码。
     */
    void TestParseSocksTargetInvalidAtyp(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x05}); // 无效 atyp
        buf.push_back(std::byte{0});
        buf.push_back(std::byte{0});

        auto [ec, target] = parse_socks_target(buf, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::bad_message,
                     "parse_socks_target: 无效 atyp → bad_message");
    }

    /**
     * @brief 测试 parse_socks_target 处理截断的 IPv4 数据
     * @details 传入 atyp=0x01 但后续数据不足 4 字节 + 2 字节端口，
     *          应返回错误码。
     */
    void TestParseSocksTargetTruncatedIPv4(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x01}); // atyp IPv4
        buf.push_back(std::byte{127});  // 仅 2 字节，不足 4+2
        buf.push_back(std::byte{0});

        auto [ec, target] = parse_socks_target(buf, psm::memory::current_resource());
        runner.Check(psm::fault::failed(ec),
                     "parse_socks_target: 截断 IPv4 → 失败");
    }

    /**
     * @brief 测试 build_user_map 构建 SHA256 密码映射
     * @details 创建用户列表，验证 build_user_map 返回的映射表
     *          包含正确的 SHA256(password) → username 条目。
     */
    void TestBuildUserMap(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::anytls::user> users(mr);
        users.push_back({.username = psm::memory::string("alice", mr),
                         .password = psm::memory::string("pass123", mr)});
        users.push_back({.username = psm::memory::string("bob", mr),
                         .password = psm::memory::string("secret", mr)});

        auto map = build_user_map(users);
        runner.Check(map.size() == 2,
                     "build_user_map: 包含 2 个条目");

        // 手动计算 SHA256("pass123") 查找 alice
        std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
        const char *pw = "pass123";
        SHA256(reinterpret_cast<const std::uint8_t *>(pw),
               std::strlen(pw), digest.data());
        auto it = map.find(digest);
        runner.Check(it != map.end(),
                     "build_user_map: 找到 alice 的密码哈希");
        runner.Check(it->second == "alice",
                     "build_user_map: alice 用户名匹配");
    }

    /**
     * @brief 测试 verify_user 验证正确的密码哈希
     * @details 构造匹配用户密码的 auth_frame，验证返回非空用户名指针。
     */
    void TestVerifyUserValid(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::anytls::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("mypassword", mr)});

        // 计算 SHA256("mypassword") 填入 auth_frame
        auth_frame frame;
        const char *pw = "mypassword";
        SHA256(reinterpret_cast<const std::uint8_t *>(pw),
               std::strlen(pw),
               reinterpret_cast<std::uint8_t *>(frame.password_hash.data()));

        auto result = verify_user(frame, users);
        runner.Check(result != nullptr,
                     "verify_user: 正确密码 → 非 nullptr");
        runner.Check(*result == "admin",
                     "verify_user: 返回 admin 用户名");
    }

    /**
     * @brief 测试 verify_user 验证错误的密码哈希
     * @details 构造不匹配任何用户的 auth_frame，验证返回 nullptr。
     */
    void TestVerifyUserInvalid(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::anytls::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("mypassword", mr)});

        // 构造错误的密码哈希
        auth_frame frame;
        const char *pw = "wrongpassword";
        SHA256(reinterpret_cast<const std::uint8_t *>(pw),
               std::strlen(pw),
               reinterpret_cast<std::uint8_t *>(frame.password_hash.data()));

        auto result = verify_user(frame, users);
        runner.Check(result == nullptr,
                     "verify_user: 错误密码 → nullptr");
    }

    /**
     * @brief 测试 scheme 的元数据接口
     * @details 验证 name()、tier()、unique()、category() 返回值。
     */
    void TestSchemeMetadata(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        runner.Check(s.name() == std::string_view{"anytls"},
                     "scheme: name=anytls");
        runner.Check(s.tier() == 2,
                     "scheme: tier=2");
        runner.Check(s.unique() == false,
                     "scheme: unique=false");
        runner.Check(s.category() == psm::stealth::scheme_category::stack,
                     "scheme: category=stack");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsScheme");

    TestParseSocksTargetIPv4(runner);
    TestParseSocksTargetDomain(runner);
    TestParseSocksTargetIPv6(runner);
    TestParseSocksTargetEmpty(runner);
    TestParseSocksTargetInvalidAtyp(runner);
    TestParseSocksTargetTruncatedIPv4(runner);
    TestBuildUserMap(runner);
    TestVerifyUserValid(runner);
    TestVerifyUserInvalid(runner);
    TestSchemeMetadata(runner);

    return runner.Summary();
}
