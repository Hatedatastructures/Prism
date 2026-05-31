/**
 * @file AnytlsSchemeDeep.cpp
 * @brief AnyTLS scheme 深度测试
 * @details 测试 anytls/scheme.cpp 中匿名命名空间的纯函数：
 *          parse_socks_target（IPv4/IPv6/域名/空/无效类型）、
 *          build_user_map、verify_user、sha256_hash。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/stealth/stack/anytls/scheme.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::stealth::anytls;

    // ─── parse_socks_target: IPv4 ───────────────────

    void TestParseSocksTargetIPv4(TestRunner &runner)
    {
        // atyp(1) + ipv4(4) + port(2) = 7 bytes
        std::array<std::uint8_t, 7> buf{};
        buf[0] = 0x01; // IPv4
        buf[1] = 127; buf[2] = 0; buf[3] = 0; buf[4] = 1;
        buf[5] = 0x00; buf[6] = 0x50; // port 80

        auto span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buf.data()), buf.size());

        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success, "parse_socks ipv4: success");
        runner.Check(target.host == "127.0.0.1", "parse_socks ipv4: host");
        runner.Check(target.port == "80", "parse_socks ipv4: port");
    }

    void TestParseSocksTargetIPv4BadPort(TestRunner &runner)
    {
        std::array<std::uint8_t, 5> buf{};
        buf[0] = 0x01;
        buf[1] = 127; buf[2] = 0; buf[3] = 0; buf[4] = 1;
        // 缺少 port

        auto span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buf.data()), buf.size());

        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec != psm::fault::code::success, "parse_socks ipv4: no port → error");
    }

    // ─── parse_socks_target: IPv6 ───────────────────

    void TestParseSocksTargetIPv6(TestRunner &runner)
    {
        // atyp(1) + ipv6(16) + port(2) = 19 bytes
        std::array<std::uint8_t, 19> buf{};
        buf[0] = 0x04; // IPv6
        // ::1
        buf[15] = 0x01; // last byte of IPv6 = ::1
        buf[17] = 0x00; buf[18] = 0x50; // port 80

        auto span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buf.data()), buf.size());

        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success, "parse_socks ipv6: success");
        runner.Check(target.port == "80", "parse_socks ipv6: port");
    }

    // ─── parse_socks_target: Domain ─────────────────

    void TestParseSocksTargetDomain(TestRunner &runner)
    {
        const char *domain = "example.com";
        auto dlen = static_cast<std::uint8_t>(std::string_view(domain).size());

        // atyp(1) + len(1) + domain(11) + port(2) = 15 bytes
        psm::memory::vector<std::uint8_t> buf(psm::memory::current_resource());
        buf.push_back(0x03); // Domain
        buf.push_back(dlen);
        for (auto c : std::string_view(domain)) buf.push_back(static_cast<std::uint8_t>(c));
        buf.push_back(0x00); buf.push_back(0x50); // port 80

        auto span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buf.data()), buf.size());

        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::success, "parse_socks domain: success");
        runner.Check(target.host == "example.com", "parse_socks domain: host");
        runner.Check(target.port == "80", "parse_socks domain: port");
    }

    // ─── parse_socks_target: 空输入 ─────────────────

    void TestParseSocksTargetEmpty(TestRunner &runner)
    {
        auto span = std::span<const std::byte>();
        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::bad_message, "parse_socks: empty → bad_message");
    }

    // ─── parse_socks_target: 无效 atyp ───────────────

    void TestParseSocksTargetBadAtyp(TestRunner &runner)
    {
        std::array<std::uint8_t, 4> buf{};
        buf[0] = 0x05; // 无效地址类型

        auto span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buf.data()), buf.size());

        auto [ec, target] = parse_socks_target(span, psm::memory::current_resource());
        runner.Check(ec == psm::fault::code::bad_message, "parse_socks: bad atyp → bad_message");
    }

    // ─── build_user_map / verify_user ───────────────

    void TestBuildUserMapAndVerify(TestRunner &runner)
    {
        psm::memory::vector<user> users(psm::memory::current_resource());
        user u;
        u.username = "testuser";
        u.password = "testpassword";
        users.push_back(u);

        auto map = build_user_map(users);
        runner.Check(map.size() == 1, "user_map: size=1");

        // 构造正确的 auth_frame
        auth_frame frame{};
        std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
        SHA256(reinterpret_cast<const std::uint8_t *>(u.password.data()),
               u.password.size(), digest.data());
        std::memcpy(frame.password_hash.data(), digest.data(), 32);

        auto result = verify_user(frame, users);
        runner.Check(result != nullptr, "verify_user: correct password → found");
        runner.Check(*result == "testuser", "verify_user: username matches");
    }

    void TestVerifyUserWrongPassword(TestRunner &runner)
    {
        psm::memory::vector<user> users(psm::memory::current_resource());
        user u;
        u.username = "testuser";
        u.password = "correct_password";
        users.push_back(u);

        auth_frame frame{};
        std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
        const char *wrong = "wrong_password";
        SHA256(reinterpret_cast<const std::uint8_t *>(wrong),
               std::strlen(wrong), digest.data());
        std::memcpy(frame.password_hash.data(), digest.data(), 32);

        auto result = verify_user(frame, users);
        runner.Check(result == nullptr, "verify_user: wrong password → nullptr");
    }

    void TestVerifyUserEmptyUsers(TestRunner &runner)
    {
        psm::memory::vector<user> users(psm::memory::current_resource());
        auth_frame frame{};
        auto result = verify_user(frame, users);
        runner.Check(result == nullptr, "verify_user: empty users → nullptr");
    }

    void TestBuildUserMapMultiple(TestRunner &runner)
    {
        psm::memory::vector<user> users(psm::memory::current_resource());
        for (int i = 0; i < 5; ++i)
        {
            user u;
            u.username = psm::memory::string("user" + std::to_string(i));
            u.password = psm::memory::string("pass" + std::to_string(i));
            users.push_back(u);
        }

        auto map = build_user_map(users);
        runner.Check(map.size() == 5, "user_map: 5 users → size=5");
    }

    // ─── sha256_hash ────────────────────────────────

    void TestSha256HashConsistency(TestRunner &runner)
    {
        sha256_hash hasher;
        std::array<std::uint8_t, 32> key1{};
        std::array<std::uint8_t, 32> key2{};
        for (std::size_t i = 0; i < 32; ++i)
        {
            key1[i] = static_cast<std::uint8_t>(i);
            key2[i] = static_cast<std::uint8_t>(i);
        }

        auto h1 = hasher(key1);
        auto h2 = hasher(key2);
        runner.Check(h1 == h2, "sha256_hash: same input → same hash");
    }

    void TestSha256HashDifferent(TestRunner &runner)
    {
        sha256_hash hasher;
        std::array<std::uint8_t, 32> key1{};
        std::array<std::uint8_t, 32> key2{};
        key2[0] = 1;

        auto h1 = hasher(key1);
        auto h2 = hasher(key2);
        runner.Check(h1 != h2, "sha256_hash: different input → different hash");
    }

    // ─── scheme 公共方法 ────────────────────────────

    void TestSchemePublicMethods(TestRunner &runner)
    {
        scheme s;
        runner.Check(s.name() == "anytls", "scheme: name=anytls");

        auto guess = s.guess(psm::config{});
        runner.Check(guess.score == 100, "scheme: guess score=100");

        psm::config cfg;
        // 未启用 anytls
        runner.Check(!s.active(cfg), "scheme: not active by default");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsSchemeDeep");

    // parse_socks_target
    TestParseSocksTargetIPv4(runner);
    TestParseSocksTargetIPv4BadPort(runner);
    TestParseSocksTargetIPv6(runner);
    TestParseSocksTargetDomain(runner);
    TestParseSocksTargetEmpty(runner);
    TestParseSocksTargetBadAtyp(runner);

    // build_user_map / verify_user
    TestBuildUserMapAndVerify(runner);
    TestVerifyUserWrongPassword(runner);
    TestVerifyUserEmptyUsers(runner);
    TestBuildUserMapMultiple(runner);

    // sha256_hash
    TestSha256HashConsistency(runner);
    TestSha256HashDifferent(runner);

    // scheme 公共方法
    TestSchemePublicMethods(runner);

    return runner.Summary();
}
