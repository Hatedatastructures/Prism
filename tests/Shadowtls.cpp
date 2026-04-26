/**
 * @file Shadowtls.cpp
 * @brief ShadowTLS v3 测试
 */

#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <openssl/hmac.h>
#include <iostream>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
    int passed = 0;
    int failed = 0;

    template<typename T>
    auto BytesToHex(const std::span<T> bytes) -> std::string
    {
        std::ostringstream oss;
        for (auto b : bytes)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
        return oss.str();
    }

    auto LogPass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Shadowtls] PASS: {}", std::string{msg});
    }

    auto LogFail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Shadowtls] FAIL: {}", std::string{msg});
    }

    auto Check(const bool condition, const std::string_view message) -> void
    {
        if (condition) LogPass(message); else LogFail(message);
    }
}

void TestHMACComputation()
{
    using namespace psm::stealth::shadowtls;

    const std::string password = "test_password";
    std::array<std::byte, 64> data{};
    for (std::size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<std::byte>(i);

    const auto hmac1 = compute_hmac(password, data.data(), data.size());
    const auto hmac2 = compute_hmac(password, data.data(), data.size());

    Check(hmac1 == hmac2, "HMAC deterministic output");

    const auto hmac3 = compute_hmac("different_password", data.data(), data.size());
    Check(hmac1 != hmac3, "HMAC differs with different password");
}

void TestWriteKeyGeneration()
{
    using namespace psm::stealth::shadowtls;

    const std::string password = "test_password";
    std::array<std::byte, 32> server_random{};
    for (std::size_t i = 0; i < server_random.size(); ++i)
        server_random[i] = static_cast<std::byte>(0xA0 + i);

    const auto write_key = compute_write_key(password, server_random);

    Check(write_key.size() == 32, "WriteKey is 32 bytes (SHA256 output)");
    Check(!write_key.empty(), "WriteKey is non-empty");

    const auto write_key2 = compute_write_key(password, server_random);
    Check(write_key == write_key2, "WriteKey deterministic");

    const auto write_key3 = compute_write_key("other_password", server_random);
    Check(write_key != write_key3, "WriteKey differs with different password");
}

void TestFrameHMACVerification()
{
    using namespace psm::stealth::shadowtls;

    const std::string password = "test_password";
    std::array<std::byte, 32> server_random{};
    for (std::size_t i = 0; i < server_random.size(); ++i)
        server_random[i] = static_cast<std::byte>(i);

    std::array<std::byte, 16> payload{};
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<std::byte>(0x10 + i);

    // compute_write_hmac 使用 "S" 标签（服务端写入方向）
    const auto write_hmac = compute_write_hmac(password, server_random, payload);

    // verify_frame_hmac 使用 "C" 标签（客户端写入方向）
    // 所以用 write_hmac 去 verify 应该失败（标签不同）
    Check(!verify_frame_hmac(password, server_random, payload, write_hmac),
          "Frame HMAC with cross-direction tag should fail");

    // 手动构建 "C" 方向的 HMAC 来验证 verify_frame_hmac 正确性
    // 使用 HMAC_CTX 手动计算 "C" 标签的 HMAC
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(server_random.data()), server_random.size());
    constexpr unsigned char tag_c = 'C';
    HMAC_Update(ctx, &tag_c, 1);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(payload.data()), payload.size());
    std::array<std::uint8_t, 20> md{}; // SHA1 输出 20 字节
    unsigned int md_len = 0;
    HMAC_Final(ctx, md.data(), &md_len);
    HMAC_CTX_free(ctx);

    std::array<std::uint8_t, 4> read_hmac{};
    std::memcpy(read_hmac.data(), md.data(), 4);

    Check(verify_frame_hmac(password, server_random, payload, read_hmac),
          "Frame HMAC verification with correct read-direction HMAC");
}

void TestClientHelloVerification()
{
    using namespace psm::stealth::shadowtls;

    const std::string password = "test_password";

    std::array<std::byte, 10> short_data{};
    Check(!verify_client_hello(short_data, password),
          "ClientHello rejects short data");

    std::array<std::byte, 80> fake_hello{};
    fake_hello[0] = std::byte{0x00};
    Check(!verify_client_hello(fake_hello, password),
          "ClientHello rejects wrong record type");
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    TestHMACComputation();
    TestWriteKeyGeneration();
    TestFrameHMACVerification();
    TestClientHelloVerification();

    psm::trace::info("[Shadowtls] =============================");
    psm::trace::info("[Shadowtls] Passed: {}, Failed: {}", passed, failed);
    psm::trace::info("[Shadowtls] =============================");
    psm::trace::shutdown();

    return failed == 0 ? 0 : 1;
}
