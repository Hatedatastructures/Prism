/**
 * @file ShadowsocksConnUtil.cpp
 * @brief SS2022 conn 工具函数 + derive_aead_context 深度测试
 * @details 先包含所有重量级头文件（aead.hpp, blake3.hpp 等），
 *          再用 #define private public 仅打开 conn.hpp 的 private。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

// 在 #define private public 之前预包含所有传递依赖，防止类布局破坏
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/fault.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/framing.hpp>
#include <prism/protocol/shadowsocks/packet.hpp>
#include <prism/protocol/shadowsocks/util/salts.hpp>
#include <prism/protocol/shadowsocks/util/cast.hpp>
#include <prism/transport/transmission.hpp>
#include <boost/asio.hpp>
#include <openssl/rand.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/MockTransport.hpp"
#include "common/TestRunner.hpp"

// 所有传递依赖已包含，现在仅打开 conn.hpp 的 private
#define private public
#include <prism/protocol/shadowsocks/conn.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/protocol/shadowsocks/conn.cpp"

using psm::testing::TestRunner;
using psm::testing::MockTransport;

// ─── as_u8_mut / to_bytes 在 ss 匿名命名空间中 ───

namespace psm::protocol::shadowsocks
{

    static void TestAsU8MutVectorBasic(TestRunner &runner)
    {
        std::vector<std::byte> v = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        auto span = as_u8_mut(v);
        runner.Check(span.size() == 3, "as_u8_mut(vector): size=3");
        runner.Check(span[0] == 0x01, "as_u8_mut(vector): first byte");
        runner.Check(span[2] == 0x03, "as_u8_mut(vector): last byte");
    }

    static void TestAsU8MutVectorEmpty(TestRunner &runner)
    {
        std::vector<std::byte> v;
        auto span = as_u8_mut(v);
        runner.Check(span.empty(), "as_u8_mut(vector): empty");
    }

    static void TestAsU8MutVectorWrite(TestRunner &runner)
    {
        std::vector<std::byte> v(4, std::byte{0x00});
        auto span = as_u8_mut(v);
        span[0] = 0xAA;
        span[3] = 0xFF;
        runner.Check(v[0] == std::byte{0xAA}, "as_u8_mut(vector): write modifies original");
        runner.Check(v[3] == std::byte{0xFF}, "as_u8_mut(vector): write last byte");
    }

    static void TestAsU8MutPmrBasic(TestRunner &runner)
    {
        psm::memory::vector<std::byte> v(psm::memory::current_resource());
        v.push_back(std::byte{0x10});
        v.push_back(std::byte{0x20});
        auto span = as_u8_mut(v);
        runner.Check(span.size() == 2, "as_u8_mut(pmr): size=2");
        runner.Check(span[0] == 0x10, "as_u8_mut(pmr): first byte");
    }

    static void TestAsU8MutPmrEmpty(TestRunner &runner)
    {
        psm::memory::vector<std::byte> v(psm::memory::current_resource());
        auto span = as_u8_mut(v);
        runner.Check(span.empty(), "as_u8_mut(pmr): empty");
    }

    static void TestAsU8MutPmrWrite(TestRunner &runner)
    {
        psm::memory::vector<std::byte> v(8, std::byte{0x00}, psm::memory::current_resource());
        auto span = as_u8_mut(v);
        span[0] = 0x42;
        span[7] = 0xFF;
        runner.Check(v[0] == std::byte{0x42}, "as_u8_mut(pmr): write index 0");
        runner.Check(v[7] == std::byte{0xFF}, "as_u8_mut(pmr): write index 7");
    }

    static void TestToBytesUint8Vector(TestRunner &runner)
    {
        std::vector<std::uint8_t> v = {0x01, 0x02, 0x03};
        auto bytes = to_bytes(v);
        runner.Check(bytes.size() == 3, "to_bytes: size=3");
        runner.Check(bytes[0] == std::byte{0x01}, "to_bytes: first byte");
        runner.Check(bytes[2] == std::byte{0x03}, "to_bytes: last byte");
    }

    static void TestToBytesEmpty(TestRunner &runner)
    {
        std::vector<std::uint8_t> v;
        auto bytes = to_bytes(v);
        runner.Check(bytes.empty(), "to_bytes: empty");
    }

    static void TestToBytesUint32Vector(TestRunner &runner)
    {
        std::vector<std::uint32_t> v = {0x01020304, 0x05060708};
        auto bytes = to_bytes(v);
        runner.Check(bytes.size() == 8, "to_bytes: uint32 vector -> 8 bytes");
    }

} // namespace psm::protocol::shadowsocks

// ─── derive_aead_context 测试在全局命名空间，用 ss:: 限定 ───

namespace
{
    namespace ss = psm::protocol::shadowsocks;

    static consteval auto psk128_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAA==";
    }

    static consteval auto psk256_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }

    static void TestDeriveAeadContextAes128(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        for (std::size_t i = 0; i < 16; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto ctx = c.derive_aead_context(salt);
        runner.Check(ctx != nullptr, "derive: aes-128 context not null");
    }

    static void TestDeriveAeadContextAes256(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-aes-256-gcm";

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 32> salt{};
        for (std::size_t i = 0; i < 32; ++i)
            salt[i] = static_cast<std::uint8_t>(i + 0x80);

        auto ctx = c.derive_aead_context(salt);
        runner.Check(ctx != nullptr, "derive: aes-256 context not null");
    }

    static void TestDeriveAeadContextChaCha20(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-chacha20-poly1305";

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 32> salt{};
        for (std::size_t i = 0; i < 32; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto ctx = c.derive_aead_context(salt);
        runner.Check(ctx != nullptr, "derive: chacha20 context not null");
    }

    static void TestDeriveAeadContextDifferentSalts(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt1{};
        salt1[0] = 0x01;
        std::array<std::uint8_t, 16> salt2{};
        salt2[0] = 0x02;

        auto ctx1 = c.derive_aead_context(salt1);
        auto ctx2 = c.derive_aead_context(salt2);
        runner.Check(ctx1 != nullptr, "derive: salt1 context");
        runner.Check(ctx2 != nullptr, "derive: salt2 context");
    }

    static void TestDeriveAeadContextEmptySalt(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto ctx = c.derive_aead_context(std::span<const std::uint8_t>{});
        runner.Check(ctx != nullptr, "derive: empty salt context");
    }

    static void TestDeriveAeadContextEncryptDecrypt(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        for (std::size_t i = 0; i < 16; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto seal_ctx = c.derive_aead_context(salt);
        runner.Check(seal_ctx != nullptr, "derive: roundtrip seal context");

        std::array<std::uint8_t, 4> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
        std::vector<std::uint8_t> ciphertext(plaintext.size() + psm::crypto::aead_context::tag_length(), 0);

        // 使用显式 nonce 重载（nonce=0），保证 seal 和 open 使用相同 nonce
        std::array<std::uint8_t, 12> seal_nonce{};
        auto seal_rc = seal_ctx->seal(psm::crypto::seal_input{
            ciphertext,
            plaintext,
            seal_nonce,
            {}});
        runner.Check(seal_rc == psm::fault::code::success, "derive: seal success");
        runner.Check(ciphertext.size() == 4 + 16, "derive: ciphertext = data + tag");

        // 派生独立解密上下文（nonce 从 0 开始，与加密上下文一致）
        auto open_ctx = c.derive_aead_context(salt);
        runner.Check(open_ctx != nullptr, "derive: roundtrip open context");

        // 使用显式 nonce 重载进行解密（nonce=0），绕过自动 nonce 递增问题
        std::array<std::uint8_t, 12> zero_nonce{};
        std::vector<std::uint8_t> decrypted(plaintext.size(), 0);
        auto open_rc = open_ctx->open(psm::crypto::open_input{
            decrypted,
            ciphertext,
            zero_nonce,
            {}});
        runner.Check(open_rc == psm::fault::code::success, "derive: open success");
        runner.Check(decrypted.size() == 4, "derive: decrypted size=4");
        runner.Check(decrypted[0] == 0xDE, "derive: decrypted byte 0");
        runner.Check(decrypted[3] == 0xEF, "derive: decrypted byte 3");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowsocksConnUtil");
    namespace ss = psm::protocol::shadowsocks;

    // as_u8_mut (std::vector)
    ss::TestAsU8MutVectorBasic(runner);
    ss::TestAsU8MutVectorEmpty(runner);
    ss::TestAsU8MutVectorWrite(runner);

    // as_u8_mut (PMR vector)
    ss::TestAsU8MutPmrBasic(runner);
    ss::TestAsU8MutPmrEmpty(runner);
    ss::TestAsU8MutPmrWrite(runner);

    // to_bytes
    ss::TestToBytesUint8Vector(runner);
    ss::TestToBytesEmpty(runner);
    ss::TestToBytesUint32Vector(runner);

    // derive_aead_context
    TestDeriveAeadContextAes128(runner);
    TestDeriveAeadContextAes256(runner);
    TestDeriveAeadContextChaCha20(runner);
    TestDeriveAeadContextDifferentSalts(runner);
    TestDeriveAeadContextEmptySalt(runner);
    TestDeriveAeadContextEncryptDecrypt(runner);

    return runner.Summary();
}
