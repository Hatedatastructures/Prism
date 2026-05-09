/**
 * @file ShadowTlsE2E.cpp
 * @brief ShadowTLS v3 集成测试
 * @details 验证 ShadowTLS v3 认证逻辑 + XOR+HMAC 帧协议。
 * 不走完整 TLS 握手（需要自定义 BIO，过于复杂），直接测试认证和帧处理。
 */

#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/stealth/shadowtls/constants.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

#include <openssl/hmac.h>

#include <array>
#include <vector>
#include <cstring>
#include <random>

namespace net = boost::asio;
using tcp = net::ip::tcp;
using namespace psm::stealth::shadowtls;

namespace
{
    int passed = 0;
    int failed = 0;

    auto LogPass(std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[ShadowTlsE2E] PASS: {}", msg);
    }

    auto LogFail(std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[ShadowTlsE2E] FAIL: {}", msg);
    }

    auto generate_random_bytes(std::size_t n) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> buf(n);
        std::random_device rd;
        for (auto &b : buf)
            b = static_cast<std::uint8_t>(rd());
        return buf;
    }

    void append_u16(std::vector<std::uint8_t> &buf, std::uint16_t val)
    {
        buf.push_back(static_cast<std::uint8_t>(val >> 8));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    void append_u24(std::vector<std::uint8_t> &buf, std::size_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    void append_u8(std::vector<std::uint8_t> &buf, std::uint8_t val)
    {
        buf.push_back(val);
    }

    /**
     * @brief 构造带 HMAC 的 TLS 1.3 ClientHello
     * @details SessionID = 32 字节，最后 4 字节 = HMAC-SHA1(password, data)[:4]
     */
    auto build_client_hello_with_hmac(const std::string &password) -> std::vector<std::byte>
    {
        // 构造 ClientHello body
        std::vector<std::uint8_t> body;

        // ClientVersion (TLS 1.2 兼容)
        append_u16(body, 0x0303);

        // Random (32 bytes)
        auto random = generate_random_bytes(32);
        body.insert(body.end(), random.begin(), random.end());

        // SessionID (32 bytes, last 4 = HMAC placeholder)
        append_u8(body, 32);
        auto session_id = generate_random_bytes(32);
        session_id[28] = 0;
        session_id[29] = 0;
        session_id[30] = 0;
        session_id[31] = 0;
        body.insert(body.end(), session_id.begin(), session_id.end());

        // CipherSuites
        append_u16(body, 2);
        append_u16(body, 0x1301);

        // CompressionMethods
        append_u8(body, 1);
        append_u8(body, 0);

        // Extensions (minimal)
        std::vector<std::uint8_t> exts;
        append_u16(exts, 0x002b); // supported_versions
        append_u16(exts, 3);
        append_u8(exts, 2);
        append_u16(exts, 0x0304);

        append_u16(body, static_cast<std::uint16_t>(exts.size()));
        body.insert(body.end(), exts.begin(), exts.end());

        // 构造完整 ClientHello（含 TLS header）
        std::vector<std::uint8_t> ch;
        ch.push_back(0x16); // Handshake
        append_u16(ch, 0x0301);
        append_u16(ch, static_cast<std::uint16_t>(body.size() + 4));
        ch.push_back(0x01); // ClientHello
        append_u24(ch, body.size());
        ch.insert(ch.end(), body.begin(), body.end());

        // 计算 HMAC 并嵌入 SessionID
        // HMAC 在 ClientHello 中的偏移 = 44 + 32 - 4 = 72
        constexpr std::size_t hmac_offset_in_ch = 72;
        std::memset(ch.data() + hmac_offset_in_ch, 0, 4);

        auto hmac = compute_hmac(password,
            reinterpret_cast<const std::byte *>(ch.data() + 5),
            ch.size() - 5);
        std::memcpy(ch.data() + hmac_offset_in_ch, hmac.data(), 4);

        // 转换为 std::byte
        std::vector<std::byte> result(ch.size());
        for (std::size_t i = 0; i < ch.size(); ++i)
            result[i] = static_cast<std::byte>(ch[i]);

        return result;
    }

    /**
     * @brief 构造带 HMAC 的 Application Data 帧
     * @details TLS header(5) + HMAC(4) + payload
     * HMAC = HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
     */
    auto build_app_data_frame(const std::string &password,
                              const std::array<std::byte, 32> &server_random,
                              const std::vector<std::uint8_t> &payload) -> std::vector<std::byte>
    {
        // 计算 HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(server_random.data()), 32);
        constexpr unsigned char tag_c = 'C';
        HMAC_Update(ctx, &tag_c, 1);
        HMAC_Update(ctx, payload.data(), payload.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        unsigned int md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        // 构建帧
        auto total_len = 4 + payload.size();
        std::vector<std::byte> frame;
        frame.push_back(std::byte{0x17}); // Application Data
        frame.push_back(std::byte{0x03}); // TLS 1.2 legacy
        frame.push_back(std::byte{0x03});
        frame.push_back(static_cast<std::byte>(total_len >> 8));
        frame.push_back(static_cast<std::byte>(total_len & 0xFF));
        for (int i = 0; i < 4; ++i)
            frame.push_back(static_cast<std::byte>(md[i]));
        for (auto b : payload)
            frame.push_back(static_cast<std::byte>(b));

        return frame;
    }

    // ═══════════════════════════════════════════════════════════
    // 测试用例
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 ClientHello HMAC 认证成功
     * @details 构造带正确 HMAC 的 ClientHello，验证 verify_client_hello 通过
     */
    void TestClientHelloHmacVerify()
    {
        psm::trace::info("[ShadowTlsE2E] === TestClientHelloHmacVerify ===");

        const std::string password = "test_password_123";
        auto ch = build_client_hello_with_hmac(password);

        auto ch_span = std::span<const std::byte>(ch.data(), ch.size());
        bool ok = verify_client_hello(ch_span, password);

        if (ok)
        {
            LogPass("ClientHelloHmacVerify: correct password accepted");
        }
        else
        {
            LogFail("ClientHelloHmacVerify: correct password rejected");
        }
    }

    /**
     * @brief 测试 ClientHello HMAC 认证失败（错误密码）
     */
    void TestClientHelloHmacVerifyWrongPassword()
    {
        psm::trace::info("[ShadowTlsE2E] === TestClientHelloHmacVerifyWrongPassword ===");

        const std::string password = "correct_password";
        const std::string wrong_password = "wrong_password";
        auto ch = build_client_hello_with_hmac(password);

        auto ch_span = std::span<const std::byte>(ch.data(), ch.size());
        bool ok = verify_client_hello(ch_span, wrong_password);

        if (!ok)
        {
            LogPass("ClientHelloHmacVerifyWrongPassword: wrong password rejected");
        }
        else
        {
            LogFail("ClientHelloHmacVerifyWrongPassword: wrong password accepted");
        }
    }

    /**
     * @brief 测试 XOR+HMAC 帧协议（verify_frame_hmac）
     * @details 构造带 HMAC 的 Application Data 帧，验证 verify_frame_hmac 通过
     */
    void TestFrameHmacProtocol()
    {
        psm::trace::info("[ShadowTlsE2E] === TestFrameHmacProtocol ===");

        const std::string password = "frame_test_password";
        auto server_random = generate_random_bytes(32);
        std::array<std::byte, 32> sr{};
        for (std::size_t i = 0; i < 32; ++i)
            sr[i] = static_cast<std::byte>(server_random[i]);

        std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        auto frame = build_app_data_frame(password, sr, payload);

        // 提取 HMAC（frame 偏移 5 处的 4 字节）
        std::array<std::uint8_t, 4> client_hmac{};
        for (int i = 0; i < 4; ++i)
            client_hmac[i] = static_cast<std::uint8_t>(frame[5 + i]);

        // payload 在 frame 偏移 9 处
        auto payload_span = std::span<const std::byte>(frame.data() + 9, frame.size() - 9);

        bool ok = verify_frame_hmac(password, sr, payload_span, client_hmac);

        if (ok)
        {
            LogPass("FrameHmacProtocol: correct HMAC accepted");
        }
        else
        {
            LogFail("FrameHmacProtocol: correct HMAC rejected");
        }
    }

    /**
     * @brief 测试 XOR+HMAC 帧协议（错误 HMAC 被拒绝）
     */
    void TestFrameHmacProtocolWrongHmac()
    {
        psm::trace::info("[ShadowTlsE2E] === TestFrameHmacProtocolWrongHmac ===");

        const std::string password = "frame_test_password";
        auto server_random = generate_random_bytes(32);
        std::array<std::byte, 32> sr{};
        for (std::size_t i = 0; i < 32; ++i)
            sr[i] = static_cast<std::byte>(server_random[i]);

        std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};

        // 使用错误的 HMAC
        std::array<std::uint8_t, 4> wrong_hmac = {0xDE, 0xAD, 0xBE, 0xEF};

        auto payload_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(payload.data()), payload.size());

        bool ok = verify_frame_hmac(password, sr, payload_span, wrong_hmac);

        if (!ok)
        {
            LogPass("FrameHmacProtocolWrongHmac: wrong HMAC rejected");
        }
        else
        {
            LogFail("FrameHmacProtocolWrongHmac: wrong HMAC accepted");
        }
    }

    void RunAllTests()
    {
        TestClientHelloHmacVerify();
        TestClientHelloHmacVerifyWrongPassword();
        TestFrameHmacProtocol();
        TestFrameHmacProtocolWrongHmac();
        // TestHandshakeWithBackend 需要真实 TLS 后端，暂不测试
        // 认证逻辑已被前 4 个测试覆盖
    }
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    psm::trace::info("[ShadowTlsE2E] Starting ShadowTLS integration tests...");

    try
    {
        RunAllTests();
    }
    catch (const std::exception &e)
    {
        psm::trace::error("[ShadowTlsE2E] Exception: {}", e.what());
    }

    psm::trace::info("[ShadowTlsE2E] Results: {} passed, {} failed", passed, failed);
    psm::trace::shutdown();

    return failed > 0 ? 1 : 0;
}
