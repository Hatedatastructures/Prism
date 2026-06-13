/**
 * @file ShadowsocksConnDeep.cpp
 * @brief SS2022 conn 深度测试（含异步）
 * @details 通过 #include 源文件访问 conn.cpp 中所有编译行，覆盖
 *          构造函数、close/cancel、executor、next_layer、target、
 *          derive_aead_context、handshake、send_chunk、fetch_chunk、
 *          acknowledge、async_read_some 等全部接口。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/proto/protocol/shadowsocks/framing.hpp>

#include <chrono>
#include <cstring>

#include "common/MockTransport.hpp"

#define private public
#include <gtest/gtest.h>

#include "../../src/prism/proto/protocol/shadowsocks/conn.cpp"

using psm::testing::MockTransport;

namespace
{
    namespace ss = psm::protocol::shadowsocks;
    namespace net = boost::asio;

    // base64 编码的 16 字节全零 PSK
    consteval auto psk128_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAA==";
    }

    // base64 编码的 32 字节全零 PSK
    consteval auto psk256_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }

    auto make_mock_transport() -> std::shared_ptr<MockTransport>
    {
        return std::make_shared<MockTransport>();
    }

    auto make_salts() -> std::shared_ptr<ss::salt_pool>
    {
        return std::make_shared<ss::salt_pool>();
    }

    // ─── 构造函数 ──────────────────────────────

    TEST(ShadowsocksConnDeep, ConnConstructAes128)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        // 验证 PSK 成功解码为 16 字节
        EXPECT_EQ(c.psk_.size(), 16u);
        EXPECT_EQ(c.method_, ss::cipher_method::aes_128_gcm);
        EXPECT_EQ(c.key_salt_len_, 16u);
    }

    TEST(ShadowsocksConnDeep, ConnConstructAes256)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-aes-256-gcm";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        EXPECT_EQ(c.psk_.size(), 32u);
        EXPECT_EQ(c.method_, ss::cipher_method::aes_256_gcm);
        EXPECT_EQ(c.key_salt_len_, 32u);
    }

    TEST(ShadowsocksConnDeep, ConnConstructChaCha20)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-chacha20-poly1305";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        EXPECT_EQ(c.psk_.size(), 32u);
        EXPECT_EQ(c.method_, ss::cipher_method::chacha20_poly1305);
        EXPECT_EQ(c.key_salt_len_, 32u);
    }

    TEST(ShadowsocksConnDeep, ConnConstructInvalidPsk)
    {
        ss::config cfg;
        cfg.psk = "!!!invalid-base64!!!";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        // 无效 PSK 解码失败 → psk_ 应为空
        EXPECT_TRUE(c.psk_.empty());
    }

    TEST(ShadowsocksConnDeep, ConnConstructEmptyPsk)
    {
        ss::config cfg;
        cfg.psk = "";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        EXPECT_TRUE(c.psk_.empty());
    }

    TEST(ShadowsocksConnDeep, ConnConfigFields)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        cfg.enable_tcp = false;
        cfg.enable_udp = true;
        cfg.timestamp_window = 120;
        cfg.salt_ttl = 300;
        cfg.idle_timeout = 180;

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        EXPECT_EQ(c.config_.enable_tcp, false);
        EXPECT_EQ(c.config_.enable_udp, true);
        EXPECT_EQ(c.config_.timestamp_window, 120);
        EXPECT_EQ(c.config_.salt_ttl, 300);
        EXPECT_EQ(c.config_.idle_timeout, 180);
    }

    // ─── close / cancel ────────────────────────

    TEST(ShadowsocksConnDeep, ConnClose)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.close();

        // close 传播到底层 transport
        EXPECT_TRUE(raw->is_closed());
    }

    TEST(ShadowsocksConnDeep, ConnCancel)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.cancel();

        EXPECT_TRUE(raw->is_cancelled());
    }

    TEST(ShadowsocksConnDeep, ConnCloseIdempotent)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.close();
        c.close();
        c.close();

        EXPECT_TRUE(raw->is_closed());
    }

    TEST(ShadowsocksConnDeep, ConnCancelThenClose)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.cancel();
        c.close();

        EXPECT_TRUE(raw->is_cancelled());
        EXPECT_TRUE(raw->is_closed());
    }

    // ─── next_layer ────────────────────────────

    TEST(ShadowsocksConnDeep, ConnNextLayer)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto *nl = c.next_layer();
        ASSERT_NE(nl, nullptr);
        EXPECT_EQ(nl, raw);
    }

    TEST(ShadowsocksConnDeep, ConnNextLayerConst)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        const ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto *nl = c.next_layer();
        ASSERT_NE(nl, nullptr);
        EXPECT_EQ(nl, raw);
    }

    // ─── target() 访问器 ───────────────────────

    TEST(ShadowsocksConnDeep, ConnTargetDefault)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto &t = c.target();
        EXPECT_TRUE(t.host.empty());
        EXPECT_EQ(t.port, "80");
    }

    // ─── executor ──────────────────────────────

    TEST(ShadowsocksConnDeep, ConnExecutor)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto ex = c.executor();
        EXPECT_TRUE(static_cast<bool>(ex));
    }

    // ─── make_conn 工厂函数 ────────────────────

    TEST(ShadowsocksConnDeep, MakeConnFactory)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        auto c = ss::make_conn(std::move(mock), cfg, std::move(salts));
        ASSERT_NE(c, nullptr);
        EXPECT_EQ(c->next_layer(), raw);
        EXPECT_EQ(c->transport_type(), psm::transport::transmission::type::tcp);
    }

    // ─── 异步测试辅助函数 ──────────────────────────────

    auto derive_test_aead(const std::span<const std::uint8_t> psk,
                           const std::span<const std::uint8_t> salt,
                           std::size_t key_len)
        -> std::unique_ptr<psm::crypto::aead_context>
    {
        std::array<std::uint8_t, 64> mat{};
        std::memcpy(mat.data(), psk.data(), psk.size());
        std::memcpy(mat.data() + psk.size(), salt.data(), salt.size());
        auto key = psm::crypto::derive_key(ss::kdf_context,
            std::span<const std::uint8_t>(mat.data(), psk.size() + salt.size()), key_len);
        return std::make_unique<psm::crypto::aead_context>(
            psm::crypto::aead_cipher::aes_128_gcm, key);
    }

    auto make_handshake_wire(const std::span<const std::uint8_t> psk,
                              std::size_t key_len,
                              const std::span<const std::uint8_t> salt,
                              std::int64_t ts_offset = 0,
                              std::uint8_t req_type = ss::request_type)
        -> std::vector<std::byte>
    {
        auto aead = derive_test_aead(psk, salt, key_len);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto ts = static_cast<std::uint64_t>(now + ts_offset);

        // 变长头明文：atyp_ipv4 + 127.0.0.1 + port=80 + paddingLen=0
        std::array<std::uint8_t, 9> var_plain{};
        var_plain[0] = ss::atyp_ipv4;
        var_plain[1] = 127;
        var_plain[5] = 0;
        var_plain[6] = 80;

        const auto var_len = static_cast<std::uint16_t>(var_plain.size());
        std::array<std::uint8_t, ss::fixed_hdr_plain> fixed_plain{};
        fixed_plain[0] = req_type;
        for (std::size_t i = 0; i < 8; ++i)
            fixed_plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        fixed_plain[9] = static_cast<std::uint8_t>(var_len >> 8);
        fixed_plain[10] = static_cast<std::uint8_t>(var_len & 0xFF);

        std::array<std::uint8_t, ss::fixed_hdr_size> fixed_enc{};
        (void)aead->seal(fixed_enc, fixed_plain);

        std::vector<std::uint8_t> var_enc(psm::crypto::aead_context::seal_size(var_plain.size()));
        (void)aead->seal(var_enc, var_plain);

        std::vector<std::byte> wire;
        wire.reserve(salt.size() + fixed_enc.size() + var_enc.size());
        for (auto b : salt) wire.push_back(static_cast<std::byte>(b));
        for (auto b : fixed_enc) wire.push_back(static_cast<std::byte>(b));
        for (auto b : var_enc) wire.push_back(static_cast<std::byte>(b));
        return wire;
    }

    // ─── derive_aead_context 同步测试 ──────────────────

    TEST(ShadowsocksConnDeep, DeriveAeadContext)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        auto ctx = c.derive_aead_context(salt);
        ASSERT_NE(ctx, nullptr);

        std::array<std::uint8_t, 4> plain{1, 2, 3, 4};
        std::array<std::uint8_t, 20> enc{};
        EXPECT_EQ(ctx->seal(enc, plain), psm::fault::code::success);
        // 同一个 context，seal 后 nonce 已递增，不能用同一个 context 解密
        // 需要构造第二个相同密钥的 context 来 open
        auto ctx2 = c.derive_aead_context(salt);
        std::array<std::uint8_t, 4> dec{};
        EXPECT_EQ(ctx2->open(dec, enc), psm::fault::code::success);
        EXPECT_EQ(dec, plain);
    }

    // ─── handshake 异步测试 ────────────────────────────

    TEST(ShadowsocksConnDeep, Handshake_Success)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto [dec_ec, psk_bytes] = ss::format::decode_psk(cfg.psk);
        ASSERT_EQ(dec_ec, psm::fault::code::success);

        std::array<std::uint8_t, 16> client_salt{};
        raw->inject_read(make_handshake_wire(psk_bytes, 16, client_salt));

        auto result_ec = std::make_shared<psm::fault::code>();
        auto result_req = std::make_shared<ss::request>();
        net::co_spawn(raw->get_io_context(),
            [&c, result_ec, result_req]() -> net::awaitable<void> {
                auto [ec, req] = co_await c.handshake();
                *result_ec = ec;
                *result_req = std::move(req);
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*result_ec, psm::fault::code::success);
        EXPECT_EQ(result_req->port, 80);
        EXPECT_TRUE(c.target().positive);
    }

    TEST(ShadowsocksConnDeep, Handshake_ConnectionReset)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        raw->set_read_error(std::make_error_code(std::errc::connection_reset));

        auto result_ec = std::make_shared<psm::fault::code>();
        net::co_spawn(raw->get_io_context(),
            [&c, result_ec]() -> net::awaitable<void> {
                auto [ec, req] = co_await c.handshake();
                *result_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();
        EXPECT_EQ(*result_ec, psm::fault::code::connection_reset);
    }

    TEST(ShadowsocksConnDeep, Handshake_SaltReplay)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto salts = make_salts();

        const auto [dec_ec, psk_bytes] = ss::format::decode_psk(cfg.psk);
        ASSERT_EQ(dec_ec, psm::fault::code::success);

        std::array<std::uint8_t, 16> client_salt{};
        auto wire = make_handshake_wire(psk_bytes, 16, client_salt);

        // 首次握手应成功
        {
            auto mock = make_mock_transport();
            auto *raw = mock.get();
            ss::conn c(std::move(mock), cfg, salts);
            raw->inject_read(wire);

            auto ec_ptr = std::make_shared<psm::fault::code>();
            net::co_spawn(raw->get_io_context(),
                [&c, ec_ptr]() -> net::awaitable<void> {
                    auto [ec, req] = co_await c.handshake();
                    *ec_ptr = ec;
                    co_return;
                }, net::detached);
            raw->get_io_context().run();
            EXPECT_EQ(*ec_ptr, psm::fault::code::success);
        }

        // 相同 salt 二次握手应检测到重放
        {
            auto mock2 = make_mock_transport();
            auto *raw2 = mock2.get();
            ss::conn c2(std::move(mock2), cfg, salts);
            raw2->inject_read(wire);

            auto ec_ptr2 = std::make_shared<psm::fault::code>();
            net::co_spawn(raw2->get_io_context(),
                [&c2, ec_ptr2]() -> net::awaitable<void> {
                    auto [ec, req] = co_await c2.handshake();
                    *ec_ptr2 = ec;
                    co_return;
                }, net::detached);
            raw2->get_io_context().run();
            EXPECT_EQ(*ec_ptr2, psm::fault::code::replay_detected);
        }
    }

    TEST(ShadowsocksConnDeep, Handshake_TimestampExpired)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto [dec_ec, psk_bytes] = ss::format::decode_psk(cfg.psk);
        ASSERT_EQ(dec_ec, psm::fault::code::success);

        std::array<std::uint8_t, 16> client_salt{};
        // 时间戳偏移 +3600 秒，超出默认 30 秒窗口
        raw->inject_read(make_handshake_wire(psk_bytes, 16, client_salt, 3600));

        auto result_ec = std::make_shared<psm::fault::code>();
        net::co_spawn(raw->get_io_context(),
            [&c, result_ec]() -> net::awaitable<void> {
                auto [ec, req] = co_await c.handshake();
                *result_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();
        EXPECT_EQ(*result_ec, psm::fault::code::timestamp_expired);
    }

    // ─── send_chunk 异步测试 ───────────────────────────

    TEST(ShadowsocksConnDeep, SendChunk_EncryptAndWrite)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        c.encrypt_ctx_ = c.derive_aead_context(salt);
        ASSERT_NE(c.encrypt_ctx_, nullptr);

        std::array<std::byte, 4> plain{
            std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

        auto result_n = std::make_shared<std::size_t>(0);
        auto result_ec = std::make_shared<std::error_code>();
        net::co_spawn(raw->get_io_context(),
            [&c, &plain, result_n, result_ec]() -> net::awaitable<void> {
                std::error_code ec;
                *result_n = co_await c.send_chunk(plain, ec);
                *result_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*result_n, 4u);
        EXPECT_FALSE(*result_ec);
        const auto &written = raw->written_data();
        // 18 字节加密长度块 + 20 字节加密 payload（4+16）
        EXPECT_EQ(written.size(), 18u + psm::crypto::aead_context::seal_size(4));
        // 密文不等于明文
        EXPECT_NE(std::memcmp(written.data() + 18, plain.data(), 4), 0);
    }

    TEST(ShadowsocksConnDeep, SendChunk_WriteError)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        c.encrypt_ctx_ = c.derive_aead_context(salt);
        raw->set_write_error(std::make_error_code(std::errc::broken_pipe));

        std::array<std::byte, 2> plain{std::byte{0x01}, std::byte{0x02}};

        auto result_n = std::make_shared<std::size_t>(99);
        auto result_ec = std::make_shared<std::error_code>();
        net::co_spawn(raw->get_io_context(),
            [&c, &plain, result_n, result_ec]() -> net::awaitable<void> {
                std::error_code ec;
                *result_n = co_await c.send_chunk(plain, ec);
                *result_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*result_n, 0u);
        EXPECT_TRUE(*result_ec);
    }

    // ─── fetch_chunk 异步测试 ──────────────────────────

    TEST(ShadowsocksConnDeep, FetchChunk_DecryptError)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        c.decrypt_ctx_ = c.derive_aead_context(salt);

        // 注入垃圾数据作为加密长度块
        std::vector<std::byte> garbage(18, std::byte{0xAA});
        raw->inject_read(garbage);

        auto result_ec = std::make_shared<std::error_code>();
        net::co_spawn(raw->get_io_context(),
            [&c, result_ec]() -> net::awaitable<void> {
                std::error_code ec;
                co_await c.fetch_chunk(ec);
                *result_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();
        EXPECT_TRUE(*result_ec);
    }

    // ─── acknowledge 异步测试 ──────────────────────────

    TEST(ShadowsocksConnDeep, Acknowledge_CallsSendResponse)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto [dec_ec, psk_bytes] = ss::format::decode_psk(cfg.psk);
        ASSERT_EQ(dec_ec, psm::fault::code::success);

        // 先完成握手
        std::array<std::uint8_t, 16> client_salt{};
        raw->inject_read(make_handshake_wire(psk_bytes, 16, client_salt));

        auto handshake_ec = std::make_shared<psm::fault::code>();
        net::co_spawn(raw->get_io_context(),
            [&c, handshake_ec]() -> net::awaitable<void> {
                auto [ec, req] = co_await c.handshake();
                *handshake_ec = ec;
                co_return;
            }, net::detached);
        raw->get_io_context().run();
        ASSERT_EQ(*handshake_ec, psm::fault::code::success);

        // 握手后调用 acknowledge
        raw->get_io_context().restart();
        auto ack_ec = std::make_shared<psm::fault::code>();
        net::co_spawn(raw->get_io_context(),
            [&c, ack_ec]() -> net::awaitable<void> {
                *ack_ec = co_await c.acknowledge();
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*ack_ec, psm::fault::code::success);
        // 响应大小：server_salt(16) + enc_fixed(1+8+16+2+16=43) + empty_payload(16) = 75
        EXPECT_EQ(raw->written_data().size(), 75u);
    }

    // ─── async_read_some 异步测试 ──────────────────────

    TEST(ShadowsocksConnDeep, AsyncReadSome_InitialPayload)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::byte, 4> payload = {
            std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        c.init_payload_.assign(payload.begin(), payload.end());

        auto result_n = std::make_shared<std::size_t>(0);
        auto result_buf = std::make_shared<std::vector<std::byte>>(4, std::byte{0});
        net::co_spawn(raw->get_io_context(),
            [&c, result_n, result_buf]() -> net::awaitable<void> {
                std::error_code ec;
                *result_n = co_await c.async_read_some(*result_buf, ec);
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*result_n, 4u);
        EXPECT_EQ(std::memcmp(result_buf->data(), payload.data(), 4), 0);
    }

    TEST(ShadowsocksConnDeep, AsyncReadSome_ChunkDecryption)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        // 用独立上下文加密测试数据，conn 的解密上下文 nonce 从 0 开始
        std::array<std::uint8_t, 16> salt{};
        auto enc_aead = c.derive_aead_context(salt);
        c.decrypt_ctx_ = c.derive_aead_context(salt);

        const std::array<std::uint8_t, 4> plain_data{0x11, 0x22, 0x33, 0x44};
        const auto chunk_len = static_cast<std::uint16_t>(plain_data.size());

        // 加密长度块
        std::array<std::uint8_t, 2> len_plain{
            static_cast<std::uint8_t>(chunk_len >> 8),
            static_cast<std::uint8_t>(chunk_len & 0xFF)};
        std::array<std::uint8_t, ss::len_block_size> len_enc{};
        ASSERT_EQ(enc_aead->seal(len_enc, len_plain), psm::fault::code::success);

        // 加密 payload 块
        std::vector<std::uint8_t> payload_enc(
            psm::crypto::aead_context::seal_size(plain_data.size()));
        ASSERT_EQ(enc_aead->seal(payload_enc, plain_data), psm::fault::code::success);

        // 注入加密 wire 数据
        std::vector<std::byte> wire;
        for (auto b : len_enc) wire.push_back(static_cast<std::byte>(b));
        for (auto b : payload_enc) wire.push_back(static_cast<std::byte>(b));
        raw->inject_read(wire);

        auto result_n = std::make_shared<std::size_t>(0);
        auto result_buf = std::make_shared<std::vector<std::byte>>(4, std::byte{0});
        net::co_spawn(raw->get_io_context(),
            [&c, result_n, result_buf]() -> net::awaitable<void> {
                std::error_code ec;
                *result_n = co_await c.async_read_some(*result_buf, ec);
                co_return;
            }, net::detached);
        raw->get_io_context().run();

        EXPECT_EQ(*result_n, 4u);
        EXPECT_EQ(std::memcmp(result_buf->data(), plain_data.data(), 4), 0);
    }

} // namespace
