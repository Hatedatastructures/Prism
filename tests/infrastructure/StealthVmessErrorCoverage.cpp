/**
 * @file StealthVmessErrorCoverage.cpp
 * @brief stealth conn 与 vmess conn 错误路径覆盖
 * @details 针对测试库 conn 装饰器的握手错误路径与数据面错误分支：
 * 1. stealth 各方案（anytls / shadowtls / reality / restls /
 *    trusttunnel / gun / ws）read_handshake / write_handshake
 *    错误路径：底层 EOF、校验失败（bad_auth）、魔数不匹配
 *    （bad_magic）、密钥派生失败（kdf_error）、发送失败（io_error）
 * 2. vmess conn 数据面错误分支：未握手读写（not_open）、
 *    chunk 解密失败（bad_auth）、EOF（unexpected_eof）、
 *    结束块（finish）→ 流结束（0 且无错误）
 * @note 使用 make_memory_pair 建立内存传输对，手动注入合法/非法
 *       字节流触发各错误分支；全部采用 co_spawn + ioc.run() 模式。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/vmess/codec.hpp>
#include <common/proxy/vmess/vmess.hpp>
#include <common/stealth/anytls/codec.hpp>
#include <common/stealth/anytls/conn.hpp>
#include <common/stealth/gun/conn.hpp>
#include <common/stealth/reality/codec.hpp>
#include <common/stealth/reality/conn.hpp>
#include <common/stealth/restls/conn.hpp>
#include <common/stealth/shadowtls/conn.hpp>
#include <common/stealth/trusttunnel/codec.hpp>
#include <common/stealth/trusttunnel/conn.hpp>
#include <common/stealth/ws/codec.hpp>
#include <common/stealth/ws/conn.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 构造固定模式随机数
    auto make_random(std::uint8_t seed, std::size_t len) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out(len);
        for (std::size_t i = 0; i < len; ++i)
        {
            out[i] = static_cast<std::uint8_t>(i * 7 + seed);
        }
        return out;
    }

    /// 字符串 → 字节视图写入（测试辅助）
    auto write_raw(memory_stream &stream, std::string_view data) -> net::awaitable<void>
    {
        std::error_code ec;
        co_await stream.async_write_some(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(data.data()), data.size()), ec);
        co_return;
    }

    /// 未握手 conn：读写返回 not_open（所有 stealth 方案共用）
    template <typename Conn>
    auto check_not_open_read_write(const std::shared_ptr<Conn> &conn, net::io_context &ioc) -> void
    {
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await conn->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                     ec.clear();
                     const auto w = co_await conn->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                 });
    }

    // =========================================================================
    // AnyTLS conn 错误路径
    // =========================================================================

    TEST(StealthAnyTlsConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：对端直接关闭 → 读帧头 EOF → unexpected_eof
                     auto server =
                         std::make_shared<anytls::conn<>>(std::make_shared<memory_stream>(std::move(b)), "pw");
                     a.close();
                     const auto err = co_await server->read_handshake();
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakePartialFrameEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server =
                         std::make_shared<anytls::conn<>>(std::make_shared<memory_stream>(std::move(b)), "pw");
                     // 只发帧头（hash + padlen），随后半关 → 读 padding 时 EOF
                     std::string frame;
                     EXPECT_EQ(anytls::build_auth_frame("pw", 16, frame), error::none);
                     std::error_code ec;
                     co_await a.async_write_some(
                         as_bytes(as_u8_span(frame).first(anytls::auth_frame_hdrlen)), ec);
                     EXPECT_FALSE(ec);
                     co_await a.shutdown();
                     const auto err = co_await server->read_handshake();
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<anytls::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "expect-pw");
                     // 客户端用错误密码构造认证帧 → 密码哈希不匹配 → bad_auth
                     std::string frame;
                     EXPECT_EQ(anytls::build_auth_frame("wrong-pw", 16, frame), error::none);
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(as_u8_span(frame)), ec);
                     EXPECT_FALSE(ec);
                     const auto err = co_await server->read_handshake();
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthAnyTlsConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<anytls::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
                     b.close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await client->write_handshake();
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthAnyTlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<anytls::conn<>>(std::make_shared<memory_stream>(std::move(a)), "pw");
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // ShadowTLS v3 conn 错误路径
    // =========================================================================

    TEST(StealthShadowTlsConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<shadowtls::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "pw");
                     a.close(); // 对端关闭 → 读 ClientHello EOF → unexpected_eof
                     const auto err = co_await server->read_handshake();
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto server_rnd = make_random(0x11, shadowtls::tls_rnd_size);
        const auto client_rnd = make_random(0x22, shadowtls::tls_rnd_size);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 客户端用错误密码构造 ClientHello（session_id HMAC 不匹配）
                     auto client = std::make_shared<shadowtls::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "wrong-pw");
                     const auto werr = co_await client->write_handshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(werr, error::none);
                     auto server = std::make_shared<shadowtls::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "expect-pw");
                     const auto err = co_await server->read_handshake();
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthShadowTlsConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto server_rnd = make_random(0x33, shadowtls::tls_rnd_size);
        const auto client_rnd = make_random(0x44, shadowtls::tls_rnd_size);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<shadowtls::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
                     b.close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await client->write_handshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthShadowTlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn =
            std::make_shared<shadowtls::conn<>>(std::make_shared<memory_stream>(std::move(a)), "pw");
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // Reality conn 错误路径
    // =========================================================================

    /// 生成 X25519 密钥对（断言成功，规避 nodiscard）
    auto make_keypair(std::array<std::uint8_t, reality::key_len> &priv,
                      std::array<std::uint8_t, reality::key_len> &pub) -> void
    {
        EXPECT_FALSE(reality::generate_keypair(priv, pub));
    }

    /// 构造客户端密封的 session_id（false = 成功）
    auto make_reality_sealed(std::span<const std::uint8_t> priv_cli,
                             std::span<const std::uint8_t> pub_srv,
                             std::span<const std::uint8_t> client_random,
                             std::span<const std::uint8_t> hello,
                             std::span<const std::uint8_t, 8> short_id,
                             std::array<std::uint8_t, reality::session_id_auth_len> &sealed) -> bool
    {
        std::array<std::uint8_t, reality::key_len> shared{};
        if (reality::x25519_shared(priv_cli, pub_srv, shared))
        {
            return true;
        }
        std::array<std::uint8_t, reality::key_len> auth_key{};
        if (reality::derive_auth_key(shared, client_random, auth_key))
        {
            return true;
        }
        std::array<std::uint8_t, 16> plain{};
        plain[0] = 0x01; // version = 1
        std::copy(short_id.begin(), short_id.end(), plain.begin() + 8);
        return reality::seal_session_id(
            reality::session_id_seal_input{auth_key, client_random, plain, hello}, sealed);
    }

    TEST(StealthRealityConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::array<std::uint8_t, reality::key_len> priv{};
        std::array<std::uint8_t, reality::key_len> pub{};
        make_keypair(priv, pub);
        const auto client_random = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, reality::max_short_id_len> short_id{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<reality::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), priv);
                     a.close(); // 对端关闭 → 读 session_id EOF → unexpected_eof
                     reality::handshake_params params{std::span<const std::uint8_t>(client_random), hello,
                                                      short_id};
                     std::array<std::uint8_t, reality::max_short_id_len> out_sid{};
                     const auto err = co_await server->read_handshake(pub, params, out_sid);
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::array<std::uint8_t, reality::key_len> priv_cli{};
        std::array<std::uint8_t, reality::key_len> pub_cli{};
        std::array<std::uint8_t, reality::key_len> priv_srv{};
        std::array<std::uint8_t, reality::key_len> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto client_random = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, reality::max_short_id_len> short_id{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 构造合法 sealed session_id 后篡改 1 字节 → GCM tag 校验失败 → bad_auth
                     std::array<std::uint8_t, reality::session_id_auth_len> sealed{};
                     EXPECT_FALSE(make_reality_sealed(priv_cli, pub_srv,
                                                      std::span<const std::uint8_t>(client_random), hello,
                                                      short_id, sealed));
                     sealed[0] ^= 0xFF;
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(sealed)), ec);
                     EXPECT_FALSE(ec);

                     auto server = std::make_shared<reality::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), priv_srv);
                     reality::handshake_params params{std::span<const std::uint8_t>(client_random), hello,
                                                      short_id};
                     std::array<std::uint8_t, reality::max_short_id_len> out_sid{};
                     const auto err = co_await server->read_handshake(pub_cli, params, out_sid);
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeKdfError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::array<std::uint8_t, reality::key_len> priv{};
        std::array<std::uint8_t, reality::key_len> pub{};
        make_keypair(priv, pub);
        const auto client_random = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, reality::max_short_id_len> short_id{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 先喂 32 字节（session_id 读取），再以非法长度公钥 → kdf_error
                     std::array<std::uint8_t, 32> junk{};
                     junk.fill(0xAA);
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(junk)), ec);
                     EXPECT_FALSE(ec);

                     auto server = std::make_shared<reality::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     reality::handshake_params params{std::span<const std::uint8_t>(client_random), hello,
                                                      short_id};
                     std::array<std::uint8_t, reality::max_short_id_len> out_sid{};
                     const auto err = co_await server->read_handshake(bad_pub, params, out_sid);
                     EXPECT_EQ(err, error::kdf_error);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeKdfError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::array<std::uint8_t, reality::key_len> priv{};
        std::array<std::uint8_t, reality::key_len> pub{};
        make_keypair(priv, pub);
        const auto client_random = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, reality::max_short_id_len> short_id{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<reality::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     reality::handshake_params params{std::span<const std::uint8_t>(client_random), hello,
                                                      short_id};
                     const auto err = co_await client->write_handshake(bad_pub, params);
                     EXPECT_EQ(err, error::kdf_error);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::array<std::uint8_t, reality::key_len> priv_cli{};
        std::array<std::uint8_t, reality::key_len> pub_cli{};
        std::array<std::uint8_t, reality::key_len> priv_srv{};
        std::array<std::uint8_t, reality::key_len> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto client_random = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, reality::max_short_id_len> short_id{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<reality::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), priv_cli);
                     b.close(); // 对端全关 → 发送 sealed session_id 失败 → io_error
                     reality::handshake_params params{std::span<const std::uint8_t>(client_random), hello,
                                                      short_id};
                     const auto err = co_await client->write_handshake(pub_srv, params);
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthRealityConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<reality::conn<>>(std::make_shared<memory_stream>(std::move(a)),
                                                      std::array<std::uint8_t, 32>{});
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // Restls conn 错误路径
    // =========================================================================

    TEST(StealthRestlsConnError, WriteHandshakeBadLength)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // server_random 长度非法（31 字节）→ bad_length
                     auto client = std::make_shared<restls::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
                     const std::array<std::uint8_t, 31> short_rnd{};
                     const auto err =
                         co_await client->write_handshake(std::span<const std::uint8_t>(short_rnd));
                     EXPECT_EQ(err, error::bad_length);
                 });
    }

    TEST(StealthRestlsConnError, ReadHandshakeBadLength)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // server_random 长度非法（33 字节）→ bad_length
                     auto server = std::make_shared<restls::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "pw");
                     const std::array<std::uint8_t, 33> long_rnd{};
                     const auto err =
                         co_await server->read_handshake(std::span<const std::uint8_t>(long_rnd));
                     EXPECT_EQ(err, error::bad_length);
                 });
    }

    TEST(StealthRestlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<restls::conn<>>(std::make_shared<memory_stream>(std::move(a)), "pw");
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // TrustTunnel conn 错误路径
    // =========================================================================

    TEST(StealthTrustTunnelConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<trusttunnel::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "user", "pass");
                     a.close(); // 对端关闭 → 头块不完整 → bad_magic
                     std::string target;
                     const auto err = co_await server->read_handshake(target);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<trusttunnel::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "user", "pass");
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string target;
                     const auto err = co_await server->read_handshake(target);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeMissingAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<trusttunnel::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "user", "pass");
                     // CONNECT 但无 Proxy-Authorization 头 → bad_auth
                     co_await write_raw(a, "CONNECT example.com:443 HTTP/2\r\n\r\n");
                     std::string target;
                     const auto err = co_await server->read_handshake(target);
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeWrongCreds)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<trusttunnel::conn<>>(
                         std::make_shared<memory_stream>(std::move(b)), "user", "pass");
                     // Basic Auth 凭据错误 → bad_auth
                     const std::string header =
                         "CONNECT example.com:443 HTTP/2\r\n"
                         "Proxy-Authorization: " +
                         trusttunnel::basic_auth("wrong", "creds") + "\r\n\r\n";
                     co_await write_raw(a, header);
                     std::string target;
                     const auto err = co_await server->read_handshake(target);
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthTrustTunnelConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<trusttunnel::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "user", "pass");
                     b.close(); // 对端全关 → 发送 CONNECT 头失败 → io_error
                     const auto err = co_await client->write_handshake("example.com", 443);
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthTrustTunnelConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<trusttunnel::conn<>>(std::make_shared<memory_stream>(std::move(a)),
                                                          "user", "pass");
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // gun conn 错误路径
    // =========================================================================

    TEST(StealthGunConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<gun::conn<>>(std::make_shared<memory_stream>(std::move(b)));
                     a.close(); // 对端关闭 → 无 CONNECT 首行 → bad_magic
                     std::string host;
                     const auto err = co_await server->read_handshake(host);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthGunConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<gun::conn<>>(std::make_shared<memory_stream>(std::move(b)));
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/2\r\n\r\n");
                     std::string host;
                     const auto err = co_await server->read_handshake(host);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthGunConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto client = std::make_shared<gun::conn<>>(std::make_shared<memory_stream>(std::move(a)));
                     b.close(); // 对端全关 → 发送 CONNECT 帧失败 → io_error
                     const auto err = co_await client->write_handshake("example.com");
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthGunConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<gun::conn<>>(std::make_shared<memory_stream>(std::move(a)));
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // WebSocket conn 错误路径
    // =========================================================================

    /// 标准测试密钥（RFC 6455 示例）
    inline constexpr const char *kTestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    TEST(StealthWsConnError, WriteHandshakeNon101)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：回复 200（非 101）→ 客户端 bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(as_bytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto client = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(a)));
                     const auto err = co_await client->write_handshake(kTestKey, "example.com");
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeBadAccept)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：101 但 Sec-WebSocket-Accept 错误 → 客户端 bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(as_bytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                                  "Upgrade: websocket\r\n"
                                                  "Connection: Upgrade\r\n"
                                                  "Sec-WebSocket-Accept: wrong-accept-value\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto client = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(a)));
                     const auto err = co_await client->write_handshake(kTestKey, "example.com");
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：读取请求后直接关闭 → 客户端读响应 EOF → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(as_bytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         b.close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto client = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(a)));
                     const auto err = co_await client->write_handshake(kTestKey, "example.com");
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(b)));
                     // 普通 HTTP 请求（无 Upgrade）→ bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string key;
                     const auto err = co_await server->read_handshake(key);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeMissingKey)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(b)));
                     // 有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                           "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
                     std::string key;
                     const auto err = co_await server->read_handshake(key);
                     EXPECT_EQ(err, error::bad_magic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(b)));
                     // 有效 Upgrade 请求后对端关闭 → 发送 101 响应失败 → io_error
                     const std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                             "Sec-WebSocket-Key: " +
                                             std::string(kTestKey) + "\r\n"
                                             "Sec-WebSocket-Version: 13\r\n\r\n";
                     co_await write_raw(a, req);
                     a.close();
                     std::string key;
                     const auto err = co_await server->read_handshake(key);
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthWsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(a)));
        check_not_open_read_write(conn, ioc);
    }

    // =========================================================================
    // VMess conn 错误路径
    // =========================================================================

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x20 + i);
        }
        return uuid;
    }

    /// 构造 vmess 目标地址
    auto make_addr(vmess::address_type type, std::string host, std::uint16_t port) -> vmess::address
    {
        vmess::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    TEST(StealthVmessConnError, NotOpenReadWrite)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：流式读写与数据报收发均返回 not_open
                     auto c = std::make_shared<vmess::conn<>>(test_uuid());
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                     ec.clear();
                     const auto w = co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                     std::vector<std::uint8_t> payload;
                     const auto rerr = co_await c->async_receive_datagram(payload);
                     EXPECT_EQ(rerr, error::not_open);
                     const auto serr = co_await c->async_send_datagram(std::span<const std::uint8_t>{});
                     EXPECT_EQ(serr, error::not_open);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeBadResponse)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：回复垃圾长度块 → 响应长度解密失败 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 18> garbage{};
                         garbage.fill(0xFF);
                         std::error_code ec;
                         co_await b.async_write_some(as_bytes(std::span<const std::uint8_t>(garbage)), ec);
                         EXPECT_FALSE(ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto cli = std::make_shared<vmess::conn<>>(test_uuid());
                     const auto err = co_await cli->write_handshake(
                         std::make_shared<memory_stream>(std::move(a)),
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(err, error::bad_auth);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto cli = std::make_shared<vmess::conn<>>(test_uuid());
                     b.close(); // 对端全关 → 发送认证头失败 → io_error
                     const auto err = co_await cli->write_handshake(
                         std::make_shared<memory_stream>(std::move(a)),
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始客户端：发送垃圾认证头前缀 → 长度字段解密失败 → bad_auth
                     std::array<std::uint8_t, 42> garbage{};
                     garbage.fill(0xFF);
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(garbage)), ec);
                     EXPECT_FALSE(ec);

                     auto server = std::make_shared<vmess::conn<>>(test_uuid());
                     auto [err, msg] =
                         co_await server->read_handshake(std::make_shared<memory_stream>(std::move(b)));
                     EXPECT_EQ(err, error::bad_auth);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server = std::make_shared<vmess::conn<>>(test_uuid());
                     a.close(); // 对端关闭 → 读认证头前缀 EOF → io_error
                     auto [err, msg] =
                         co_await server->read_handshake(std::make_shared<memory_stream>(std::move(b)));
                     EXPECT_EQ(err, error::io_error);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ChunkTagMismatch)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手后写入垃圾 chunk 头 → 客户端 tag 校验失败
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         std::array<std::byte, 18> garbage{};
                         garbage.fill(std::byte{0xFF});
                         std::error_code ec;
                         co_await conn->next_layer()->async_write_some(garbage, ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     // 空缓冲写入：直接返回 0 且无错误
                     std::error_code ec;
                     const auto wn = co_await cli->async_write_some(std::span<const std::byte>{}, ec);
                     EXPECT_EQ(wn, 0u);
                     EXPECT_FALSE(ec);
                     // 垃圾 chunk 头 → 长度字段 tag 校验失败 → bad_auth
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(error::bad_auth));
                     cli->close();
                 });
    }

    TEST(StealthVmessConnError, EofDuringChunkRead)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手后直接关闭 → 客户端读 chunk 头 EOF
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::none);
                         if (conn)
                         {
                             conn->close();
                         }
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(error::unexpected_eof));
                     cli->close();
                 });
    }

    TEST(StealthVmessConnError, FinishBlockThenEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 写结束块 → 关闭
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         const auto body_key = vmess::kdf(req.request_key, req.request_nonce);
                         std::array<std::uint8_t, 16> chunk_key{};
                         std::memcpy(chunk_key.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> chunk_nonce{};
                         std::memcpy(chunk_nonce.data(), req.request_nonce.data(), 12);
                         vmess::chunk_encryptor enc(chunk_key, chunk_nonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.finish(end_block);
                         std::error_code ec;
                         co_await conn->next_layer()->async_write_some(
                             as_bytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     // 结束块 → 流结束：0 字节且无错误（read_chunk 置 eof_ 分支）
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n1 = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n1, 0u);
                     EXPECT_FALSE(ec);
                     // 再次读取：eof_ 已置位 → 仍返回 0 且无错误（入口 eof_ 分支）
                     const auto n2 = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n2, 0u);
                     EXPECT_FALSE(ec);
                     cli->close();
                 });
    }

    TEST(StealthVmessConnError, DatagramFinishEof)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept（udp 命令）→ 写结束块 → 关闭
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         const auto body_key = vmess::kdf(req.request_key, req.request_nonce);
                         std::array<std::uint8_t, 16> chunk_key{};
                         std::memcpy(chunk_key.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> chunk_nonce{};
                         std::memcpy(chunk_nonce.data(), req.request_nonce.data(), 12);
                         vmess::chunk_encryptor enc(chunk_key, chunk_nonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.finish(end_block);
                         std::error_code ec;
                         co_await conn->next_layer()->async_write_some(
                             as_bytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 443), vmess::command::udp);
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     // 结束块 → 数据报接收 unexpected_eof（read_chunk 置 eof_ 分支）
                     std::vector<std::uint8_t> payload;
                     const auto derr1 = co_await cli->async_receive_datagram(payload);
                     EXPECT_EQ(derr1, error::unexpected_eof);
                     // 再次接收：eof_ 已置位 → 直接 unexpected_eof（入口 eof_ 分支）
                     const auto derr2 = co_await cli->async_receive_datagram(payload);
                     EXPECT_EQ(derr2, error::unexpected_eof);
                     cli->close();
                 });
    }

} // namespace
