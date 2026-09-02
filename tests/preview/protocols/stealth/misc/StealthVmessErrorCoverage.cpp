/**
 * @file StealthVmessErrorCoverage.cpp
 * @brief stealth Conn 与 vmess Conn 错误路径覆盖
 * @details 针对测试库 Conn 装饰器的握手错误路径与数据面错误分支：
 * 1. stealth 各方案（anytls / shadowtls / reality / restls /
 *    trusttunnel / gun / ws）ReadHandshake / WriteHandshake
 *    错误路径：底层 EOF、校验失败（bad_auth）、魔数不匹配
 *    （bad_magic）、密钥派生失败（kdf_error）、发送失败（io_error）
 * 2. vmess Conn 数据面错误分支：未握手读写（not_open）、
 *    chunk 解密失败（bad_auth）、EOF（unexpected_eof）、
 *    结束块（Finish）→ 流结束（0 且无错误）
 * @note 使用 MakeMemoryPair 建立内存传输对，手动注入合法/非法
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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>
#include <preview/Protocols/Anytls/Codec.hpp>
#include <preview/Protocols/Anytls/Conn.hpp>
#include <preview/Protocols/Gun/Conn.hpp>
#include <preview/Protocols/Reality/Codec.hpp>
#include <preview/Protocols/Reality/Conn.hpp>
#include <preview/Protocols/Restls/Conn.hpp>
#include <preview/Protocols/Shadowtls/Conn.hpp>
#include <preview/Protocols/Trusttunnel/Codec.hpp>
#include <preview/Protocols/Trusttunnel/Conn.hpp>
#include <preview/Protocols/Ws/Codec.hpp>
#include <preview/Protocols/Ws/Conn.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
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
    auto write_raw(MemoryStream &Stream, std::string_view Data) -> net::awaitable<void>
    {
        std::error_code ec;
        co_await Stream.async_write_some(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size()), ec);
        co_return;
    }

    /// 未握手 Conn：读写返回 not_open（所有 stealth 方案共用）
    template <typename ConnT>
    auto check_not_open_read_write(const std::shared_ptr<ConnT> &Conn, net::io_context &ioc) -> void
    {
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await Conn->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                 });
    }

    // =========================================================================
    // AnyTLS Conn 错误路径
    // =========================================================================

    TEST(StealthAnyTlsConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：对端直接关闭 → 读帧头 EOF → unexpected_eof
                     auto Server =
                         std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(b)), "pw");
                     a.Close();
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakePartialFrameEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server =
                         std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(b)), "pw");
                     // 只发帧头（Hash + padlen），随后半关 → 读 padding 时 EOF
                     std::string Frame;
                     EXPECT_EQ(Anytls::BuildAuthFrame("pw", 16, Frame), Error::None);
                     std::error_code ec;
                     co_await a.async_write_some(
                         AsBytes(AsU8Span(Frame).first(Anytls::AuthFrameHdrlen)), ec);
                     EXPECT_FALSE(ec);
                     a.Shutdown();
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Anytls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "Expect-pw");
                     // 客户端用错误密码构造认证帧 → 密码哈希不匹配 → bad_auth
                     std::string Frame;
                     EXPECT_EQ(Anytls::BuildAuthFrame("wrong-pw", 16, Frame), Error::None);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(AsU8Span(Frame)), ec);
                     EXPECT_FALSE(ec);
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthAnyTlsConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Anytls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     b.Close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await Client->WriteHandshake();
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthAnyTlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // ShadowTLS v3 Conn 错误路径
    // =========================================================================

    TEST(StealthShadowTlsConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "pw");
                     a.Close(); // 对端关闭 → 读 ClientHello EOF → unexpected_eof
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x11, Shadowtls::TlsRndSize);
        const auto client_rnd = make_random(0x22, Shadowtls::TlsRndSize);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 客户端用错误密码构造 ClientHello（SessionId HMAC 不匹配）
                     auto Client = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "wrong-pw");
                     const auto werr = co_await Client->WriteHandshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(werr, Error::None);
                     auto Server = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "Expect-pw");
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthShadowTlsConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x33, Shadowtls::TlsRndSize);
        const auto client_rnd = make_random(0x44, Shadowtls::TlsRndSize);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     b.Close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await Client->WriteHandshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthShadowTlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn =
            std::make_shared<Shadowtls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // Reality Conn 错误路径
    // =========================================================================

    /// 生成 X25519 密钥对（断言成功，规避 nodiscard）
    auto make_keypair(std::array<std::uint8_t, Reality::KeyLen> &priv,
                      std::array<std::uint8_t, Reality::KeyLen> &pub) -> void
    {
        EXPECT_FALSE(Reality::GenerateKeypair(priv, pub));
    }

    /// 构造客户端密封的 SessionId（false = 成功）
    auto make_reality_sealed(std::span<const std::uint8_t> priv_cli,
                             std::span<const std::uint8_t> pub_srv,
                             std::span<const std::uint8_t> ClientRandom,
                             std::span<const std::uint8_t> hello,
                             std::span<const std::uint8_t, 8> ShortId,
                             std::array<std::uint8_t, Reality::SessionIdAuthLen> &sealed) -> bool
    {
        std::array<std::uint8_t, Reality::KeyLen> shared{};
        if (Reality::X25519Shared(priv_cli, pub_srv, shared))
        {
            return true;
        }
        std::array<std::uint8_t, Reality::KeyLen> AuthKey{};
        if (Reality::DeriveAuthKey(shared, ClientRandom, AuthKey))
        {
            return true;
        }
        std::array<std::uint8_t, 16> plain{};
        plain[0] = 0x01; // version = 1
        std::copy(ShortId.begin(), ShortId.end(), plain.begin() + 8);
        return Reality::SealSessionId(
            Reality::SessionIdSealInput{AuthKey, ClientRandom, plain, hello}, sealed);
    }

    TEST(StealthRealityConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv);
                     a.Close(); // 对端关闭 → 读 SessionId EOF → unexpected_eof
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(pub, params, out_sid);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv_cli{};
        std::array<std::uint8_t, Reality::KeyLen> pub_cli{};
        std::array<std::uint8_t, Reality::KeyLen> priv_srv{};
        std::array<std::uint8_t, Reality::KeyLen> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto ClientRandom = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 构造合法 sealed SessionId 后篡改 1 字节 → GCM tag 校验失败 → bad_auth
                     std::array<std::uint8_t, Reality::SessionIdAuthLen> sealed{};
                     EXPECT_FALSE(make_reality_sealed(priv_cli, pub_srv,
                                                      std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId, sealed));
                     sealed[0] ^= 0xFF;
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(sealed)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv_srv);
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(pub_cli, params, out_sid);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeKdfError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 先喂 32 字节（SessionId 读取），再以非法长度公钥 → kdf_error
                     std::array<std::uint8_t, 32> junk{};
                     junk.fill(0xAA);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(junk)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(bad_pub, params, out_sid);
                     EXPECT_EQ(err, Error::KdfError);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeKdfError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     const auto err = co_await Client->WriteHandshake(bad_pub, params);
                     EXPECT_EQ(err, Error::KdfError);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv_cli{};
        std::array<std::uint8_t, Reality::KeyLen> pub_cli{};
        std::array<std::uint8_t, Reality::KeyLen> priv_srv{};
        std::array<std::uint8_t, Reality::KeyLen> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto ClientRandom = make_random(0x55, 40);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), priv_cli);
                     b.Close(); // 对端全关 → 发送 sealed SessionId 失败 → io_error
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     const auto err = co_await Client->WriteHandshake(pub_srv, params);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthRealityConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Reality::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                      std::array<std::uint8_t, 32>{});
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // Restls Conn 错误路径
    // =========================================================================

    TEST(StealthRestlsConnError, WriteHandshakeBadLength)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // ServerRandom 长度非法（31 字节）→ bad_length
                     auto Client = std::make_shared<Restls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     const std::array<std::uint8_t, 31> short_rnd{};
                     const auto err =
                         co_await Client->WriteHandshake(std::span<const std::uint8_t>(short_rnd));
                     EXPECT_EQ(err, Error::BadLength);
                 });
    }

    TEST(StealthRestlsConnError, ReadHandshakeBadLength)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // ServerRandom 长度非法（33 字节）→ bad_length
                     auto Server = std::make_shared<Restls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "pw");
                     const std::array<std::uint8_t, 33> long_rnd{};
                     const auto err =
                         co_await Server->ReadHandshake(std::span<const std::uint8_t>(long_rnd));
                     EXPECT_EQ(err, Error::BadLength);
                 });
    }

    TEST(StealthRestlsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Restls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // TrustTunnel Conn 错误路径
    // =========================================================================

    TEST(StealthTrustTunnelConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     a.Close(); // 对端关闭 → 头块不完整 → bad_magic
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeMissingAuth)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // CONNECT 但无 Proxy-Authorization 头 → bad_auth
                     co_await write_raw(a, "CONNECT example.com:443 HTTP/2\r\n\r\n");
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeWrongCreds)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // Basic Auth 凭据错误 → bad_auth
                     const std::string Header =
                         "CONNECT example.com:443 HTTP/2\r\n"
                         "Proxy-Authorization: " +
                         Trusttunnel::BasicAuth("wrong", "creds") + "\r\n\r\n";
                     co_await write_raw(a, Header);
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthTrustTunnelConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "user", "pass");
                     b.Close(); // 对端全关 → 发送 CONNECT 头失败 → io_error
                     const auto err = co_await Client->WriteHandshake("example.com", 443);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthTrustTunnelConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Trusttunnel::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                          "user", "pass");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // gun Conn 错误路径
    // =========================================================================

    TEST(StealthGunConnError, ReadHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     a.Close(); // 对端关闭 → 无 CONNECT 首行 → bad_magic
                     std::string host;
                     const auto err = co_await Server->ReadHandshake(host);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthGunConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/2\r\n\r\n");
                     std::string host;
                     const auto err = co_await Server->ReadHandshake(host);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthGunConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Client = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端全关 → 发送 CONNECT 帧失败 → io_error
                     const auto err = co_await Client->WriteHandshake("example.com");
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthGunConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // WebSocket Conn 错误路径
    // =========================================================================

    /// 标准测试密钥（RFC 6455 示例）
    inline constexpr const char *kTestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    TEST(StealthWsConnError, WriteHandshakeNon101)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：回复 200（非 101）→ 客户端 bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto Client = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     const auto err = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeBadAccept)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：101 但 Sec-WebSocket-Accept 错误 → 客户端 bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                                  "Upgrade: websocket\r\n"
                                                  "Connection: Upgrade\r\n"
                                                  "Sec-WebSocket-Accept: wrong-Accept-value\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto Client = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     const auto err = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：读取请求后直接关闭 → 客户端读响应 EOF → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n =
                             co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         b.Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto Client = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     const auto err = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeBadMagic)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 普通 HTTP 请求（无 Upgrade）→ bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeMissingKey)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                           "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 有效 Upgrade 请求后对端关闭 → 发送 101 响应失败 → io_error
                     const std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                             "Sec-WebSocket-Key: " +
                                             std::string(kTestKey) + "\r\n"
                                             "Sec-WebSocket-Version: 13\r\n\r\n";
                     co_await write_raw(a, req);
                     a.Close();
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthWsConnError, NotOpenReadWrite)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // VMess Conn 错误路径
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
    auto make_addr(Vmess::AddressType Type, std::string host, std::uint16_t port) -> Vmess::Address
    {
        Vmess::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    TEST(StealthVmessConnError, NotOpenReadWrite)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：流式读写与数据报收发均返回 not_open
                     auto c = std::make_shared<Vmess::Conn<>>(test_uuid());
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     std::vector<std::uint8_t> payload;
                     const auto rerr = co_await c->AsyncReceiveDatagram(payload);
                     EXPECT_EQ(rerr, Error::NotOpen);
                     const auto serr = co_await c->AsyncSendDatagram(std::span<const std::uint8_t>{});
                     EXPECT_EQ(serr, Error::NotOpen);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeBadResponse)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：回复垃圾长度块 → 响应长度解密失败 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 18> garbage{};
                         garbage.fill(0xFF);
                         std::error_code ec;
                         co_await b.async_write_some(AsBytes(std::span<const std::uint8_t>(garbage)), ec);
                         EXPECT_FALSE(ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto cli = std::make_shared<Vmess::Conn<>>(test_uuid());
                     const auto err = co_await cli->WriteHandshake(
                         std::make_shared<MemoryStream>(std::move(a)),
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto cli = std::make_shared<Vmess::Conn<>>(test_uuid());
                     b.Close(); // 对端全关 → 发送认证头失败 → io_error
                     const auto err = co_await cli->WriteHandshake(
                         std::make_shared<MemoryStream>(std::move(a)),
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeBadAuth)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始客户端：发送垃圾认证头前缀 → 长度字段解密失败 → bad_auth
                     std::array<std::uint8_t, 42> garbage{};
                     garbage.fill(0xFF);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(garbage)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Vmess::Conn<>>(test_uuid());
                     auto [err, msg] =
                         co_await Server->ReadHandshake(std::make_shared<MemoryStream>(std::move(b)));
                     EXPECT_EQ(err, Error::BadAuth);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Server = std::make_shared<Vmess::Conn<>>(test_uuid());
                     a.Close(); // 对端关闭 → 读认证头前缀 EOF → io_error
                     auto [err, msg] =
                         co_await Server->ReadHandshake(std::make_shared<MemoryStream>(std::move(b)));
                     EXPECT_EQ(err, Error::IoError);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ChunkTagMismatch)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手后写入垃圾 chunk 头 → 客户端 tag 校验失败
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         std::array<std::byte, 18> garbage{};
                         garbage.fill(std::byte{0xFF});
                         std::error_code ec;
                         co_await Conn->NextLayer()->async_write_some(garbage, ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::None);
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
                     EXPECT_EQ(ec, make_error_code(Error::BadAuth));
                     cli->Close();
                 });
    }

    TEST(StealthVmessConnError, EofDuringChunkRead)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手后直接关闭 → 客户端读 chunk 头 EOF
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::None);
                         if (Conn)
                         {
                             Conn->Close();
                         }
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::UnexpectedEof));
                     cli->Close();
                 });
    }

    TEST(StealthVmessConnError, FinishBlockThenEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 写结束块 → 关闭
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         const auto body_key = Vmess::Kdf(req.RequestKey, req.RequestNonce);
                         std::array<std::uint8_t, 16> ChunkKey{};
                         std::memcpy(ChunkKey.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> ChunkNonce{};
                         std::memcpy(ChunkNonce.data(), req.RequestNonce.data(), 12);
                         Vmess::ChunkEncryptor enc(ChunkKey, ChunkNonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.Finish(end_block);
                         std::error_code ec;
                         co_await Conn->NextLayer()->async_write_some(
                             AsBytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     // 结束块 → 流结束：0 字节且无错误（ReadChunk 置 Eof_ 分支）
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n1 = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n1, 0u);
                     EXPECT_FALSE(ec);
                     // 再次读取：Eof_ 已置位 → 仍返回 0 且无错误（入口 Eof_ 分支）
                     const auto n2 = co_await cli->async_read_some(buf, ec);
                     EXPECT_EQ(n2, 0u);
                     EXPECT_FALSE(ec);
                     cli->Close();
                 });
    }

    TEST(StealthVmessConnError, DatagramFinishEof)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept（udp 命令）→ 写结束块 → 关闭
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         const auto body_key = Vmess::Kdf(req.RequestKey, req.RequestNonce);
                         std::array<std::uint8_t, 16> ChunkKey{};
                         std::memcpy(ChunkKey.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> ChunkNonce{};
                         std::memcpy(ChunkNonce.data(), req.RequestNonce.data(), 12);
                         Vmess::ChunkEncryptor enc(ChunkKey, ChunkNonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.Finish(end_block);
                         std::error_code ec;
                         co_await Conn->NextLayer()->async_write_some(
                             AsBytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, cli] = co_await Vmess::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443),
                         static_cast<std::uint8_t>(Vmess::Command::Udp)});
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     // 结束块 → 数据报接收 unexpected_eof（ReadChunk 置 Eof_ 分支）
                     std::vector<std::uint8_t> payload;
                     const auto derr1 = co_await cli->AsyncReceiveDatagram(payload);
                     EXPECT_EQ(derr1, Error::UnexpectedEof);
                     // 再次接收：Eof_ 已置位 → 直接 unexpected_eof（入口 Eof_ 分支）
                     const auto derr2 = co_await cli->AsyncReceiveDatagram(payload);
                     EXPECT_EQ(derr2, Error::UnexpectedEof);
                     cli->Close();
                 });
    }

} // namespace
