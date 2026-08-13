/**
 * @file QuicGatewayE2E.cpp
 * @brief QUIC 入站网关端到端测试（Hysteria2 / TUIC v5）
 * @details 搭建最小网关环境（进程资源 + worker + balancer + quic_gateway），
 *          用 quic::client 模拟真实客户端：
 *          Hysteria2：HTTP/3 认证（POST /auth + QPACK）→ 0x401 TCP 帧 → 回显
 *          TUIC v5：uni stream 认证（Exporter token）→ Connect 帧 → 回显
 */

#include <prism/diagnose/log.hpp>
#include <prism/net/transport/quic/server.hpp>
#include <prism/protocol/hysteria2/codec.hpp>
#include <prism/protocol/hysteria2/h3_auth.hpp>
#include <prism/protocol/hysteria2/qpack.hpp>
#include <prism/protocol/tuic/codec.hpp>
#include <prism/resource/process.hpp>
#include <prism/resource/worker.hpp>
#include <prism/runtime/front/quic_gateway.hpp>
#include <prism/runtime/runtime.hpp>
#include <prism/user/directory.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <thread>

#include <gtest/gtest.h>

namespace
{
    namespace quic = psm::quic;
    namespace net = boost::asio;
    using udp = net::ip::udp;
    using tcp = net::ip::tcp;

    void configure_self_signed(net::ssl::context &ctx)
    {
        auto *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *pkey = nullptr;
        if (pkey_ctx && EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) > 0)
        {
            EVP_PKEY_keygen(pkey_ctx, &pkey);
        }
        EVP_PKEY_CTX_free(pkey_ctx);
        ASSERT_NE(pkey, nullptr);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("quic-gateway-e2e"), -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey);
        SSL_CTX_set_alpn_select_cb(
            ctx.native_handle(),
            [](SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
               unsigned int inlen, void *) -> int
            {
                if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                                          reinterpret_cast<const unsigned char *>("\x2h3"), 3, in,
                                          inlen) == OPENSSL_NPN_NEGOTIATED)
                {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_NOACK;
            },
            nullptr);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }

    /// 最小网关环境
    struct gateway_env
    {
        std::shared_ptr<psm::settings> cfg;
        std::shared_ptr<net::ssl::context> ssl_ctx;
        std::shared_ptr<psm::user::directory> accounts;
        std::shared_ptr<psm::resource::process> process;
        std::shared_ptr<psm::resource::worker> worker;
        std::shared_ptr<psm::runtime::front::balancer> dispatcher;
        std::shared_ptr<psm::runtime::front::quic_gateway> gateway;
        std::thread worker_thread;
        std::uint16_t port{0};

        void setup(bool hysteria2, bool tuic)
        {
            // 随机端口：先绑定探测
            net::io_context probe_ioc;
            udp::socket probe(probe_ioc, udp::endpoint(net::ip::address_v4::loopback(), 0));
            port = probe.local_endpoint().port();
            probe.close();

            cfg = std::make_shared<psm::settings>();
            cfg->instance.addressable.host = "127.0.0.1";
            cfg->instance.addressable.port = port;
            cfg->instance.auth.users.push_back(
                psm::runtime::authentication::user{.password = "hysteria2_password",
                                                   .uuid = "123e4567-e89b-12d3-a456-426614174000",
                                                   .max_connections = 0});
            cfg->buffer.size = 65536;
            cfg->stealth.hysteria2.enable = hysteria2;
            cfg->stealth.hysteria2.users.push_back(psm::memory::string("hysteria2_password"));
            cfg->stealth.tuic.enable = tuic;
            cfg->stealth.tuic.users.push_back(psm::handshake::tuic::user{
                .uuid = psm::memory::string("123e4567-e89b-12d3-a456-426614174000"),
                .password = psm::memory::string("tuic_password")});

            ssl_ctx = std::make_shared<net::ssl::context>(net::ssl::context::tlsv13);
            ssl_ctx->set_options(net::ssl::context::default_workarounds);
            configure_self_signed(*ssl_ctx);

            accounts = std::make_shared<psm::user::directory>(psm::memory::current_resource());
            accounts->upsert("hysteria2_password", 0);
            accounts->upsert("123e4567-e89b-12d3-a456-426614174000", 0);

            process = std::make_shared<psm::resource::process>(
                psm::resource::process::options{cfg, ssl_ctx, accounts});

            worker = std::make_shared<psm::resource::worker>(
                psm::resource::worker::options{process, psm::memory::current_resource(), 0});

            psm::memory::vector<psm::runtime::front::balancer::worker_binding> bindings;
            bindings.push_back(psm::runtime::front::balancer::worker_binding{
                [](tcp::socket) {}, []() -> psm::stats::worker_snapshot { return {}; },
                []() -> bool { return true; }});
            dispatcher = std::make_shared<psm::runtime::front::balancer>(std::move(bindings));

            psm::memory::vector<std::shared_ptr<psm::resource::worker>> workers;
            workers.push_back(worker);

            gateway =
                std::make_shared<psm::runtime::front::quic_gateway>(*cfg, *dispatcher, std::move(workers));
            gateway->start();
            worker_thread = std::thread([this]() { worker->ioc.run(); });
        }

        void teardown()
        {
            gateway->stop();
            worker->stop();
            if (worker_thread.joinable())
            {
                worker_thread.join();
            }
        }
    };

    /// 模拟客户端驱动
    struct mock_client
    {
        net::io_context ioc;
        std::shared_ptr<udp::socket> sock;
        std::shared_ptr<net::ssl::context> client_ctx;
        std::shared_ptr<quic::client> qc;
        std::map<std::int64_t, std::vector<std::byte>> recv_data;
        bool handshake_done{false};
        std::chrono::steady_clock::time_point deadline;

        explicit mock_client(const std::uint16_t server_port)
        {
            sock = std::make_shared<udp::socket>(ioc, udp::endpoint(net::ip::address_v4::loopback(), 0));
            client_ctx = std::make_shared<net::ssl::context>(net::ssl::context::tlsv13);
            client_ctx->set_verify_mode(net::ssl::verify_none);
            static const unsigned char h3_alpn[] = {0x02, 'h', '3'};
            SSL_CTX_set_alpn_protos(client_ctx->native_handle(), h3_alpn, sizeof(h3_alpn));

            qc = quic::make_client(quic::client_options{
                .executor = ioc.get_executor(),
                .peer = udp::endpoint(net::ip::address_v4::loopback(), server_port),
                .udp = sock,
                .ssl_ctx = client_ctx->native_handle(),
                .host = "quic-gateway-e2e",
                .mr = psm::memory::current_resource(),
                .prefix = std::make_shared<psm::diagnose::context>(),
            });
            qc->on_handshake_complete = [this]() { handshake_done = true; };
            qc->on_stream_data = [this](std::int64_t sid, std::span<const std::byte> data)
            {
                auto &v = recv_data[sid];
                v.insert(v.end(), data.begin(), data.end());
            };
        }

        void start_pump()
        {
            net::co_spawn(
                ioc,
                [this]() -> net::awaitable<void>
                {
                    std::array<std::byte, 65536> buf{};
                    while (true)
                    {
                        boost::system::error_code ec;
                        udp::endpoint from;
                        const auto n =
                            co_await sock->async_receive_from(net::buffer(buf.data(), buf.size()), from,
                                                              net::redirect_error(net::use_awaitable, ec));
                        if (ec || n == 0)
                        {
                            break;
                        }
                        co_await qc->handle_datagram(from, std::span<const std::byte>(buf.data(), n));
                    }
                },
                net::detached);
        }

        auto wait_handshake(const std::chrono::milliseconds timeout) -> bool
        {
            auto end = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < end)
            {
                ioc.poll();
                net::co_spawn(
                    ioc, [this]() -> net::awaitable<void> { co_await qc->flush_handshake(); }, net::detached);
                ioc.poll();
                if (handshake_done)
                {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            return handshake_done;
        }

        auto read_stream(std::int64_t sid, const std::size_t want, const std::chrono::milliseconds timeout)
            -> bool
        {
            auto end = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < end)
            {
                ioc.poll();
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                auto it = recv_data.find(sid);
                if (it != recv_data.end() && it->second.size() >= want)
                {
                    return true;
                }
            }
            return recv_data[sid].size() >= want;
        }

        auto write_stream(std::int64_t sid, std::span<const std::byte> data) -> void
        {
            net::co_spawn(
                ioc,
                [this, sid, d = std::vector<std::byte>(data.begin(), data.end())]() -> net::awaitable<void>
                { co_await qc->write_stream_data(sid, d); }, net::detached);
            // 驱动协程直至写入完成（多轮 poll 保证 QUIC 包发出）
            for (int i = 0; i < 200; ++i)
            {
                ioc.poll();
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    };

    /// echo TCP 服务器
    struct echo_server
    {
        net::io_context ioc;
        tcp::acceptor acceptor;
        std::thread thread;
        std::uint16_t port{0};

        echo_server() : acceptor(ioc, tcp::endpoint(net::ip::address_v4::loopback(), 0))
        {
            port = acceptor.local_endpoint().port();
            accept_loop();
            thread = std::thread([this]() { ioc.run(); });
        }

        ~echo_server()
        {
            boost::system::error_code ec;
            acceptor.close(ec);
            ioc.stop();
            if (thread.joinable())
            {
                thread.join();
            }
        }

        void accept_loop()
        {
            net::co_spawn(
                ioc,
                [this]() -> net::awaitable<void>
                {
                    while (true)
                    {
                        boost::system::error_code ec;
                        auto sock =
                            co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));
                        if (ec)
                        {
                            break;
                        }
                        net::co_spawn(
                            ioc,
                            [sock = std::move(sock)]() mutable -> net::awaitable<void>
                            {
                                std::array<std::byte, 4096> buf{};
                                while (true)
                                {
                                    boost::system::error_code rec;
                                    const auto n = co_await sock.async_read_some(
                                        net::buffer(buf.data(), buf.size()),
                                        net::redirect_error(net::use_awaitable, rec));
                                    if (rec || n == 0)
                                    {
                                        break;
                                    }
                                    boost::system::error_code wr;
                                    co_await sock.async_write_some(
                                        net::buffer(buf.data(), n),
                                        net::redirect_error(net::use_awaitable, wr));
                                    if (wr)
                                    {
                                        break;
                                    }
                                }
                            },
                            net::detached);
                    }
                },
                net::detached);
        }
    };

    std::array<std::uint8_t, 16> parse_uuid(const std::string_view hex)
    {
        std::array<std::uint8_t, 16> out{};
        std::size_t out_idx = 0;
        std::uint8_t nibble = 0;
        bool hi = true;
        for (const char c : hex)
        {
            if (c == '-')
            {
                continue;
            }
            std::uint8_t d = 0;
            if (c >= '0' && c <= '9')
            {
                d = static_cast<std::uint8_t>(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                d = static_cast<std::uint8_t>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F')
            {
                d = static_cast<std::uint8_t>(c - 'A' + 10);
            }
            if (hi)
            {
                nibble = static_cast<std::uint8_t>(d << 4);
                hi = false;
            }
            else
            {
                out[out_idx++] = static_cast<std::uint8_t>(nibble | d);
                hi = true;
            }
        }
        return out;
    }

    /// 构造 Hysteria2 HTTP/3 认证请求（HEADERS 帧 + QPACK 块）
    /// 与 quic-go（mihomo 客户端）字节级兼容：QPACK 前缀 + 静态表索引
    /// + 字面量字段（H=0 无 huffman，避免自研编码与 RFC 差异）。
    std::vector<std::byte> BuildH3AuthRequest(const std::string &password)
    {
        auto append = [](std::vector<std::byte> &v, const std::string_view s)
        {
            v.insert(v.end(), reinterpret_cast<const std::byte *>(s.data()),
                     reinterpret_cast<const std::byte *>(s.data() + s.size()));
        };
        // 字面量值（H=0）：7 位长度前缀（<128 单字节）
        auto val = [&](std::vector<std::byte> &v, const std::string_view s)
        {
            v.push_back(std::byte{static_cast<unsigned char>(s.size())});
            append(v, s);
        };
        // 字面量名称（H=0）：001 + 3 位长度前缀
        auto lit_name = [&](std::vector<std::byte> &v, const std::string_view name)
        {
            if (name.size() < 8)
            {
                v.push_back(std::byte{static_cast<unsigned char>(0x20 | name.size())});
            }
            else
            {
                v.push_back(std::byte{0x27});
                v.push_back(std::byte{static_cast<unsigned char>(name.size() - 7)});
            }
            append(v, name);
        };
        // 名称引用静态表（01N S Index）：S 位 = bit4（0x10）= 静态表，索引 4 位
        auto ref_name = [&](std::vector<std::byte> &v, const std::size_t index)
        { v.push_back(std::byte{static_cast<unsigned char>(0x50 | index)}); };

        std::vector<std::byte> block;
        // QPACK Header Block Prefix：Required Insert Count=0 + Delta Base=0
        block.push_back(std::byte{0x00});
        block.push_back(std::byte{0x00});
        // :method POST（静态表 20）
        block.push_back(std::byte{0xD4});
        // :scheme https（静态表 23）
        block.push_back(std::byte{0xD7});
        // :authority hysteria（名称引用静态表 0）
        ref_name(block, 0);
        val(block, "hysteria");
        // :path /auth（名称引用静态表 1）
        ref_name(block, 1);
        val(block, "/auth");
        // hysteria-auth（字面量名称）
        lit_name(block, "hysteria-auth");
        val(block, password);
        // hysteria-cc-rx: 0
        lit_name(block, "hysteria-cc-rx");
        val(block, "0");
        // hysteria-padding: 0
        lit_name(block, "hysteria-padding");
        val(block, "0");

        std::vector<std::byte> frame;
        frame.push_back(std::byte{0x01}); // HEADERS 帧类型
        // length：QUIC varint（首字节高 2 位定长：00=1B, 01=2B, 10=4B, 11=8B）
        std::size_t len = block.size();
        std::vector<std::byte> len_bytes;
        if (len < 64)
        {
            len_bytes.push_back(std::byte{static_cast<unsigned char>(len)});
        }
        else if (len < 16384)
        {
            len_bytes.push_back(std::byte{static_cast<unsigned char>(0x40 | (len >> 8))});
            len_bytes.push_back(std::byte{static_cast<unsigned char>(len & 0xFF)});
        }
        else
        {
            len_bytes.push_back(std::byte{static_cast<unsigned char>(0x80 | ((len >> 24) & 0x3F))});
            len_bytes.push_back(std::byte{static_cast<unsigned char>((len >> 16) & 0xFF)});
            len_bytes.push_back(std::byte{static_cast<unsigned char>((len >> 8) & 0xFF)});
            len_bytes.push_back(std::byte{static_cast<unsigned char>(len & 0xFF)});
        }
        frame.insert(frame.end(), len_bytes.begin(), len_bytes.end());
        frame.insert(frame.end(), block.begin(), block.end());
        return frame;
    }

    /// 构造 TUIC 认证帧：[VER][TYPE 0x00][UUID 16B][TOKEN 32B]
    std::vector<std::byte> BuildTuicAuth(SSL *ssl, const std::array<std::uint8_t, 16> &uuid_bytes,
                                         const std::string &password)
    {
        namespace tuic = psm::protocol::tuic;
        std::vector<std::byte> auth;
        auth.push_back(std::byte{tuic::version});
        auth.push_back(std::byte{static_cast<std::uint8_t>(tuic::command::authenticate)});
        auth.insert(auth.end(), reinterpret_cast<const std::byte *>(uuid_bytes.data()),
                    reinterpret_cast<const std::byte *>(uuid_bytes.data() + 16));
        std::array<std::uint8_t, 32> token{};
        EXPECT_EQ(SSL_export_keying_material(ssl, token.data(), token.size(),
                                             reinterpret_cast<const char *>(uuid_bytes.data()), 16,
                                             reinterpret_cast<const unsigned char *>(password.data()),
                                             static_cast<int>(password.size()), 1),
                  1);
        auth.insert(auth.end(), reinterpret_cast<const std::byte *>(token.data()),
                    reinterpret_cast<const std::byte *>(token.data() + 32));
        return auth;
    }
} // namespace

TEST(QuicGatewayE2E, Hysteria2TcpEcho)
{
    gateway_env env;
    env.setup(true, false);

    echo_server echo;

    mock_client client(env.port);
    client.start_pump();
    client.qc->start();
    ASSERT_TRUE(client.wait_handshake(std::chrono::seconds(5)));

    // 1. HTTP/3 认证：控制流（流类型 0x00 + SETTINGS 帧）+ 认证请求流（HEADERS + QPACK）
    const auto ctrl_sid = client.qc->open_uni_stream();
    ASSERT_GE(ctrl_sid, 0);
    // uni 流首字节 = 流类型 varint（0x00 控制流），随后是 SETTINGS 帧（type 0x04 + length 0）
    std::vector<std::byte> settings{std::byte{0x00}, std::byte{0x04}, std::byte{0x00}};
    client.write_stream(ctrl_sid, settings);

    const auto auth_sid = client.qc->open_stream();
    ASSERT_GE(auth_sid, 0);
    auto auth_frame = BuildH3AuthRequest("hysteria2_password");
    client.write_stream(auth_sid, auth_frame);

    // 2. 认证响应（HEADERS 帧：:status 233 + hysteria 头）——完整解析验证
    ASSERT_TRUE(client.read_stream(auth_sid, 2, std::chrono::seconds(3)));
    const auto &resp = client.recv_data[auth_sid];
    ASSERT_GE(resp.size(), 2);
    EXPECT_EQ(static_cast<unsigned char>(resp[0]), 0x01); // HEADERS 帧类型
    // 解析 QPACK 块：验证 :status 233（与 quic-go 客户端字节级一致）
    {
        std::size_t off = 1;
        std::uint64_t frame_len = 0;
        // QUIC varint 帧长（首字节高 2 位定长）
        const auto *rp = reinterpret_cast<const std::uint8_t *>(resp.data() + off);
        std::size_t flen = 0;
        switch (rp[0] >> 6)
        {
        case 0:
            flen = 1;
            frame_len = rp[0] & 0x3F;
            break;
        case 1:
            flen = 2;
            frame_len = static_cast<std::uint64_t>(rp[0] & 0x3F) << 8 | rp[1];
            break;
        case 2: flen = 4; break;
        default: flen = 8; break;
        }
        if (flen == 4)
        {
            frame_len = static_cast<std::uint64_t>(rp[0] & 0x3F) << 24 |
                        static_cast<std::uint64_t>(rp[1]) << 16 | static_cast<std::uint64_t>(rp[2]) << 8 |
                        rp[3];
        }
        off += flen;
        ASSERT_LE(off + frame_len, resp.size());
        auto fields = psm::protocol::hysteria2::qpack::decode_header_block(
            std::span<const std::uint8_t>(rp + flen, static_cast<std::size_t>(frame_len)),
            psm::memory::current_resource());
        auto find = [&fields](const std::string_view name) -> std::string_view
        {
            for (const auto &f : fields)
            {
                if (f.name == name)
                {
                    return std::string_view(f.value.data(), f.value.size());
                }
            }
            return {};
        };
        EXPECT_EQ(find(":status"), "233");
        EXPECT_EQ(find("hysteria-udp"), "true");
    }

    // 3. TCP 请求帧 + 数据（新开 bidi 流：0x401，mihomo 认证后新开流）
    const auto data_sid = client.qc->open_stream();
    ASSERT_GE(data_sid, 0);
    std::vector<std::byte> frame;
    const auto addr = "127.0.0.1:" + std::to_string(echo.port);
    std::array<std::uint8_t, 8> vt{};
    auto vn = psm::protocol::hysteria2::encode_varint(psm::protocol::hysteria2::frame_type_tcp, vt);
    frame.insert(frame.end(), reinterpret_cast<std::byte *>(vt.data()),
                 reinterpret_cast<std::byte *>(vt.data() + vn));
    vn = psm::protocol::hysteria2::encode_varint(addr.size(), vt);
    frame.insert(frame.end(), reinterpret_cast<std::byte *>(vt.data()),
                 reinterpret_cast<std::byte *>(vt.data() + vn));
    frame.insert(frame.end(), reinterpret_cast<const std::byte *>(addr.data()),
                 reinterpret_cast<const std::byte *>(addr.data() + addr.size()));
    vn = psm::protocol::hysteria2::encode_varint(0, vt);
    frame.insert(frame.end(), reinterpret_cast<std::byte *>(vt.data()),
                 reinterpret_cast<std::byte *>(vt.data() + vn));

    const std::string payload = "hello hysteria2";
    frame.insert(frame.end(), reinterpret_cast<const std::byte *>(payload.data()),
                 reinterpret_cast<const std::byte *>(payload.data() + payload.size()));

    // 在发送数据前记录基线，避免 write_stream 的 poll 期间 echo 已到达
    const auto baseline = client.recv_data[data_sid].size();
    client.write_stream(data_sid, frame);
    // 服务器必须先回 TCP 响应帧（[status 0][msg len 0][padding len 0]），随后才是 echo 数据
    ASSERT_TRUE(client.read_stream(data_sid, baseline + 3 + payload.size(), std::chrono::seconds(15)));
    const auto &echo_data = client.recv_data[data_sid];
    EXPECT_EQ(static_cast<unsigned char>(echo_data[baseline]), 0x00);     // status = 成功
    EXPECT_EQ(static_cast<unsigned char>(echo_data[baseline + 1]), 0x00); // message len = 0
    EXPECT_EQ(static_cast<unsigned char>(echo_data[baseline + 2]), 0x00); // padding len = 0
    const std::string echo_str(
        reinterpret_cast<const char *>(echo_data.data() + echo_data.size() - payload.size()), payload.size());
    EXPECT_EQ(echo_str, payload);

    env.teardown();
}

TEST(QuicGatewayE2E, TuicV5TcpEcho)
{
    gateway_env env;
    env.setup(false, true);

    echo_server echo;

    mock_client client(env.port);
    client.start_pump();
    client.qc->start();
    ASSERT_TRUE(client.wait_handshake(std::chrono::seconds(5)));

    // 1. 认证（uni stream）：VER TYPE UUID TOKEN（mihomo 兼容，无 TUCI 魔数）
    const auto auth_sid = client.qc->open_uni_stream();
    ASSERT_GE(auth_sid, 0);
    const auto uuid_bytes = parse_uuid("123e4567-e89b-12d3-a456-426614174000");
    auto auth = BuildTuicAuth(client.qc->native_ssl(), uuid_bytes, "tuic_password");
    client.write_stream(auth_sid, auth);
    // mihomo 客户端认证后不读响应；此处留 300ms 确认连接未被关闭
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 2. Connect 流（bidi）：VER TYPE ATYP(IPv4) ADDR PORT
    const auto conn_sid = client.qc->open_stream();
    ASSERT_GE(conn_sid, 0);
    std::vector<std::byte> connect;
    connect.push_back(std::byte{0x05});
    connect.push_back(std::byte{0x01});
    connect.push_back(std::byte{0x01});
    const auto ip = net::ip::address_v4::loopback().to_bytes();
    connect.insert(connect.end(), reinterpret_cast<const std::byte *>(ip.data()),
                   reinterpret_cast<const std::byte *>(ip.data() + 4));
    connect.push_back(std::byte{static_cast<unsigned char>(echo.port >> 8)});
    connect.push_back(std::byte{static_cast<unsigned char>(echo.port & 0xFF)});
    client.write_stream(conn_sid, connect);

    const std::string payload = "hello tuic v5";
    const auto baseline = client.recv_data[conn_sid].size();
    client.write_stream(conn_sid, std::span<const std::byte>(
                                      reinterpret_cast<const std::byte *>(payload.data()), payload.size()));
    ASSERT_TRUE(client.read_stream(conn_sid, baseline + payload.size(), std::chrono::seconds(15)));
    const auto &echo_data = client.recv_data[conn_sid];
    const std::string echo_str(
        reinterpret_cast<const char *>(echo_data.data() + echo_data.size() - payload.size()), payload.size());
    EXPECT_EQ(echo_str, payload);

    env.teardown();
}
