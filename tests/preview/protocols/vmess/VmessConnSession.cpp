/**
 * @file VmessConnSession.cpp
 * @brief VMess conn/dgram 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept AEAD 握手 + 双向回显
 * 2. 结束块（end block）语义：服务端发结束块 → 客户端 EOF；
 *    客户端发结束块 → 服务端 EOF
 * 3. UDP 数据面：connect_packet / accept_packet + dgram 收发往返
 * 4. 错误分支：bad_auth / not_open / io_error
 * 5. 装饰器链方法：executor / close / cancel / next_layer / release
 * @note 使用 make_memory_pair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/vmess/vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
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

    /// 精确读取（测试辅助）
    auto recv_exact(memory_stream &stream, std::span<std::uint8_t> dst) -> net::awaitable<bool>
    {
        std::size_t done = 0;
        while (done < dst.size())
        {
            std::error_code ec;
            const auto n = co_await stream.async_read_some(as_bytes(dst.subspan(done)), ec);
            if (ec || n == 0)
            {
                co_return true;
            }
            done += n;
        }
        co_return false;
    }

    /// 原始客户端：AEAD 握手 → 数据块 → 结束块
    /// @return 全流程成功返回 true
    auto run_raw_client(memory_stream &stream, const std::array<std::uint8_t, 16> &uuid,
                        const std::string &payload) -> net::awaitable<bool>
    {
        // 1. 生成随机参数
        std::random_device rd;
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        for (auto &b : iv)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        for (auto &b : key)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto v = static_cast<std::uint8_t>(rd() & 0xFF);
        const auto p = static_cast<std::uint8_t>(rd() % 16);
        std::array<std::uint8_t, 4> random4{};
        for (auto &b : random4)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto time_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();

        // 2. 密封认证头并发送
        vmess::request_header hdr;
        hdr.version = vmess::protocol_version;
        hdr.cmd = vmess::command::tcp;
        hdr.opt = static_cast<std::uint8_t>(vmess::option::chunk_stream);
        hdr.sec = vmess::security::aes_128_gcm;
        hdr.target = make_addr(vmess::address_type::domain, "example.com", 443);
        const auto plain = vmess::build_request_header(hdr, vmess::request_meta{iv, key, v, p});
        const auto cmd_key = vmess::cmd_key_from_uuid(uuid);
        const auto sealed = vmess::seal_auth_header(cmd_key, vmess::auth_header_input{plain, time_sec, random4});
        const auto auth_id = vmess::create_auth_id(time_sec, random4);
        std::error_code ec;
        co_await stream.async_write_some(as_bytes(std::span<const std::uint8_t>(sealed)), ec);
        if (ec)
        {
            co_return false;
        }

        // 3. 读取响应长度块并解密
        std::array<std::uint8_t, 18> len_enc{};
        if (co_await recv_exact(stream, std::span<std::uint8_t>(len_enc)))
        {
            co_return false;
        }
        const auto resp_body_key = vmess::detail::sha256(key);
        const auto resp_body_iv = vmess::detail::sha256(iv);
        std::array<std::uint8_t, 16> resp_key16{};
        std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
        std::array<std::uint8_t, 16> resp_iv16{};
        std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);
        const auto resp_len_key = vmess::kdf(resp_key16, vmess::kdf_resp_len_key);
        const auto resp_len_iv = vmess::kdf(resp_iv16, vmess::kdf_resp_len_iv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), resp_len_key.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), resp_len_iv.data(), 12);
        const auto len_plain = vmess::detail::aes_gcm_open(
            vmess::detail::open_input{rlk, rliv, len_enc, auth_id});
        if (len_plain.size() != 2)
        {
            co_return false;
        }
        const auto resp_len = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

        // 4. 读取响应头并校验验证字节
        std::vector<std::uint8_t> resp_enc(resp_len);
        if (co_await recv_exact(stream, resp_enc))
        {
            co_return false;
        }
        const auto resp_key = vmess::kdf(resp_key16, vmess::kdf_resp_key);
        const auto resp_iv = vmess::kdf(resp_iv16, vmess::kdf_resp_iv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), resp_key.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), resp_iv.data(), 12);
        vmess::response_header rh;
        const auto oerr = vmess::open_response_header(rk, vmess::resp_header_parse_input{riv, resp_enc, auth_id},
                                                      rh);
        if (oerr != error::none || rh.version != v)
        {
            co_return false;
        }

        // 5. 派生分块密钥，发送数据块 + 结束块
        const auto body_key = vmess::kdf(key, iv);
        std::array<std::uint8_t, 16> chunk_key{};
        std::memcpy(chunk_key.data(), body_key.data(), 16);
        std::array<std::uint8_t, 12> chunk_nonce{};
        std::memcpy(chunk_nonce.data(), iv.data(), 12);
        vmess::chunk_encryptor enc(chunk_key, chunk_nonce);
        std::vector<std::uint8_t> chunk(payload.size() + vmess::chunk_encryptor::overhead);
        const auto enc_n = enc.seal(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                          payload.size()),
            chunk);
        co_await stream.async_write_some(as_bytes(std::span<const std::uint8_t>(chunk).first(enc_n)), ec);
        if (ec)
        {
            co_return false;
        }
        std::array<std::uint8_t, 34> end_block{};
        const auto end_n = enc.finish(end_block);
        co_await stream.async_write_some(as_bytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
        if (ec)
        {
            co_return false;
        }
        co_return true;
    }

    TEST(VmessConnSession, ClientServerEchoRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "vmess echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept AEAD 握手 → 解密读取 → 回显
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
                         EXPECT_EQ(req.cmd, static_cast<std::uint8_t>(vmess::command::tcp));
                         EXPECT_EQ(req.dst.host, "example.com");
                         EXPECT_EQ(req.dst.port, 443u);
                         EXPECT_EQ(conn->parsed().dst.host, "example.com");
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
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
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 1024> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->close();
                 });
    }

    TEST(VmessConnSession, ServerEofOnEndBlock)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "end block payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 读数据块 → 经底层传输写结束块 → 客户端 EOF
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
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         // 经底层传输写原始结束块（accept 已把底层流 move 进 conn，
                         // 用 next_layer() 导航获取底层传输，不可再用已移动的局部流）
                         const auto body_key = vmess::kdf(req.request_key, req.request_nonce);
                         std::array<std::uint8_t, 16> chunk_key{};
                         std::memcpy(chunk_key.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> chunk_nonce{};
                         std::memcpy(chunk_nonce.data(), req.request_nonce.data(), 12);
                         vmess::chunk_encryptor enc(chunk_key, chunk_nonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.finish(end_block);
                         co_await conn->next_layer()->async_write_some(
                             as_bytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：connect 握手 → 写数据块 → 读结束块 → EOF
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
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     // 流式读取：结束块 → EOF（0 字节、无错误）
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(n, 0u);
                     // 数据报读取：结束块 → unexpected_eof
                     std::vector<std::uint8_t> out;
                     const auto derr = co_await cli->async_receive_datagram(out);
                     EXPECT_EQ(derr, error::unexpected_eof);
                     cli->close();
                 });
    }

    TEST(VmessConnSession, ClientEofOnEndBlock)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "client end block payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端完成通知：防止 detached 协程在 ioc 析构时
                     // 仍挂起在 channel 读上（use-after-free）
                     net::experimental::channel<void(boost::system::error_code)> server_done(ioc.get_executor(), 1);

                     // 服务端：accept 握手 → 读数据块 → 读结束块 → EOF
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             server_done.try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         // 结束块 → 流结束（0 字节、无错误）
                         const auto m = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(m, 0u);
                         conn->close();
                         server_done.try_send(boost::system::error_code{});
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：握手 + 数据块 + 结束块
                     EXPECT_TRUE(co_await run_raw_client(a, uuid, payload));
                     a.close();
                     // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                     co_await server_done.async_receive(net::use_awaitable);
                 });
    }

    TEST(VmessConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept_packet（udp 命令）→ dgram 收包
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, dg] =
                             co_await vmess::accept_packet(std::make_shared<memory_stream>(std::move(b)),
                                                           cfg);
                         if (err != error::none || !dg)
                         {
                             EXPECT_TRUE(false) << "accept_packet failed";
                             co_return;
                         }
                         EXPECT_EQ(req.cmd, static_cast<std::uint8_t>(vmess::command::udp));
                         EXPECT_EQ(dg->transport_type(), preview::transmission::type::udp);
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->async_receive_from(payload);
                         EXPECT_EQ(rerr, error::none);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "vmess datagram");
                         EXPECT_TRUE(dg->stream());
                         dg->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await vmess::connect_packet(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 53));
                     EXPECT_EQ(herr, error::none);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "vmess datagram";
                     const auto serr = co_await dg->async_send_to(
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, error::none);
                     dg->close();
                 });
    }

    TEST(VmessConnSession, BadUuidRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：UUID 不匹配 → bad_auth（不发送响应）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [err, req, conn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(conn);
                         (void)req;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：错误 UUID 密封认证头，发送后关闭
                     std::array<std::uint8_t, 16> bad_uuid{};
                     bad_uuid.fill(0xEE);
                     std::random_device rd;
                     std::array<std::uint8_t, 16> iv{};
                     std::array<std::uint8_t, 16> key{};
                     for (auto &b : iv)
                     {
                         b = static_cast<std::uint8_t>(rd() & 0xFF);
                     }
                     for (auto &b : key)
                     {
                         b = static_cast<std::uint8_t>(rd() & 0xFF);
                     }
                     const auto v = static_cast<std::uint8_t>(rd() & 0xFF);
                     const std::array<std::uint8_t, 4> random4{1, 2, 3, 4};
                     const auto time_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count();
                     vmess::request_header hdr;
                     hdr.version = vmess::protocol_version;
                     hdr.cmd = vmess::command::tcp;
                     hdr.opt = static_cast<std::uint8_t>(vmess::option::chunk_stream);
                     hdr.sec = vmess::security::aes_128_gcm;
                     hdr.target = make_addr(vmess::address_type::domain, "example.com", 443);
                     const auto plain = vmess::build_request_header(hdr, vmess::request_meta{iv, key, v, 0});
                     const auto cmd_key = vmess::cmd_key_from_uuid(bad_uuid);
                     const auto sealed =
                         vmess::seal_auth_header(cmd_key, vmess::auth_header_input{plain, time_sec, random4});
                     std::error_code ec;
                     co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(sealed)), ec);
                     a.close();
                 });
    }

    TEST(VmessConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：读写与数据报均应返回 not_open
                     auto c = std::make_shared<vmess::conn<>>(uuid);
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));
                     const auto e1 = co_await c->async_send_datagram(as_u8(std::span<std::byte>(buf)).first(4));
                     EXPECT_EQ(e1, error::not_open);
                     std::vector<std::uint8_t> out;
                     const auto e2 = co_await c->async_receive_datagram(out);
                     EXPECT_EQ(e2, error::not_open);
                     c->close();
                     c->cancel();
                 });
    }

    TEST(VmessConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.close(); // 对端已全关 → 写失败 → io_error
                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, error::io_error);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(VmessConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：close / cancel / release 可直接调用（无传输安全返回空）
                     auto c = std::make_shared<vmess::conn<>>(uuid);
                     c->close();
                     c->cancel();
                     auto released = c->release();
                     EXPECT_FALSE(released);
                     EXPECT_EQ(c->next_layer(), nullptr); // 未绑定传输
                     // 绑定传输后 next_layer 可导航（服务端接受握手）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         vmess::server_config cfg;
                         cfg.uuid = uuid;
                         auto [serr, sreq, sconn] =
                             co_await vmess::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                         if (serr == error::none && sconn)
                         {
                             sconn->close();
                         }
                         (void)sreq;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);
                     vmess::client_config cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await vmess::connect(
                         std::make_shared<memory_stream>(std::move(a)), cfg,
                         make_addr(vmess::address_type::domain, "example.com", 443));
                     EXPECT_EQ(err, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     EXPECT_NE(cli->next_layer(), nullptr);
                     EXPECT_NE(cli->lowest_layer<memory_stream>(), nullptr);
                     EXPECT_TRUE(cli->executor());
                     cli->cancel(); // 绑定后 cancel 透传
                     // const 版本装饰器导航
                     const vmess::conn<> *const_cli = cli.get();
                     EXPECT_NE(const_cli->next_layer(), nullptr);
                     auto released2 = cli->release();
                     EXPECT_TRUE(released2);
                     EXPECT_EQ(cli->next_layer(), nullptr);
                 });
    }

    TEST(VmessDgramSession, WrapNonConnRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // dgram 包裹非 conn 传输 → dynamic_cast 失败 → not_open
                     auto dg = std::make_shared<vmess::dgram<>>(std::make_shared<memory_stream>(std::move(a)));
                     const std::string p = "x";
                     const auto serr = co_await dg->async_send_to(
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, error::not_open);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->async_receive_from(out);
                     EXPECT_EQ(rerr, error::not_open);
                     EXPECT_TRUE(dg->executor());
                     // 透传读写（passthrough）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 4u); // 对端未关，写入成功
                     b.close();        // 关闭对端 → 读 EOF
                     const auto n = co_await dg->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     dg->close();
                     dg->cancel();
                     EXPECT_NE(dg->next_layer(), nullptr);
                     const vmess::dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->next_layer(), nullptr);
                     auto released = dg->release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
