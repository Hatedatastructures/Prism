/**
 * @file VmessConnSession.cpp
 * @brief VMess Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept AEAD 握手 + 双向回显
 * 2. 结束块（end block）语义：服务端发结束块 → 客户端 EOF；
 *    客户端发结束块 → 服务端 EOF
 * 3. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 4. 错误分支：bad_auth / not_open / io_error
 * 5. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
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

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Vmess/Vmess.hpp>
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

    /// 精确读取（测试辅助）
    auto RecvExact(MemoryStream &Stream, std::span<std::uint8_t> dst) -> net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < dst.size())
        {
            std::error_code ec;
            const auto n = co_await Stream.async_read_some(AsBytes(dst.subspan(Done)), ec);
            if (ec || n == 0)
            {
                co_return true;
            }
            Done += n;
        }
        co_return false;
    }

    /// 原始客户端：AEAD 握手 → 数据块 → 结束块
    /// @return 全流程成功返回 true
    auto run_raw_client(MemoryStream &Stream, const std::array<std::uint8_t, 16> &uuid,
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
        Vmess::RequestHeader hdr;
        hdr.Version = Vmess::ProtocolVersion;
        hdr.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
        hdr.opt = static_cast<std::uint8_t>(Vmess::Option::ChunkStream);
        hdr.sec = Vmess::Security::Aes128Gcm;
        hdr.Target = make_addr(Vmess::AddressType::Domain, "example.com", 443);
        const auto plain = Vmess::BuildRequestHeader(hdr, Vmess::RequestMeta{iv, key, v, p});
        const auto cmd_key = Vmess::CmdKeyFromUuid(uuid);
        const auto sealed = Vmess::SealAuthHeader(cmd_key, Vmess::AuthHeaderInput{plain, time_sec, random4});
        const auto auth_id = Vmess::CreateAuthId(time_sec, random4);
        std::error_code ec;
        co_await Stream.async_write_some(AsBytes(std::span<const std::uint8_t>(sealed)), ec);
        if (ec)
        {
            co_return false;
        }

        // 3. 读取响应长度块并解密
        std::array<std::uint8_t, 18> len_enc{};
        if (co_await RecvExact(Stream, std::span<std::uint8_t>(len_enc)))
        {
            co_return false;
        }
        const auto resp_body_key = Vmess::detail::Sha256(key);
        const auto resp_body_iv = Vmess::detail::Sha256(iv);
        std::array<std::uint8_t, 16> resp_key16{};
        std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
        std::array<std::uint8_t, 16> resp_iv16{};
        std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);
        const auto resp_len_key = Vmess::Kdf(resp_key16, Vmess::KdfRespLenKey);
        const auto resp_len_iv = Vmess::Kdf(resp_iv16, Vmess::KdfRespLenIv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), resp_len_key.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), resp_len_iv.data(), 12);
        const auto len_plain = Vmess::detail::AesGcmOpen(
            Vmess::detail::OpenInput{rlk, rliv, len_enc, auth_id});
        if (len_plain.size() != 2)
        {
            co_return false;
        }
        const auto resp_len = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

        // 4. 读取响应头并校验验证字节
        std::vector<std::uint8_t> resp_enc(resp_len);
        if (co_await RecvExact(Stream, resp_enc))
        {
            co_return false;
        }
        const auto resp_key = Vmess::Kdf(resp_key16, Vmess::KdfRespKey);
        const auto resp_iv = Vmess::Kdf(resp_iv16, Vmess::KdfRespIv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), resp_key.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), resp_iv.data(), 12);
        Vmess::ResponseHeader rh;
        const auto oerr = Vmess::OpenResponseHeader(rk, Vmess::RespHeaderParseInput{riv, resp_enc, auth_id},
                                                      rh);
        if (oerr != Error::None || rh.Version != v)
        {
            co_return false;
        }

        // 5. 派生分块密钥，发送数据块 + 结束块
        const auto body_key = Vmess::Kdf(key, iv);
        std::array<std::uint8_t, 16> ChunkKey{};
        std::memcpy(ChunkKey.data(), body_key.data(), 16);
        std::array<std::uint8_t, 12> ChunkNonce{};
        std::memcpy(ChunkNonce.data(), iv.data(), 12);
        Vmess::ChunkEncryptor enc(ChunkKey, ChunkNonce);
        std::vector<std::uint8_t> chunk(payload.size() + Vmess::ChunkEncryptor::Overhead);
        const auto enc_n = enc.Seal(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                          payload.size()),
            chunk);
        co_await Stream.async_write_some(AsBytes(std::span<const std::uint8_t>(chunk).first(enc_n)), ec);
        if (ec)
        {
            co_return false;
        }
        std::array<std::uint8_t, 34> end_block{};
        const auto end_n = enc.Finish(end_block);
        co_await Stream.async_write_some(AsBytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
        if (ec)
        {
            co_return false;
        }
        co_return true;
    }

    TEST(VmessConnSession, ClientServerEchoRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "vmess echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept AEAD 握手 → 解密读取 → 回显
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
                         EXPECT_EQ(req.Cmd, static_cast<std::uint8_t>(Vmess::Command::Tcp));
                         EXPECT_EQ(req.dst.Host, "example.com");
                         EXPECT_EQ(req.dst.Port, 443u);
                         EXPECT_EQ(Conn->Parsed().dst.Host, "example.com");
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
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
                     cli->Close();
                 });
    }

    TEST(VmessConnSession, ServerEofOnEndBlock)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "end block payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 读数据块 → 经底层传输写结束块 → 客户端 EOF
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
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         // 经底层传输写原始结束块（Accept 已把底层流 move 进 Conn，
                         // 用 NextLayer() 导航获取底层传输，不可再用已移动的局部流）
                         const auto body_key = Vmess::Kdf(req.RequestKey, req.RequestNonce);
                         std::array<std::uint8_t, 16> ChunkKey{};
                         std::memcpy(ChunkKey.data(), body_key.data(), 16);
                         std::array<std::uint8_t, 12> ChunkNonce{};
                         std::memcpy(ChunkNonce.data(), req.RequestNonce.data(), 12);
                         Vmess::ChunkEncryptor enc(ChunkKey, ChunkNonce);
                         std::array<std::uint8_t, 34> end_block{};
                         const auto end_n = enc.Finish(end_block);
                         co_await Conn->NextLayer()->async_write_some(
                             AsBytes(std::span<const std::uint8_t>(end_block).first(end_n)), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 客户端：Connect 握手 → 写数据块 → 读结束块 → EOF
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
                     const auto derr = co_await cli->AsyncReceiveDatagram(out);
                     EXPECT_EQ(derr, Error::UnexpectedEof);
                     cli->Close();
                 });
    }

    TEST(VmessConnSession, ClientEofOnEndBlock)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();
        const std::string payload = "Client end block payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端完成通知：防止 detached 协程在 ioc 析构时
                     // 仍挂起在 channel 读上（use-after-free）
                     net::experimental::channel<void(boost::system::error_code)> server_done(ioc.get_executor(), 1);

                     // 服务端：Accept 握手 → 读数据块 → 读结束块 → EOF
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             server_done.try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         // 结束块 → 流结束（0 字节、无错误）
                         const auto m = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(m, 0u);
                         Conn->Close();
                         server_done.try_send(boost::system::error_code{});
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     // 原始客户端：握手 + 数据块 + 结束块
                     EXPECT_TRUE(co_await run_raw_client(a, uuid, payload));
                     a.Close();
                     // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                     co_await server_done.async_receive(net::use_awaitable);
                 });
    }

    TEST(VmessConnSession, UdpDgramRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：AcceptPacket（udp 命令）→ Dgram 收包
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, dg] =
                             co_await Vmess::AcceptPacket(std::make_shared<MemoryStream>(std::move(b)),
                                                           cfg);
                         if (err != Error::None || !dg)
                         {
                             EXPECT_TRUE(false) << "AcceptPacket Failed";
                             co_return;
                         }
                         EXPECT_EQ(req.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
                         EXPECT_EQ(dg->TransportType(), Preview::Transmission::Type::Udp);
                         std::vector<std::uint8_t> payload;
                         const auto rerr = co_await dg->AsyncReceiveFrom(payload);
                         EXPECT_EQ(rerr, Error::None);
                         EXPECT_EQ(std::string(payload.begin(), payload.end()), "vmess datagram");
                         EXPECT_TRUE(dg->Stream());
                         dg->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await Vmess::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 53));
                     EXPECT_EQ(herr, Error::None);
                     if (!dg)
                     {
                         co_return;
                     }
                     const std::string p = "vmess datagram";
                     const auto serr = co_await dg->AsyncSendTo(
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, Error::None);
                     dg->Close();
                 });
    }

    TEST(VmessConnSession, BadUuidRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：UUID 不匹配 → bad_auth（不发送响应）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [err, req, Conn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
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
                     Vmess::RequestHeader hdr;
                     hdr.Version = Vmess::ProtocolVersion;
                     hdr.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
                     hdr.opt = static_cast<std::uint8_t>(Vmess::Option::ChunkStream);
                     hdr.sec = Vmess::Security::Aes128Gcm;
                     hdr.Target = make_addr(Vmess::AddressType::Domain, "example.com", 443);
                     const auto plain = Vmess::BuildRequestHeader(hdr, Vmess::RequestMeta{iv, key, v, 0});
                     const auto cmd_key = Vmess::CmdKeyFromUuid(bad_uuid);
                     const auto sealed =
                         Vmess::SealAuthHeader(cmd_key, Vmess::AuthHeaderInput{plain, time_sec, random4});
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(sealed)), ec);
                     a.Close();
                 });
    }

    TEST(VmessConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：读写与数据报均应返回 not_open
                     auto c = std::make_shared<Vmess::Conn<>>(uuid);
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     const auto e1 = co_await c->AsyncSendDatagram(AsU8(std::span<std::byte>(buf)).first(4));
                     EXPECT_EQ(e1, Error::NotOpen);
                     std::vector<std::uint8_t> out;
                     const auto e2 = co_await c->AsyncReceiveDatagram(out);
                     EXPECT_EQ(e2, Error::NotOpen);
                     c->Close();
                     c->Cancel();
                 });
    }

    TEST(VmessConnSession, WriteToClosedPeer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     b.Close(); // 对端已全关 → 写失败 → io_error
                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Ipv4, "1.1.1.1", 80));
                     EXPECT_EQ(err, Error::IoError);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(VmessConnSession, DecoratorChain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = test_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：Close / Cancel / Release 可直接调用（无传输安全返回空）
                     auto c = std::make_shared<Vmess::Conn<>>(uuid);
                     c->Close();
                     c->Cancel();
                     auto released = c->Release();
                     EXPECT_FALSE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr); // 未绑定传输
                     // 绑定传输后 NextLayer 可导航（服务端接受握手）
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         Vmess::ServerConfig cfg;
                         cfg.uuid = uuid;
                         auto [serr, sreq, sconn] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)), cfg);
                         if (serr == Error::None && sconn)
                         {
                             sconn->Close();
                         }
                         (void)sreq;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);
                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [err, cli] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), cfg,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(err, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     EXPECT_NE(cli->NextLayer(), nullptr);
                     EXPECT_NE(cli->lowest_layer<MemoryStream>(), nullptr);
                     EXPECT_TRUE(cli->Executor());
                     cli->Cancel(); // 绑定后 Cancel 透传
                     // const 版本装饰器导航
                     const Vmess::Conn<> *const_cli = cli.get();
                     EXPECT_NE(const_cli->NextLayer(), nullptr);
                     auto released2 = cli->Release();
                     EXPECT_TRUE(released2);
                     EXPECT_EQ(cli->NextLayer(), nullptr);
                 });
    }

    TEST(VmessDgramSession, WrapNonConnRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // Dgram 包裹非 Conn 传输 → dynamic_cast 失败 → not_open
                     auto dg = std::make_shared<Vmess::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(serr, Error::NotOpen);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(out);
                     EXPECT_EQ(rerr, Error::NotOpen);
                     EXPECT_TRUE(dg->Executor());
                     // 透传读写（passthrough）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto w = co_await dg->async_write_some(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 4u); // 对端未关，写入成功
                     b.Close();        // 关闭对端 → 读 EOF
                     const auto n = co_await dg->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     dg->Close();
                     dg->Cancel();
                     EXPECT_NE(dg->NextLayer(), nullptr);
                     const Vmess::Dgram<> *const_dg = dg.get();
                     EXPECT_NE(const_dg->NextLayer(), nullptr);
                     auto released = dg->Release();
                     EXPECT_TRUE(released);
                 });
    }

} // namespace
