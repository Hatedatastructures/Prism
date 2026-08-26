/**
 * @file Ss2022CodecDeep.cpp
 * @brief Shadowsocks 2022 Codec / Conn / Dgram 剩余分支深度测试
 * @details 覆盖 EncodeAddress / ParseAddress / ParseVarHeader 的
 *          ipv6 与截断分支、ChunkCodec 的起始 Nonce 与全部错误路径、
 *          UDP 数据报编解码的成功与错误路径、握手 Parser 的错误分支，
 *          Conn / Dgram 装饰器透传方法。
 */

#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Shadowsocks2022/Codec.hpp>
#include <common/Protocols/Shadowsocks2022/Conn.hpp>
#include <common/Protocols/Shadowsocks2022/Dgram.hpp>
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace ss = Preview::Shadowsocks2022;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     * @details 同一 io_context 可能被多次驱动，restart() 重置
     * stopped 标志；对从未运行的 ioc 调用同样安全。
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        ioc.restart();
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

    /**
     * @brief 从初始值列表构造字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    TEST(Ss2022CodecDeep, AddressBranches)
    {
        // EncodeAddress ipv6
        ss::Address addr{};
        addr.Type = ss::AddressType::Ipv6;
        addr.Host.assign(16, 'q');
        addr.Port = 8080;
        const auto v6 = ss::EncodeAddress(addr);
        EXPECT_EQ(v6.size(), 19u);
        EXPECT_EQ(v6[0], 0x04);

        // ParseAddress ipv4 截断
        std::size_t off = 0;
        EXPECT_EQ(ss::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr, off),
                  Error::NeedMore);
        // ParseAddress ipv6 截断 + 成功
        off = 0;
        std::vector<std::uint8_t> p6{0x04};
        p6.insert(p6.end(), 5, 0x42);
        EXPECT_EQ(ss::ParseAddress(p6, addr, off), Error::NeedMore);
        off = 0;
        p6.assign(17, 0);
        p6[0] = 0x04;
        p6.insert(p6.end(), 2, 0);
        EXPECT_EQ(ss::ParseAddress(p6, addr, off), Error::None);
        EXPECT_EQ(addr.Host, std::string(16, 0));

        // ParseVarHeader 各分支
        std::span<const std::uint8_t> payload;
        // ipv4 截断
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr, payload),
                  Error::NeedMore);
        // ipv6 截断
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, payload),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> var6{0x04};
        var6.insert(var6.end(), 16, 0x42);
        var6.push_back(0x00);
        var6.push_back(0x50);
        var6.push_back(0x00);
        var6.push_back(0x00);
        var6.push_back('x');
        EXPECT_EQ(ss::ParseVarHeader(var6, addr, payload), Error::None);
        EXPECT_EQ(addr.Type, ss::AddressType::Ipv6);
        EXPECT_EQ(addr.Port, 80u);
        EXPECT_EQ(payload.size(), 1u);
        // domain 长度截断
        std::vector<std::uint8_t> dom{0x03, 0x05, 'a'};
        EXPECT_EQ(ss::ParseVarHeader(dom, addr, payload), Error::NeedMore);
        // domain 成功
        std::vector<std::uint8_t> dom_ok{0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50, 0x00, 0x00};
        EXPECT_EQ(ss::ParseVarHeader(dom_ok, addr, payload), Error::None);
        EXPECT_EQ(addr.Host, "abc");
    }

    TEST(Ss2022CodecDeep, ChunkCodecErrors)
    {
        std::array<std::uint8_t, 16> key{};
        // StartNonce > 0 → IncNonce 路径
        ss::ChunkCodec Codec(std::span<const std::uint8_t>(key), 3);
        ss::ChunkCodec dec(std::span<const std::uint8_t>(key), 3);

        // OpenLen：头部不足
        EXPECT_FALSE(Codec.OpenLen(std::span<const std::uint8_t>(make_bytes({1, 2}))).has_value());
        // 坏密文
        std::vector<std::uint8_t> bad(18, 0);
        bad[17] = 0xFF;
        EXPECT_FALSE(Codec.OpenLen(bad).has_value());

        // Seal + Open 成功路径
        const auto wire = dec.Seal(AsU8Span(std::string_view{"hello"}));
        std::size_t consumed = 0;
        const auto plain = Codec.Open(wire, consumed);
        EXPECT_EQ(plain.size(), 5u);
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(plain.data()), plain.size()), "hello");
        EXPECT_EQ(consumed, wire.size());

        // 结束块
        ss::ChunkCodec codec2(std::span<const std::uint8_t>(key), 3);
        ss::ChunkCodec dec2(std::span<const std::uint8_t>(key), 3);
        const auto fin = dec2.Finish();
        std::size_t fin_consumed = 0;
        EXPECT_TRUE(codec2.Open(fin, fin_consumed).empty());
        EXPECT_EQ(fin_consumed, 18u);

        // Open：数据不足（长度块后缺载荷）
        ss::ChunkCodec codec3(std::span<const std::uint8_t>(key), 3);
        ss::ChunkCodec dec3(std::span<const std::uint8_t>(key), 3);
        const auto big = dec3.Seal(AsU8Span(std::string_view{"12345678"}));
        std::size_t c3 = 0;
        EXPECT_TRUE(codec3.Open(std::span<const std::uint8_t>(big).first(20), c3).empty());

        // OpenPayload：载荷过短 / 校验失败
        ss::ChunkCodec codec4(std::span<const std::uint8_t>(key), 3);
        EXPECT_TRUE(codec4.OpenPayload(std::span<const std::uint8_t>(make_bytes({1, 2}))).empty());
        std::vector<std::uint8_t> bad_body(17, 0);
        bad_body[16] = 0xFF;
        EXPECT_TRUE(codec4.OpenPayload(bad_body).empty());

        // 超长长度块（> max_chunk_size = 0xFFFF）
        ss::ChunkCodec codec5(std::span<const std::uint8_t>(key), 3);
        ss::ChunkCodec dec5(std::span<const std::uint8_t>(key), 3);
        std::vector<std::uint8_t> big_payload(20000, 0xAB);
        const auto big_wire = dec5.Seal(big_payload);
        EXPECT_FALSE(codec5.OpenLen(std::span<const std::uint8_t>(big_wire).first(18)).has_value());
    }

    TEST(Ss2022CodecDeep, SessionKeyAndUdp)
    {
        std::array<std::uint8_t, 16> psk{};
        psk.fill(0x11);
        std::array<std::uint8_t, 16> salt{};
        salt.fill(0x22);
        const auto key = ss::SessionKey(psk, salt, 16);
        EXPECT_EQ(key.size(), 16u);

        // BuildUdpPacket 成功
        ss::Address dst{};
        dst.Type = ss::AddressType::Ipv4;
        dst.Host = "1.2.3.4";
        dst.Port = 443;
        const auto packet = ss::BuildUdpPacket(
            ss::UdpBuildInput{key, 7, &dst, AsU8Span(std::string_view{"Data"})});
        EXPECT_GT(packet.size(), 16u);

        // ParseUdpPacket 成功
        ss::Address out_dst{};
        std::vector<std::uint8_t> out_payload;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{key, packet, &out_dst, &out_payload}), Error::None);
        EXPECT_EQ(out_dst.Host, "1.2.3.4");
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(out_payload.data()), out_payload.size()),
                  "Data");

        // 空 Target → bad_length
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{key, packet, nullptr, &out_payload}),
                  Error::BadLength);
        // 短包 → bad_length
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{key, std::span<const std::uint8_t>(packet).first(10),
                                                           &out_dst, &out_payload}),
                  Error::BadLength);
        // SessionID 不匹配 → bad_auth
        std::array<std::uint8_t, 16> wrong_key{};
        wrong_key.fill(0x99);
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{wrong_key, packet, &out_dst, &out_payload}),
                  Error::BadAuth);
        // 类型字节非法 → bad_message
        auto bad_type = packet;
        bad_type[16] = 0x02;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{key, bad_type, &out_dst, &out_payload}),
                  Error::BadMessage);
        // 载荷 tag 校验失败 → bad_auth
        auto bad_tag = packet;
        bad_tag.back() ^= 0x01;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{key, bad_tag, &out_dst, &out_payload}),
                  Error::BadAuth);
    }

    TEST(Ss2022CodecDeep, HandshakeParserErrors)
    {
        std::array<std::uint8_t, 16> psk{};
        psk.fill(0x11);

        // Serializer 生成合法握手包
        ss::Serializer ser(psk);
        ss::Message msg{};
        msg.dst.Type = ss::AddressType::Ipv4;
        msg.dst.Host = "8.8.8.8";
        msg.dst.Port = 53;
        msg.InitialPayload = "hello";
        ser.Reset(msg, 1000);
        std::array<std::uint8_t, 2048> buf{};
        std::error_code ec;
        const auto n = ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec);
        const auto wire = std::vector<std::uint8_t>(buf.begin(), buf.begin() + n);

        // Parser 成功
        ss::Parser p(psk);
        EXPECT_EQ(p.Put(boost::asio::buffer(wire), ec), wire.size());
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
        EXPECT_EQ(p.Get().InitialPayload, "hello");

        // 数据不足
        p.Reset();
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));

        // 固定头解密失败（篡改）→ auth_failed
        p.Reset();
        auto tampered = wire;
        tampered[30] ^= 0x01;
        EXPECT_EQ(p.Put(boost::asio::buffer(tampered), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::AuthFailed));

        // 变长头不足（截断尾部）→ need_more
        p.Reset();
        const auto truncated = std::vector<std::uint8_t>(wire.begin(), wire.end() - 40);
        EXPECT_EQ(p.Put(boost::asio::buffer(truncated), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));

        // 变长头解密失败 → auth_failed
        p.Reset();
        auto tampered2 = wire;
        tampered2[tampered2.size() - 1] ^= 0x01;
        EXPECT_EQ(p.Put(boost::asio::buffer(tampered2), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::AuthFailed));
    }

    TEST(Ss2022CodecDeep, ConnAndDgramDecorators)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        std::array<std::uint8_t, 16> key{};
        key.fill(0x55);

        // Dgram 装饰器
        auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)), key);
        EXPECT_EQ(dg->TransportType(), Transmission::Type::Udp);
        (void)dg->Executor();
        EXPECT_NE(dg->NextLayer(), nullptr);
        const auto *cdg = dg.get();
        EXPECT_NE(cdg->NextLayer(), nullptr);
        EXPECT_NE(dg->Stream(), nullptr);
        dg->Cancel();
        dg->Close();
        EXPECT_NE(dg->Release(), nullptr);

        // Dgram 收发往返
        auto [c, d] = MakeMemoryPair(ioc.get_executor());
        auto peer2 = std::make_shared<MemoryStream>(std::move(d));
        auto dg2 = std::make_shared<Shadowsocks2022::Dgram<>>(std::make_shared<MemoryStream>(std::move(c)), key);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     ss::Address dst{};
                     dst.Type = ss::AddressType::Domain;
                     dst.Host = "example.com";
                     dst.Port = 80;
                     const auto serr = co_await dg2->AsyncSendTo(dst, AsU8Span(std::string_view{"pkt"}));
                     EXPECT_EQ(serr, Error::None);
                     std::array<std::uint8_t, 2048> raw{};
                     std::error_code ec;
                     const auto rn = co_await peer2->async_read_some(AsBytes(std::span<std::uint8_t>(raw)), ec);
                     const auto back = std::vector<std::uint8_t>(raw.begin(), raw.begin() + rn);
                     const auto werr = co_await peer2->WriteAll(back);
                     EXPECT_FALSE(werr);
                     ss::Address src{};
                     std::vector<std::uint8_t> payload;
                     const auto rerr = co_await dg2->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(rerr, Error::None);
                     EXPECT_EQ(src.Host, "example.com");
                 });

        // Conn：完整握手（fake Server 响应）+ 装饰器方法 + 数据面
        auto [e, f] = MakeMemoryPair(ioc.get_executor());
        auto server_side = std::make_shared<MemoryStream>(std::move(f));
        auto cn = std::make_shared<Shadowsocks2022::Conn<>>("pw");

        // 未握手读写 → not_open
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await cn->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                     ec.clear();
                     const auto w = co_await cn->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_TRUE(ec);
                 });

        // fake Server（解析 salt → 按标准响应帧回复）与客户端握手必须并发运行：
        // 服务端先读 salt，客户端握手后才有数据，串行驱动会互相等待
        // （server salt(16) + 裸块固定头：27B 明文 + 16B tag）
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     bool server_done = false;
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 16 + 45 + 128> buf{};
                         std::error_code ec;
                         const auto n = co_await server_side->async_read_some(
                             AsBytes(std::span<std::uint8_t>(buf)), ec);
                         EXPECT_GT(n, 16u + 45u);
                         const auto salt = std::span<const std::uint8_t>(buf.data(), 16);
                         std::array<std::uint8_t, 16> ServerSalt{};
                         ServerSalt.fill(0x77);
                         const auto resp_key =
                             ss::SessionKey(Shadowsocks2022::DerivePsk("pw"), ServerSalt, 16);
                         ss::ChunkCodec RespCodec(resp_key);
                         std::array<std::uint8_t, ss::RespFixedHdrPlain> plain{};
                         plain[0] = ss::HeaderTypeServer;
                         // requestSalt 回显（[9..24]），初始载荷长度 [25..26] = 0
                         std::memcpy(plain.data() + 9, salt.data(), 16);
                         const auto werr = co_await server_side->WriteAll(ServerSalt);
                         EXPECT_FALSE(werr);
                         const auto werr2 = co_await server_side->WriteAll(RespCodec.SealRaw(plain));
                         EXPECT_FALSE(werr2);
                         // payloadLen=0 的标准响应仍须跟一个 16B 空 AEAD 块（SIP022 chunk 对齐），
                         // 否则客户端读响应阶段会永久挂起
                         const auto werr3 =
                             co_await server_side->WriteAll(RespCodec.SealRaw({}));
                         EXPECT_FALSE(werr3);
                         server_done = true;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     ss::Address Target{};
                     Target.Type = ss::AddressType::Domain;
                     Target.Host = "example.com";
                     Target.Port = 443;
                     const auto herr = co_await cn->WriteHandshake(std::make_shared<MemoryStream>(std::move(e)),
                                                                   Target);
                     EXPECT_EQ(herr, Error::None);

                     // 装饰器方法
                     (void)cn->Executor();
                     EXPECT_NE(cn->NextLayer(), nullptr);
                     const auto *ccn = cn.get();
                     EXPECT_NE(ccn->NextLayer(), nullptr);
                     cn->Cancel();

                     // UDP 数据面（握手后，须在 Release 之前执行）
                     ss::Address dst{};
                     dst.Type = ss::AddressType::Ipv4;
                     dst.Host = "1.2.3.4";
                     dst.Port = 53;
                     const auto serr =
                         co_await cn->AsyncSendDatagram(dst, AsU8Span(std::string_view{"udp"}));
                     EXPECT_EQ(serr, Error::None);

                     // 最后释放内层传输
                     EXPECT_NE(cn->Release(), nullptr);

                     // 等待服务端协程结束，保证 server_side 存活至 detached 协程退出
                     net::steady_timer wait(ioc.get_executor());
                     const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                     while (!server_done && std::chrono::steady_clock::now() < deadline)
                     {
                         wait.expires_after(std::chrono::milliseconds(1));
                         co_await wait.async_wait(net::use_awaitable);
                     }
                 });
    }

} // namespace
