/**
 * @file HttpQuicCoverage.cpp
 * @brief core 高级协议模块审计补测（http2 / http3-qpack / http3-Auth / http3-Server / quic）
 * @details 覆盖 tests/common/core 下高级协议模块的纯函数与骨架接口：
 * - http2/Session.hpp + Stream.hpp：流打开结果工厂、失败路径、流 ID 边界、
 *   句柄委托与会话失效安全
 * - http3/qpack.hpp：QPACK 编解码往返 + 错误路径（非法前缀 / 动态表越界 /
 *   静态表越界 / 截断）+ HPACK huffman 往返与坏填充
 * - http3/Auth.hpp：认证请求解析（成功/拒绝）、认证响应帧构造与回环解码
 * - http3/Server.hpp：nghttp3 服务端初始化守卫 + 认证全流程（字节级 quic-go
 *   兼容路径）+ CheckAuth 包装
 * - quic/GatewayCommon.hpp：首字节分流、连接表生命周期、分发钩子
 * - quic/StreamAdapter.hpp：读写委托、空提供者安全、关闭与类型传播
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <common/Protocols/Http2/Session.hpp>
#include <common/Protocols/Http2/Stream.hpp>
#include <common/Protocols/Http3/Auth.hpp>
#include <common/Protocols/Http3/Qpack.hpp>
#include <common/Protocols/Http3/Server.hpp>
#include <common/Protocols/Quic/GatewayCommon.hpp>
#include <common/Protocols/Quic/StreamAdapter.hpp>

namespace
{

    namespace h2 = Preview::Http2;
    namespace h3 = Preview::Http3;
    namespace h3a = Preview::Http3;
    namespace memory = Preview::Memory;
    namespace qp = Preview::Http3::Qpack;
    namespace quic = Preview::Quic;
    namespace net = boost::asio;

    // ── http2：会话记录型 mock ──

    /**
     * @class mock_h2_session
     * @brief H2Session 接口的记录型实现
     * @details 记录每次调用参数，供句柄委托与边界用例断言。
     */
    class mock_h2_session final : public h2::H2Session
    {
    public:
        net::any_io_executor ex{};
        std::int32_t open_result{1};
        bool feed_result{true};
        bool collect_result{false};
        std::vector<std::int32_t> submitted_headers_streams;
        std::vector<bool> headers_end;
        std::vector<std::int32_t> submitted_data_streams;
        std::vector<bool> data_end;
        std::vector<std::vector<std::byte>> submitted_data;
        std::vector<std::int32_t> reset_streams;
        std::vector<std::uint32_t> reset_codes;

        auto Feed(std::span<const std::byte>, std::error_code &ec) -> bool override
        {
            ec.clear();
            return feed_result;
        }

        auto Collect(std::vector<std::byte> &) -> bool override
        {
            return collect_result;
        }

        auto OpenStream(const h2::HeaderList &, bool) -> std::int32_t override
        {
            return open_result;
        }

        auto SubmitHeaders(std::int32_t StreamId, const h2::HeaderList &, bool EndStream)
            -> std::int32_t override
        {
            submitted_headers_streams.push_back(StreamId);
            headers_end.push_back(EndStream);
            return 0;
        }

        auto SubmitData(std::int32_t StreamId, std::span<const std::byte> Data, bool EndStream)
            -> std::int32_t override
        {
            submitted_data_streams.push_back(StreamId);
            data_end.push_back(EndStream);
            submitted_data.emplace_back(Data.begin(), Data.end());
            return 0;
        }

        auto ResetStream(std::int32_t StreamId, std::uint32_t ErrorCode) -> std::int32_t override
        {
            reset_streams.push_back(StreamId);
            reset_codes.push_back(ErrorCode);
            return 0;
        }

        auto Executor() const -> net::any_io_executor override
        {
            return ex;
        }
    };

    // ── http2：用例 ──

    TEST(Http2Session, StreamOpenResultFactories)
    {
        // 成功/失败结果工厂的字段约定（失败恒为 -1）
        const auto Ok = h2::StreamOpenResult::MakeSuccess(5);
        EXPECT_TRUE(Ok.Ok);
        EXPECT_EQ(Ok.StreamId, 5);
        EXPECT_FALSE(Ok.ec);

        const auto Fail =
            h2::StreamOpenResult::MakeFailure(std::make_error_code(std::errc::protocol_error));
        EXPECT_FALSE(Fail.Ok);
        EXPECT_EQ(Fail.StreamId, -1);
        EXPECT_TRUE(Fail.ec);
        EXPECT_EQ(Fail.ec, std::make_error_code(std::errc::protocol_error));
    }

    TEST(Http2Session, OpenStreamFailurePaths)
    {
        // 空会话 → not_connected
        const auto r1 = h2::OpenStream(nullptr, {}, false);
        EXPECT_FALSE(r1.Ok);
        EXPECT_EQ(r1.StreamId, -1);
        EXPECT_EQ(r1.ec, std::make_error_code(std::errc::not_connected));

        // 会话返回负流 ID → protocol_error（失败边界）
        auto Session = std::make_shared<mock_h2_session>();
        Session->open_result = -1;
        const auto r2 = h2::OpenStream(Session, {}, false);
        EXPECT_FALSE(r2.Ok);
        EXPECT_EQ(r2.StreamId, -1);
        EXPECT_EQ(r2.ec, std::make_error_code(std::errc::protocol_error));

        // 失败时不产出句柄
        EXPECT_EQ(h2::OpenStreamHandle(nullptr, {}, false), nullptr);
        EXPECT_EQ(h2::OpenStreamHandle(Session, {}, false), nullptr);
    }

    TEST(Http2Session, StreamIdBoundaries)
    {
        // 最小合法流 ID 0 可正常打开
        auto Session = std::make_shared<mock_h2_session>();
        Session->open_result = 0;
        const auto r = h2::OpenStream(Session, {}, false);
        EXPECT_TRUE(r.Ok);
        EXPECT_EQ(r.StreamId, 0);
        auto Handle = std::make_shared<h2::StreamHandle>(0, Session);
        EXPECT_TRUE(Handle->IsOpen());

        // 负流 ID 句柄恒视为关闭，但操作仍委托（仅校验会话存活）
        auto bad = std::make_shared<h2::StreamHandle>(-1, Session);
        EXPECT_FALSE(bad->IsOpen());
        EXPECT_EQ(bad->Reset(0), 0);
        ASSERT_EQ(Session->reset_streams.size(), 1);
        EXPECT_EQ(Session->reset_streams[0], -1);

        // 最大流 ID 原样透传
        auto big = std::make_shared<h2::StreamHandle>(0x7FFFFFFF, Session);
        EXPECT_TRUE(big->IsOpen());
        EXPECT_EQ(big->Write({}, false), 0);
        ASSERT_EQ(Session->submitted_data_streams.size(), 1);
        EXPECT_EQ(Session->submitted_data_streams[0], 0x7FFFFFFF);
    }

    TEST(Http2Session, StreamHandleDelegatesOperations)
    {
        // 句柄四类写操作全部委托到会话，参数原样传递
        auto Session = std::make_shared<mock_h2_session>();
        auto Handle = std::make_shared<h2::StreamHandle>(9, Session);

        h2::HeaderList headers{{"x-test", "1"}};
        EXPECT_EQ(Handle->SubmitHeaders(headers, true), 0);

        const std::array<std::byte, 2> payload{std::byte{0xAA}, std::byte{0xBB}};
        EXPECT_EQ(Handle->Write(payload, false), 0);
        EXPECT_EQ(Handle->Reset(7), 0);
        EXPECT_EQ(Handle->Close(), 0); // Close = SubmitData({}, true)

        ASSERT_EQ(Session->submitted_headers_streams.size(), 1);
        EXPECT_EQ(Session->submitted_headers_streams[0], 9);
        ASSERT_EQ(Session->headers_end.size(), 1);
        EXPECT_TRUE(Session->headers_end[0]);

        ASSERT_EQ(Session->submitted_data_streams.size(), 2);
        EXPECT_EQ(Session->submitted_data_streams[0], 9);
        ASSERT_EQ(Session->data_end.size(), 2);
        EXPECT_FALSE(Session->data_end[0]);
        EXPECT_EQ(Session->submitted_data[0],
                  std::vector<std::byte>(payload.begin(), payload.end()));
        EXPECT_EQ(Session->submitted_data_streams[1], 9);
        EXPECT_TRUE(Session->data_end[1]);
        EXPECT_TRUE(Session->submitted_data[1].empty());

        ASSERT_EQ(Session->reset_streams.size(), 1);
        EXPECT_EQ(Session->reset_streams[0], 9);
        ASSERT_EQ(Session->reset_codes.size(), 1);
        EXPECT_EQ(Session->reset_codes[0], 7);
    }

    TEST(Http2Session, StreamHandleExpiredSession)
    {
        // 会话销毁后句柄安全失效：IsOpen=false、操作返回 -1
        h2::SharedH2Session Session = std::make_shared<mock_h2_session>();
        auto Handle = std::make_shared<h2::StreamHandle>(5, Session);
        EXPECT_TRUE(Handle->IsOpen());
        EXPECT_NE(Handle->Session(), nullptr);

        Session.reset();
        EXPECT_FALSE(Handle->IsOpen());
        EXPECT_EQ(Handle->Session(), nullptr);
        EXPECT_EQ(Handle->SubmitHeaders({}, false), -1);
        EXPECT_EQ(Handle->Write({}, false), -1);
        EXPECT_EQ(Handle->Reset(0), -1);
        EXPECT_EQ(Handle->Close(), -1);
    }

    // ── http3/qpack：错误路径与编解码往返 ──

    TEST(Http3Qpack, DecodeInvalidPrefixRejected)
    {
        const auto mr = Preview::Memory::CurrentResource();
        // 空输入
        EXPECT_TRUE(qp::DecodeHeaderBlock({}, mr).empty());
        // Required Insert Count != 0
        const std::array<std::uint8_t, 2> ric{0x01, 0x00};
        EXPECT_TRUE(qp::DecodeHeaderBlock(ric, mr).empty());
        // Delta Base != 0
        const std::array<std::uint8_t, 2> db{0x00, 0x02};
        EXPECT_TRUE(qp::DecodeHeaderBlock(db, mr).empty());
        // 前缀本身截断（8 位前缀续位无终止）
        const std::array<std::uint8_t, 1> cut{0x80};
        EXPECT_TRUE(qp::DecodeHeaderBlock(cut, mr).empty());
    }

    TEST(Http3Qpack, DecodeTableBoundsRejected)
    {
        const auto mr = Preview::Memory::CurrentResource();
        // 动态表索引（T=0）不支持 → 空
        const std::array<std::uint8_t, 3> dyn{0x00, 0x00, 0x80};
        EXPECT_TRUE(qp::DecodeHeaderBlock(dyn, mr).empty());
        // 动态表指令（000xxxxx）不支持 → 空
        const std::array<std::uint8_t, 3> instr{0x00, 0x00, 0x00};
        EXPECT_TRUE(qp::DecodeHeaderBlock(instr, mr).empty());
        // 静态表索引 99 越界 → 空
        const std::array<std::uint8_t, 4> oob{0x00, 0x00, 0xFF, 0x24};
        EXPECT_TRUE(qp::DecodeHeaderBlock(oob, mr).empty());
        // 静态表索引 98（合法末项）→ 正常解码
        const std::array<std::uint8_t, 4> last{0x00, 0x00, 0xFF, 0x23};
        const auto fields = qp::DecodeHeaderBlock(last, mr);
        ASSERT_EQ(fields.size(), 1);
        EXPECT_EQ(std::string_view(fields[0].Name.data(), fields[0].Name.size()), "x-Frame-Options");
        EXPECT_EQ(std::string_view(fields[0].value.data(), fields[0].value.size()), "sameorigin");
    }

    TEST(Http3Qpack, DecodeTruncatedRejected)
    {
        const auto mr = Preview::Memory::CurrentResource();
        // 静态索引 varint 续位无终止字节
        const std::array<std::uint8_t, 4> varint{0x00, 0x00, 0xFF, 0x80};
        EXPECT_TRUE(qp::DecodeHeaderBlock(varint, mr).empty());
        // 字面量名称声明长度超出剩余数据
        const std::array<std::uint8_t, 6> Name{0x00, 0x00, 0x25, 0x05, 'h', 'i'};
        EXPECT_TRUE(qp::DecodeHeaderBlock(Name, mr).empty());
        // 字面量值 huffman 数据填充非法（解码失败）
        const std::array<std::uint8_t, 5> value{0x00, 0x00, 0x20, 0x81, 0x10};
        EXPECT_TRUE(qp::DecodeHeaderBlock(value, mr).empty());
    }

    TEST(Http3Qpack, EncodeDecodeRoundtrip)
    {
        const auto mr = Preview::Memory::CurrentResource();
        // 静态表全命中：值命中 → 单字节索引（前缀 + 字面量构成完整块）
        std::array<std::uint8_t, 64> b1{};
        std::size_t off1 = qp::EncodePrefix(b1);
        off1 += qp::EncodeLiteral(":status", "200",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        ASSERT_EQ(off1, 3);
        EXPECT_EQ(b1[2], 0xD9);
        auto f1 = qp::DecodeHeaderBlock(std::span<const std::uint8_t>(b1.data(), off1), mr);
        ASSERT_EQ(f1.size(), 1);
        EXPECT_EQ(std::string_view(f1[0].Name.data(), f1[0].Name.size()), ":status");
        EXPECT_EQ(std::string_view(f1[0].value.data(), f1[0].value.size()), "200");

        // 名称命中值不同 → 名称引用字面量
        std::array<std::uint8_t, 64> b2{};
        std::size_t off2 = qp::EncodePrefix(b2);
        off2 += qp::EncodeLiteral(":method", "HEAD",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        auto f2 = qp::DecodeHeaderBlock(std::span<const std::uint8_t>(b2.data(), off2), mr);
        ASSERT_EQ(f2.size(), 1);
        EXPECT_EQ(std::string_view(f2[0].Name.data(), f2[0].Name.size()), ":method");
        EXPECT_EQ(std::string_view(f2[0].value.data(), f2[0].value.size()), "HEAD");

        // 未命中 → 字面量名称（长值走堆路径，>63 字符）
        std::string long_value;
        for (int i = 0; i < 10; ++i)
        {
            long_value += "0123456789";
        }
        std::array<std::uint8_t, 1024> b3{};
        std::size_t off = qp::EncodePrefix(b3);
        off += qp::EncodeLiteral("hysteria-auth", long_value,
                                  std::span<std::uint8_t>(b3.data() + off, b3.size() - off));
        auto f3 = qp::DecodeHeaderBlock(std::span<const std::uint8_t>(b3.data(), off), mr);
        ASSERT_EQ(f3.size(), 1);
        EXPECT_EQ(std::string_view(f3[0].Name.data(), f3[0].Name.size()), "hysteria-auth");
        EXPECT_EQ(std::string_view(f3[0].value.data(), f3[0].value.size()), long_value);

        // 编码前缀 + 完整认证头集回环
        std::array<std::uint8_t, 1024> b4{};
        std::size_t off4 = qp::EncodePrefix(b4);
        off4 += qp::EncodeLiteral(":method", "POST",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::EncodeLiteral(":path", "/Auth",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::EncodeLiteral("hysteria-auth", "password123",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::EncodeLiteral("hysteria-cc-rx", "0",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        auto f4 = qp::DecodeHeaderBlock(std::span<const std::uint8_t>(b4.data(), off4), mr);
        ASSERT_EQ(f4.size(), 4);
        EXPECT_EQ(std::string_view(f4[0].value.data(), f4[0].value.size()), "POST");
        EXPECT_EQ(std::string_view(f4[1].value.data(), f4[1].value.size()), "/Auth");
        EXPECT_EQ(std::string_view(f4[2].value.data(), f4[2].value.size()), "password123");
        EXPECT_EQ(std::string_view(f4[3].value.data(), f4[3].value.size()), "0");

        // 输出缓冲不足 → 编码失败返回 0
        std::array<std::uint8_t, 0> tiny{};
        EXPECT_EQ(qp::EncodePrefix(tiny), 0);
        EXPECT_EQ(qp::EncodeLiteral(":method", "POST", tiny), 0);
    }

    TEST(Http3Qpack, HuffmanRoundtripAndErrors)
    {
        const auto mr = Preview::Memory::CurrentResource();
        std::string long_value;
        for (int i = 0; i < 20; ++i)
        {
            long_value += "payload-Data-";
        }
        const std::vector<std::string> samples = {
            "", "a", "GET", "password123", "application/json; charset=utf-8", long_value};

        for (const auto &s : samples)
        {
            std::vector<std::uint8_t> enc;
            ASSERT_TRUE(qp::HuffmanEncode(s, enc));
            std::vector<std::uint8_t> dec;
            ASSERT_TRUE(qp::HuffmanDecode(enc, dec));
            EXPECT_EQ(std::string(dec.begin(), dec.end()), s);
        }

        // 'a'（码 00011 len5 + EOS 填充）精确字节 0x1F
        std::vector<std::uint8_t> enc_a;
        ASSERT_TRUE(qp::HuffmanEncode("a", enc_a));
        ASSERT_EQ(enc_a.size(), 1);
        EXPECT_EQ(enc_a[0], 0x1F);

        // 坏填充：0x10 解出 '2' 后剩余 3 位不满足 EOS 全 1 → 失败
        std::vector<std::uint8_t> dec_bad;
        const std::array<std::uint8_t, 1> bad{0x10};
        EXPECT_FALSE(qp::HuffmanDecode(bad, dec_bad));
    }

    // ── http3/Auth：头构造与解析 ──

    TEST(Http3Auth, ParseAuthRequestSuccess)
    {
        const auto mr = Preview::Memory::CurrentResource();
        std::array<std::uint8_t, 512> buf{};
        std::size_t off = qp::EncodePrefix(buf);
        off += qp::EncodeLiteral(":method", "POST",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::EncodeLiteral(":authority", "hysteria",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::EncodeLiteral(":path", "/Auth",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::EncodeLiteral("hysteria-auth", "password123",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::EncodeLiteral("hysteria-cc-rx", "12345",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));

        h3a::AuthRequest req(mr);
        ASSERT_TRUE(h3a::ParseAuthRequest(std::span<const std::uint8_t>(buf.data(), off), req, mr));
        EXPECT_EQ(req.Method, "POST");
        EXPECT_EQ(req.Host, "hysteria");
        EXPECT_EQ(req.Path, "/Auth");
        EXPECT_EQ(req.Auth, "password123");
        EXPECT_EQ(req.Rx, 12345);
    }

    TEST(Http3Auth, ParseAuthRequestRejectsInvalid)
    {
        const auto mr = Preview::Memory::CurrentResource();
        // 方法非 POST
        std::array<std::uint8_t, 128> b1{};
        std::size_t off1 = qp::EncodePrefix(b1);
        off1 += qp::EncodeLiteral(":method", "GET",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        off1 += qp::EncodeLiteral(":path", "/Auth",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        off1 += qp::EncodeLiteral("hysteria-auth", "password123",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        h3a::AuthRequest req1(mr);
        EXPECT_FALSE(h3a::ParseAuthRequest(std::span<const std::uint8_t>(b1.data(), off1), req1, mr));

        // 缺少 hysteria-auth
        std::array<std::uint8_t, 128> b2{};
        std::size_t off2 = qp::EncodePrefix(b2);
        off2 += qp::EncodeLiteral(":method", "POST",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        off2 += qp::EncodeLiteral(":path", "/Auth",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        h3a::AuthRequest req2(mr);
        EXPECT_FALSE(h3a::ParseAuthRequest(std::span<const std::uint8_t>(b2.data(), off2), req2, mr));

        // 垃圾字节（QPACK 解码失败 → 字段为空）
        const std::array<std::uint8_t, 4> junk{0xFF, 0xFF, 0xFF, 0xFF};
        h3a::AuthRequest req3(mr);
        EXPECT_FALSE(h3a::ParseAuthRequest(junk, req3, mr));

        // 空输入
        h3a::AuthRequest req4(mr);
        EXPECT_FALSE(h3a::ParseAuthRequest({}, req4, mr));
    }

    TEST(Http3Auth, EncodeAuthResponseRoundtrip)
    {
        const auto mr = Preview::Memory::CurrentResource();
        std::array<std::byte, 256> out{};
        const auto n = h3a::EncodeAuthResponse(h3a::StatusAuthOk, true, 1000000, out);
        ASSERT_GT(n, 2);

        // HTTP/3 帧头：Type=HEADERS(1) + Length varint（RFC 9000 §16）
        const auto *hdr = reinterpret_cast<const std::uint8_t *>(out.data());
        auto ParseVarint = [](const std::uint8_t *p, std::size_t &pos) -> std::uint64_t
        {
            const auto first = p[pos++];
            std::uint64_t v = first & 0x3F;
            static constexpr std::uint8_t Extra[4] = {0, 1, 3, 7};
            for (std::size_t i = 0; i < Extra[first >> 6]; ++i)
            {
                v = (v << 8) | p[pos++];
            }
            return v;
        };
        std::size_t pos = 0;
        EXPECT_EQ(ParseVarint(hdr, pos), h3a::FrameHeaders);
        const auto len = ParseVarint(hdr, pos);
        ASSERT_LE(len, n - pos);

        // 帧载荷即 QPACK 块 → 解码回环
        const auto fields =
            qp::DecodeHeaderBlock(std::span<const std::uint8_t>(hdr + pos, len), mr);
        ASSERT_EQ(fields.size(), 4);
        EXPECT_EQ(std::string_view(fields[0].value.data(), fields[0].value.size()), "233");
        EXPECT_EQ(std::string_view(fields[1].Name.data(), fields[1].Name.size()), "hysteria-udp");
        EXPECT_EQ(std::string_view(fields[1].value.data(), fields[1].value.size()), "true");
        EXPECT_EQ(std::string_view(fields[2].Name.data(), fields[2].Name.size()), "hysteria-cc-rx");
        EXPECT_EQ(std::string_view(fields[2].value.data(), fields[2].value.size()), "1000000");
        EXPECT_EQ(std::string_view(fields[3].Name.data(), fields[3].Name.size()), "hysteria-padding");
        EXPECT_EQ(std::string_view(fields[3].value.data(), fields[3].value.size()), "0");

        // udp 关闭分支
        std::array<std::byte, 256> out2{};
        const auto n2 = h3a::EncodeAuthResponse(233, false, 0, out2);
        ASSERT_GT(n2, 2);
        const auto *hdr2 = reinterpret_cast<const std::uint8_t *>(out2.data());
        std::size_t pos2 = 0;
        ParseVarint(hdr2, pos2); // Type
        const auto len2 = ParseVarint(hdr2, pos2);
        ASSERT_LE(len2, n2 - pos2);
        const auto fields2 =
            qp::DecodeHeaderBlock(std::span<const std::uint8_t>(hdr2 + pos2, len2), mr);
        ASSERT_EQ(fields2.size(), 4);
        EXPECT_EQ(std::string_view(fields2[1].value.data(), fields2[1].value.size()), "false");
        EXPECT_EQ(std::string_view(fields2[2].value.data(), fields2[2].value.size()), "0");

        // 缓冲不足 → 0
        std::array<std::byte, 1> tiny{};
        EXPECT_EQ(h3a::EncodeAuthResponse(233, true, 0, tiny), 0);
    }

    // ── http3/Server：nghttp3 服务端骨架 ──

    TEST(Http3Server, InitFailureAndGuards)
    {
        auto srv = h3::MakeServer({});
        // 未初始化：Feed 直接协议错误（Conn 为空）
        EXPECT_EQ(srv->Feed(0, {}, false), Preview::Fault::Code::ProtocolError);

        // OpenUniStream 失败 → Init 失败
        EXPECT_FALSE(srv->Init([]() -> std::int64_t { return -1; }));

        // 正常初始化：控制流 3 / encoder 7 / decoder 11（服务器 uni 流）
        int next = 3;
        ASSERT_TRUE(srv->Init([&]() -> std::int64_t
                              {
                                  const auto Id = next;
                                  next += 4;
                                  return Id;
                              }));
        EXPECT_NE(srv->Native(), nullptr);
        EXPECT_FALSE(srv->AuthHeadersComplete());
        EXPECT_EQ(srv->Method(), "");
        EXPECT_EQ(srv->AuthStreamId(), -1);

        // 重复 Init 幂等
        EXPECT_TRUE(srv->Init([&]() -> std::int64_t { return -1; }));
        srv->Close();
        EXPECT_EQ(srv->Native(), nullptr);
    }

    TEST(Http3Server, AuthFlowEndToEnd)
    {
        const auto mr = Preview::Memory::CurrentResource();
        h3::ServerOptions opts;
        opts.authenticate = [](std::string_view Method, std::string_view Path,
                               std::string_view Auth)
        {
            return Method == "POST" && Path == "/Auth" && Auth == "password123";
        };
        auto srv = h3::MakeServer(opts);
        int next = 3;
        ASSERT_TRUE(srv->Init([&]() -> std::int64_t
                              {
                                  const auto Id = next;
                                  next += 4;
                                  return Id;
                              }));

        // 客户端控制流（Stream 2）：空 SETTINGS
        const std::array<std::byte, 2> settings{std::byte{0x04}, std::byte{0x00}};
        EXPECT_EQ(srv->Feed(2, settings, false), Preview::Fault::Code::Success);

        // 客户端 QPACK encoder 流（Stream 6）：Set Dynamic Table Capacity=0
        const std::array<std::byte, 1> qenc{std::byte{0x20}};
        EXPECT_EQ(srv->Feed(6, qenc, false), Preview::Fault::Code::Success);

        // 认证请求流（Stream 0）：QPACK 编码的 HEADERS 帧。
        // nghttp3 要求请求含 :method+:path+:scheme 且 :authority/Host 至少其一
        std::array<std::uint8_t, 512> block{};
        std::size_t off = qp::EncodePrefix(block);
        off += qp::EncodeLiteral(":method", "POST",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::EncodeLiteral(":scheme", "https",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::EncodeLiteral(":authority", "hysteria",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::EncodeLiteral(":path", "/Auth",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::EncodeLiteral("hysteria-auth", "password123",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::EncodeLiteral("hysteria-cc-rx", "12345",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        ASSERT_LT(off, block.size());

        // HTTP/3 HEADERS 帧：Type varint(1) + Length varint（RFC 9000 §16）+ QPACK 块
        std::array<std::byte, 600> Frame{};
        std::size_t fn = 0;
        ASSERT_TRUE(h3a::WriteFrameVarint(Frame, fn, h3a::FrameHeaders));
        ASSERT_TRUE(h3a::WriteFrameVarint(Frame, fn, off));
        std::memcpy(Frame.data() + fn, block.data(), off);
        EXPECT_EQ(srv->Feed(0, std::span<const std::byte>(Frame.data(), fn + off), true),
                  Preview::Fault::Code::Success);

        // 认证头解析结果
        EXPECT_TRUE(srv->AuthHeadersComplete());
        EXPECT_EQ(srv->Method(), "POST");
        EXPECT_EQ(srv->Path(), "/Auth");
        EXPECT_EQ(srv->Auth(), "password123");
        EXPECT_EQ(srv->Rx(), 12345);
        EXPECT_EQ(srv->AuthStreamId(), 0);
        EXPECT_TRUE(srv->CheckAuth());

        // 认证响应提交并泵出（响应 HEADERS 帧发往 Stream 0）
        EXPECT_EQ(srv->SubmitAuthResponse(), Preview::Fault::Code::Success);
        std::vector<h3::OutPacket> out;
        ASSERT_TRUE(srv->PumpOutput(out));
        ASSERT_FALSE(out.empty());
        bool found_response = false;
        for (const auto &p : out)
        {
            if (p.StreamId == 0 && !p.Data.empty() &&
                std::to_integer<std::uint8_t>(p.Data[0]) == 0x01)
            {
                found_response = true;
            }
        }
        EXPECT_TRUE(found_response);
        srv->Close();
    }

    TEST(Http3Server, CheckAuthWrapperBehavior)
    {
        // 未配置回调 → 默认放行
        auto srv = h3::MakeServer({});
        EXPECT_TRUE(srv->CheckAuth());
        EXPECT_EQ(srv->Options().mr, nullptr);

        // 配置回调 → 委托判定
        h3::ServerOptions opts;
        int calls = 0;
        opts.authenticate = [&calls](std::string_view, std::string_view, std::string_view)
        {
            ++calls;
            return false;
        };
        auto srv2 = h3::MakeServer(opts);
        EXPECT_FALSE(srv2->CheckAuth());
        EXPECT_EQ(calls, 1);
        srv2->Close();
    }

    // ── quic/GatewayCommon：分流与连接表 ──

    TEST(QuicGateway, GuessProtocolFirstByte)
    {
        // 空输入 → unknown
        EXPECT_EQ(Preview::Quic::GuessProtocol({}), Preview::Quic::ProtocolGuess::Unknown);
        // 0x04 = HTTP/3 SETTINGS → hysteria2
        const std::array<std::byte, 1> h3{std::byte{0x04}};
        const std::array<std::byte, 2> h3two{std::byte{0x04}, std::byte{0x01}};
        const std::array<std::byte, 1> tuic{std::byte{0x40}};
        EXPECT_EQ(Preview::Quic::GuessProtocol(h3), Preview::Quic::ProtocolGuess::Hysteria2);
        EXPECT_EQ(Preview::Quic::GuessProtocol(h3two), Preview::Quic::ProtocolGuess::Hysteria2);
        // 0x40 = tuic
        EXPECT_EQ(Preview::Quic::GuessProtocol(tuic), Preview::Quic::ProtocolGuess::Tuic);
        // 其余字节 → unknown
        for (const auto fb : {std::byte{0x00}, std::byte{0x05}, std::byte{0x3F}, std::byte{0x41}})
        {
            const std::array<std::byte, 1> b{fb};
            EXPECT_EQ(Preview::Quic::GuessProtocol(b), Preview::Quic::ProtocolGuess::Unknown);
        }
    }

    TEST(QuicGateway, ConnectionTableLifecycle)
    {
        Preview::Quic::GatewayCommon gw;
        EXPECT_EQ(gw.Size(), 0);

        const auto key = Preview::Quic::GatewayCommon::ConnKey{42};
        EXPECT_TRUE(gw.RegisterConnection(key));
        EXPECT_FALSE(gw.RegisterConnection(key)); // 重复登记拒绝
        EXPECT_EQ(gw.Size(), 1);

        // 新登记连接状态默认值
        auto *st = gw.Lookup(key);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->Type, Preview::Quic::ProtocolGuess::Unknown);
        EXPECT_FALSE(st->authenticated);
        EXPECT_EQ(st->StreamCount, 0);

        // 未登记键查询为 nullptr（可变与只读两版本）
        EXPECT_EQ(gw.Lookup(0xDEAD), nullptr);
        const auto *cst = static_cast<const Preview::Quic::GatewayCommon &>(gw).Lookup(key);
        ASSERT_NE(cst, nullptr);
        EXPECT_EQ(cst->Type, Preview::Quic::ProtocolGuess::Unknown);

        EXPECT_TRUE(gw.EraseConnection(key));
        EXPECT_FALSE(gw.EraseConnection(key)); // 重复移除返回 false
        EXPECT_EQ(gw.Lookup(key), nullptr);
        EXPECT_EQ(gw.Size(), 0);
    }

    /**
     * @class recording_gateway
     * @brief 记录分发钩子调用次数的 GatewayCommon 子类
     */
    class recording_gateway final : public Preview::Quic::GatewayCommon
    {
    public:
        int h3_calls{0};
        int tuic_calls{0};
        std::vector<ConnKey> h3_keys;
        std::vector<ConnKey> tuic_keys;

    protected:
        void OnH3Stream(ConnKey key, std::span<const std::byte>) override
        {
            ++h3_calls;
            h3_keys.push_back(key);
        }

        void OnTuicStream(ConnKey key, std::span<const std::byte>) override
        {
            ++tuic_calls;
            tuic_keys.push_back(key);
        }
    };

    TEST(QuicGateway, DispatchRoutesToHooks)
    {
        recording_gateway gw;
        const auto key = Preview::Quic::GatewayCommon::ConnKey{0x1122};
        const std::array<std::byte, 1> fb_h3{std::byte{0x04}};
        const std::array<std::byte, 1> fb_tuic{std::byte{0x40}};
        const std::array<std::byte, 1> fb_unk{std::byte{0x05}};
        // 未登记连接 → 分发拒绝
        EXPECT_FALSE(gw.Dispatch(key, fb_h3));
        ASSERT_TRUE(gw.RegisterConnection(key));

        // 0x04 → hysteria2 钩子
        EXPECT_TRUE(gw.Dispatch(key, fb_h3));
        auto *st = gw.Lookup(key);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->Type, Preview::Quic::ProtocolGuess::Hysteria2);
        EXPECT_EQ(gw.h3_calls, 1);
        EXPECT_EQ(gw.tuic_calls, 0);
        ASSERT_EQ(gw.h3_keys.size(), 1);
        EXPECT_EQ(gw.h3_keys[0], key);

        // 0x40 → tuic 钩子（同一连接可切换判定）
        EXPECT_TRUE(gw.Dispatch(key, fb_tuic));
        EXPECT_EQ(st->Type, Preview::Quic::ProtocolGuess::Tuic);
        EXPECT_EQ(gw.tuic_calls, 1);
        ASSERT_EQ(gw.tuic_keys.size(), 1);
        EXPECT_EQ(gw.tuic_keys[0], key);

        // 未知首字节 → false，钩子不触发
        EXPECT_FALSE(gw.Dispatch(key, fb_unk));
        EXPECT_EQ(st->Type, Preview::Quic::ProtocolGuess::Unknown);
        EXPECT_EQ(gw.h3_calls, 1);
        EXPECT_EQ(gw.tuic_calls, 1);
    }

    // ── quic/StreamAdapter：传输适配 ──

    /**
     * @class mock_stream_provider
     * @brief 同步完成的内存流提供者（无 ngtcp2 依赖）
     */
    class mock_stream_provider final : public Preview::Quic::StreamProvider
    {
    public:
        std::vector<std::byte> read_data;
        std::vector<std::byte> written;
        bool closed{false};
        std::int64_t sid{7};
        std::size_t write_limit{std::numeric_limits<std::size_t>::max()};

        auto Read(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            const auto n = std::min(Buffer.size(), read_data.size());
            if (n > 0)
            {
                std::memcpy(Buffer.data(), read_data.data(), n);
                read_data.erase(read_data.begin(),
                                read_data.begin() + static_cast<std::ptrdiff_t>(n));
            }
            co_return n;
        }

        auto Write(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            const auto n = std::min(Buffer.size(), write_limit);
            written.insert(written.end(), Buffer.begin(),
                           Buffer.begin() + static_cast<std::ptrdiff_t>(n));
            co_return n;
        }

        void Close() override
        {
            closed = true;
        }

        auto StreamId() const noexcept -> std::int64_t override
        {
            return sid;
        }

        auto IsClosed() const noexcept -> bool override
        {
            return closed;
        }
    };

    TEST(QuicStreamAdapter, ReadDelegatesToProvider)
    {
        net::io_context ioc;
        auto provider = std::make_shared<mock_stream_provider>();
        provider->read_data = {std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
        auto adapter = std::make_shared<Preview::Quic::StreamAdapter>(ioc.get_executor(), provider);

        std::exception_ptr ep;
        std::array<std::byte, 8> buf{};
        std::error_code ec;
        std::size_t n1 = 0;
        std::size_t n2 = 0;
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                n1 = co_await adapter->async_read_some(buf, ec);
                n2 = co_await adapter->async_read_some(buf, ec); // 数据耗尽 → EOF
                co_return;
            },
            [&](std::exception_ptr e) { ep = e; });
        ioc.run();

        ASSERT_EQ(ep, nullptr);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n1, 3);
        EXPECT_EQ(n2, 0);
        EXPECT_EQ(buf[0], std::byte{0x41});
        EXPECT_EQ(buf[2], std::byte{0x43});
    }

    TEST(QuicStreamAdapter, WriteDelegatesToProvider)
    {
        net::io_context ioc;
        auto provider = std::make_shared<mock_stream_provider>();
        provider->write_limit = 2; // 提供者部分写入
        auto adapter = std::make_shared<Preview::Quic::StreamAdapter>(ioc.get_executor(), provider);

        const std::array<std::byte, 3> payload{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
        std::exception_ptr ep;
        std::error_code ec;
        std::size_t n = 0;
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                n = co_await adapter->async_write_some(payload, ec);
                co_return;
            },
            [&](std::exception_ptr e) { ep = e; });
        ioc.run();

        ASSERT_EQ(ep, nullptr);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 2);
        ASSERT_EQ(provider->written.size(), 2);
        EXPECT_EQ(provider->written[0], std::byte{0x41});
        EXPECT_EQ(provider->written[1], std::byte{0x42});
    }

    TEST(QuicStreamAdapter, NullProviderErrorSafe)
    {
        net::io_context ioc;
        auto adapter = std::make_shared<Preview::Quic::StreamAdapter>(ioc.get_executor(), nullptr);

        std::exception_ptr ep;
        std::array<std::byte, 4> buf{};
        std::array<std::byte, 1> one{std::byte{0x01}};
        std::error_code ec;
        std::error_code wec;
        std::size_t n = 0;
        std::size_t wn = 0;
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                n = co_await adapter->async_read_some(buf, ec);
                wn = co_await adapter->async_write_some(one, wec);
                co_return;
            },
            [&](std::exception_ptr e) { ep = e; });
        ioc.run();

        ASSERT_EQ(ep, nullptr);
        EXPECT_EQ(n, 0);
        EXPECT_EQ(ec, std::make_error_code(std::errc::bad_file_descriptor));
        EXPECT_EQ(wn, 0);
        EXPECT_EQ(wec, std::make_error_code(std::errc::bad_file_descriptor));

        // 关闭空提供者不崩溃
        adapter->Close();
    }

    TEST(QuicStreamAdapter, CloseAndTypePropagation)
    {
        net::io_context ioc;
        auto provider = std::make_shared<mock_stream_provider>();
        auto adapter = std::make_shared<Preview::Quic::StreamAdapter>(ioc.get_executor(), provider);

        // 传输类型与执行器传播
        EXPECT_EQ(adapter->TransportType(), Preview::Transmission::Type::Tcp);
        EXPECT_EQ(adapter->Executor(), ioc.get_executor());
        EXPECT_EQ(adapter->NextLayer(), nullptr);

        // Close 委托给提供者
        EXPECT_FALSE(provider->closed);
        adapter->Close();
        EXPECT_TRUE(provider->closed);
        EXPECT_TRUE(provider->IsClosed());
    }

} // namespace
