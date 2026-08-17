/**
 * @file HttpQuicCoverage.cpp
 * @brief core 高级协议模块审计补测（http2 / http3-qpack / http3-auth / http3-server / quic）
 * @details 覆盖 tests/common/core 下高级协议模块的纯函数与骨架接口：
 * - http2/session.hpp + stream.hpp：流打开结果工厂、失败路径、流 ID 边界、
 *   句柄委托与会话失效安全
 * - http3/qpack.hpp：QPACK 编解码往返 + 错误路径（非法前缀 / 动态表越界 /
 *   静态表越界 / 截断）+ HPACK huffman 往返与坏填充
 * - http3/auth.hpp：认证请求解析（成功/拒绝）、认证响应帧构造与回环解码
 * - http3/server.hpp：nghttp3 服务端初始化守卫 + 认证全流程（字节级 quic-go
 *   兼容路径）+ check_auth 包装
 * - quic/gateway_common.hpp：首字节分流、连接表生命周期、分发钩子
 * - quic/stream_adapter.hpp：读写委托、空提供者安全、关闭与类型传播
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

#include <common/protocols/http2/session.hpp>
#include <common/protocols/http2/stream.hpp>
#include <common/protocols/http3/auth.hpp>
#include <common/protocols/http3/qpack.hpp>
#include <common/protocols/http3/server.hpp>
#include <common/protocols/quic/gateway_common.hpp>
#include <common/protocols/quic/stream_adapter.hpp>

namespace
{

    namespace h2 = preview::http2;
    namespace h3 = preview::http3;
    namespace h3a = preview::http3;
    namespace memory = preview::memory;
    namespace qp = preview::http3::qpack;
    namespace quic = preview::quic;
    namespace net = boost::asio;

    // ── http2：会话记录型 mock ──

    /**
     * @class mock_h2_session
     * @brief h2_session 接口的记录型实现
     * @details 记录每次调用参数，供句柄委托与边界用例断言。
     */
    class mock_h2_session final : public h2::h2_session
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

        auto feed(std::span<const std::byte>, std::error_code &ec) -> bool override
        {
            ec.clear();
            return feed_result;
        }

        auto collect(std::vector<std::byte> &) -> bool override
        {
            return collect_result;
        }

        auto open_stream(const h2::header_list &, bool) -> std::int32_t override
        {
            return open_result;
        }

        auto submit_headers(std::int32_t stream_id, const h2::header_list &, bool end_stream)
            -> std::int32_t override
        {
            submitted_headers_streams.push_back(stream_id);
            headers_end.push_back(end_stream);
            return 0;
        }

        auto submit_data(std::int32_t stream_id, std::span<const std::byte> data, bool end_stream)
            -> std::int32_t override
        {
            submitted_data_streams.push_back(stream_id);
            data_end.push_back(end_stream);
            submitted_data.emplace_back(data.begin(), data.end());
            return 0;
        }

        auto reset_stream(std::int32_t stream_id, std::uint32_t error_code) -> std::int32_t override
        {
            reset_streams.push_back(stream_id);
            reset_codes.push_back(error_code);
            return 0;
        }

        auto executor() const -> net::any_io_executor override
        {
            return ex;
        }
    };

    // ── http2：用例 ──

    TEST(Http2Session, StreamOpenResultFactories)
    {
        // 成功/失败结果工厂的字段约定（失败恒为 -1）
        const auto ok = h2::stream_open_result::make_success(5);
        EXPECT_TRUE(ok.ok);
        EXPECT_EQ(ok.stream_id, 5);
        EXPECT_FALSE(ok.ec);

        const auto fail =
            h2::stream_open_result::make_failure(std::make_error_code(std::errc::protocol_error));
        EXPECT_FALSE(fail.ok);
        EXPECT_EQ(fail.stream_id, -1);
        EXPECT_TRUE(fail.ec);
        EXPECT_EQ(fail.ec, std::make_error_code(std::errc::protocol_error));
    }

    TEST(Http2Session, OpenStreamFailurePaths)
    {
        // 空会话 → not_connected
        const auto r1 = h2::open_stream(nullptr, {}, false);
        EXPECT_FALSE(r1.ok);
        EXPECT_EQ(r1.stream_id, -1);
        EXPECT_EQ(r1.ec, std::make_error_code(std::errc::not_connected));

        // 会话返回负流 ID → protocol_error（失败边界）
        auto session = std::make_shared<mock_h2_session>();
        session->open_result = -1;
        const auto r2 = h2::open_stream(session, {}, false);
        EXPECT_FALSE(r2.ok);
        EXPECT_EQ(r2.stream_id, -1);
        EXPECT_EQ(r2.ec, std::make_error_code(std::errc::protocol_error));

        // 失败时不产出句柄
        EXPECT_EQ(h2::open_stream_handle(nullptr, {}, false), nullptr);
        EXPECT_EQ(h2::open_stream_handle(session, {}, false), nullptr);
    }

    TEST(Http2Session, StreamIdBoundaries)
    {
        // 最小合法流 ID 0 可正常打开
        auto session = std::make_shared<mock_h2_session>();
        session->open_result = 0;
        const auto r = h2::open_stream(session, {}, false);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.stream_id, 0);
        auto handle = std::make_shared<h2::stream_handle>(0, session);
        EXPECT_TRUE(handle->is_open());

        // 负流 ID 句柄恒视为关闭，但操作仍委托（仅校验会话存活）
        auto bad = std::make_shared<h2::stream_handle>(-1, session);
        EXPECT_FALSE(bad->is_open());
        EXPECT_EQ(bad->reset(0), 0);
        ASSERT_EQ(session->reset_streams.size(), 1);
        EXPECT_EQ(session->reset_streams[0], -1);

        // 最大流 ID 原样透传
        auto big = std::make_shared<h2::stream_handle>(0x7FFFFFFF, session);
        EXPECT_TRUE(big->is_open());
        EXPECT_EQ(big->write({}, false), 0);
        ASSERT_EQ(session->submitted_data_streams.size(), 1);
        EXPECT_EQ(session->submitted_data_streams[0], 0x7FFFFFFF);
    }

    TEST(Http2Session, StreamHandleDelegatesOperations)
    {
        // 句柄四类写操作全部委托到会话，参数原样传递
        auto session = std::make_shared<mock_h2_session>();
        auto handle = std::make_shared<h2::stream_handle>(9, session);

        h2::header_list headers{{"x-test", "1"}};
        EXPECT_EQ(handle->submit_headers(headers, true), 0);

        const std::array<std::byte, 2> payload{std::byte{0xAA}, std::byte{0xBB}};
        EXPECT_EQ(handle->write(payload, false), 0);
        EXPECT_EQ(handle->reset(7), 0);
        EXPECT_EQ(handle->close(), 0); // close = submit_data({}, true)

        ASSERT_EQ(session->submitted_headers_streams.size(), 1);
        EXPECT_EQ(session->submitted_headers_streams[0], 9);
        ASSERT_EQ(session->headers_end.size(), 1);
        EXPECT_TRUE(session->headers_end[0]);

        ASSERT_EQ(session->submitted_data_streams.size(), 2);
        EXPECT_EQ(session->submitted_data_streams[0], 9);
        ASSERT_EQ(session->data_end.size(), 2);
        EXPECT_FALSE(session->data_end[0]);
        EXPECT_EQ(session->submitted_data[0],
                  std::vector<std::byte>(payload.begin(), payload.end()));
        EXPECT_EQ(session->submitted_data_streams[1], 9);
        EXPECT_TRUE(session->data_end[1]);
        EXPECT_TRUE(session->submitted_data[1].empty());

        ASSERT_EQ(session->reset_streams.size(), 1);
        EXPECT_EQ(session->reset_streams[0], 9);
        ASSERT_EQ(session->reset_codes.size(), 1);
        EXPECT_EQ(session->reset_codes[0], 7);
    }

    TEST(Http2Session, StreamHandleExpiredSession)
    {
        // 会话销毁后句柄安全失效：is_open=false、操作返回 -1
        h2::shared_h2_session session = std::make_shared<mock_h2_session>();
        auto handle = std::make_shared<h2::stream_handle>(5, session);
        EXPECT_TRUE(handle->is_open());
        EXPECT_NE(handle->session(), nullptr);

        session.reset();
        EXPECT_FALSE(handle->is_open());
        EXPECT_EQ(handle->session(), nullptr);
        EXPECT_EQ(handle->submit_headers({}, false), -1);
        EXPECT_EQ(handle->write({}, false), -1);
        EXPECT_EQ(handle->reset(0), -1);
        EXPECT_EQ(handle->close(), -1);
    }

    // ── http3/qpack：错误路径与编解码往返 ──

    TEST(Http3Qpack, DecodeInvalidPrefixRejected)
    {
        const auto mr = preview::memory::current_resource();
        // 空输入
        EXPECT_TRUE(qp::decode_header_block({}, mr).empty());
        // Required Insert Count != 0
        const std::array<std::uint8_t, 2> ric{0x01, 0x00};
        EXPECT_TRUE(qp::decode_header_block(ric, mr).empty());
        // Delta Base != 0
        const std::array<std::uint8_t, 2> db{0x00, 0x02};
        EXPECT_TRUE(qp::decode_header_block(db, mr).empty());
        // 前缀本身截断（8 位前缀续位无终止）
        const std::array<std::uint8_t, 1> cut{0x80};
        EXPECT_TRUE(qp::decode_header_block(cut, mr).empty());
    }

    TEST(Http3Qpack, DecodeTableBoundsRejected)
    {
        const auto mr = preview::memory::current_resource();
        // 动态表索引（T=0）不支持 → 空
        const std::array<std::uint8_t, 3> dyn{0x00, 0x00, 0x80};
        EXPECT_TRUE(qp::decode_header_block(dyn, mr).empty());
        // 动态表指令（000xxxxx）不支持 → 空
        const std::array<std::uint8_t, 3> instr{0x00, 0x00, 0x00};
        EXPECT_TRUE(qp::decode_header_block(instr, mr).empty());
        // 静态表索引 99 越界 → 空
        const std::array<std::uint8_t, 4> oob{0x00, 0x00, 0xFF, 0x24};
        EXPECT_TRUE(qp::decode_header_block(oob, mr).empty());
        // 静态表索引 98（合法末项）→ 正常解码
        const std::array<std::uint8_t, 4> last{0x00, 0x00, 0xFF, 0x23};
        const auto fields = qp::decode_header_block(last, mr);
        ASSERT_EQ(fields.size(), 1);
        EXPECT_EQ(std::string_view(fields[0].name.data(), fields[0].name.size()), "x-frame-options");
        EXPECT_EQ(std::string_view(fields[0].value.data(), fields[0].value.size()), "sameorigin");
    }

    TEST(Http3Qpack, DecodeTruncatedRejected)
    {
        const auto mr = preview::memory::current_resource();
        // 静态索引 varint 续位无终止字节
        const std::array<std::uint8_t, 4> varint{0x00, 0x00, 0xFF, 0x80};
        EXPECT_TRUE(qp::decode_header_block(varint, mr).empty());
        // 字面量名称声明长度超出剩余数据
        const std::array<std::uint8_t, 6> name{0x00, 0x00, 0x25, 0x05, 'h', 'i'};
        EXPECT_TRUE(qp::decode_header_block(name, mr).empty());
        // 字面量值 huffman 数据填充非法（解码失败）
        const std::array<std::uint8_t, 5> value{0x00, 0x00, 0x20, 0x81, 0x10};
        EXPECT_TRUE(qp::decode_header_block(value, mr).empty());
    }

    TEST(Http3Qpack, EncodeDecodeRoundtrip)
    {
        const auto mr = preview::memory::current_resource();
        // 静态表全命中：值命中 → 单字节索引（前缀 + 字面量构成完整块）
        std::array<std::uint8_t, 64> b1{};
        std::size_t off1 = qp::encode_prefix(b1);
        off1 += qp::encode_literal(":status", "200",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        ASSERT_EQ(off1, 3);
        EXPECT_EQ(b1[2], 0xD9);
        auto f1 = qp::decode_header_block(std::span<const std::uint8_t>(b1.data(), off1), mr);
        ASSERT_EQ(f1.size(), 1);
        EXPECT_EQ(std::string_view(f1[0].name.data(), f1[0].name.size()), ":status");
        EXPECT_EQ(std::string_view(f1[0].value.data(), f1[0].value.size()), "200");

        // 名称命中值不同 → 名称引用字面量
        std::array<std::uint8_t, 64> b2{};
        std::size_t off2 = qp::encode_prefix(b2);
        off2 += qp::encode_literal(":method", "HEAD",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        auto f2 = qp::decode_header_block(std::span<const std::uint8_t>(b2.data(), off2), mr);
        ASSERT_EQ(f2.size(), 1);
        EXPECT_EQ(std::string_view(f2[0].name.data(), f2[0].name.size()), ":method");
        EXPECT_EQ(std::string_view(f2[0].value.data(), f2[0].value.size()), "HEAD");

        // 未命中 → 字面量名称（长值走堆路径，>63 字符）
        std::string long_value;
        for (int i = 0; i < 10; ++i)
        {
            long_value += "0123456789";
        }
        std::array<std::uint8_t, 1024> b3{};
        std::size_t off = qp::encode_prefix(b3);
        off += qp::encode_literal("hysteria-auth", long_value,
                                  std::span<std::uint8_t>(b3.data() + off, b3.size() - off));
        auto f3 = qp::decode_header_block(std::span<const std::uint8_t>(b3.data(), off), mr);
        ASSERT_EQ(f3.size(), 1);
        EXPECT_EQ(std::string_view(f3[0].name.data(), f3[0].name.size()), "hysteria-auth");
        EXPECT_EQ(std::string_view(f3[0].value.data(), f3[0].value.size()), long_value);

        // 编码前缀 + 完整认证头集回环
        std::array<std::uint8_t, 1024> b4{};
        std::size_t off4 = qp::encode_prefix(b4);
        off4 += qp::encode_literal(":method", "POST",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::encode_literal(":path", "/auth",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::encode_literal("hysteria-auth", "password123",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        off4 += qp::encode_literal("hysteria-cc-rx", "0",
                                   std::span<std::uint8_t>(b4.data() + off4, b4.size() - off4));
        auto f4 = qp::decode_header_block(std::span<const std::uint8_t>(b4.data(), off4), mr);
        ASSERT_EQ(f4.size(), 4);
        EXPECT_EQ(std::string_view(f4[0].value.data(), f4[0].value.size()), "POST");
        EXPECT_EQ(std::string_view(f4[1].value.data(), f4[1].value.size()), "/auth");
        EXPECT_EQ(std::string_view(f4[2].value.data(), f4[2].value.size()), "password123");
        EXPECT_EQ(std::string_view(f4[3].value.data(), f4[3].value.size()), "0");

        // 输出缓冲不足 → 编码失败返回 0
        std::array<std::uint8_t, 0> tiny{};
        EXPECT_EQ(qp::encode_prefix(tiny), 0);
        EXPECT_EQ(qp::encode_literal(":method", "POST", tiny), 0);
    }

    TEST(Http3Qpack, HuffmanRoundtripAndErrors)
    {
        const auto mr = preview::memory::current_resource();
        std::string long_value;
        for (int i = 0; i < 20; ++i)
        {
            long_value += "payload-data-";
        }
        const std::vector<std::string> samples = {
            "", "a", "GET", "password123", "application/json; charset=utf-8", long_value};

        for (const auto &s : samples)
        {
            memory::vector<std::uint8_t> enc(mr);
            ASSERT_TRUE(qp::huffman_encode(s, enc));
            memory::vector<std::uint8_t> dec(mr);
            ASSERT_TRUE(qp::huffman_decode(enc, dec));
            EXPECT_EQ(std::string(dec.begin(), dec.end()), s);
        }

        // 'a'（码 00011 len5 + EOS 填充）精确字节 0x1F
        memory::vector<std::uint8_t> enc_a(mr);
        ASSERT_TRUE(qp::huffman_encode("a", enc_a));
        ASSERT_EQ(enc_a.size(), 1);
        EXPECT_EQ(enc_a[0], 0x1F);

        // 坏填充：0x10 解出 '2' 后剩余 3 位不满足 EOS 全 1 → 失败
        memory::vector<std::uint8_t> dec_bad(mr);
        const std::array<std::uint8_t, 1> bad{0x10};
        EXPECT_FALSE(qp::huffman_decode(bad, dec_bad));
    }

    // ── http3/auth：头构造与解析 ──

    TEST(Http3Auth, ParseAuthRequestSuccess)
    {
        const auto mr = preview::memory::current_resource();
        std::array<std::uint8_t, 512> buf{};
        std::size_t off = qp::encode_prefix(buf);
        off += qp::encode_literal(":method", "POST",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::encode_literal(":authority", "hysteria",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::encode_literal(":path", "/auth",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::encode_literal("hysteria-auth", "password123",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));
        off += qp::encode_literal("hysteria-cc-rx", "12345",
                                  std::span<std::uint8_t>(buf.data() + off, buf.size() - off));

        h3a::auth_request req(mr);
        ASSERT_TRUE(h3a::parse_auth_request(std::span<const std::uint8_t>(buf.data(), off), req, mr));
        EXPECT_EQ(req.method, "POST");
        EXPECT_EQ(req.host, "hysteria");
        EXPECT_EQ(req.path, "/auth");
        EXPECT_EQ(req.auth, "password123");
        EXPECT_EQ(req.rx, 12345);
    }

    TEST(Http3Auth, ParseAuthRequestRejectsInvalid)
    {
        const auto mr = preview::memory::current_resource();
        // 方法非 POST
        std::array<std::uint8_t, 128> b1{};
        std::size_t off1 = qp::encode_prefix(b1);
        off1 += qp::encode_literal(":method", "GET",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        off1 += qp::encode_literal(":path", "/auth",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        off1 += qp::encode_literal("hysteria-auth", "password123",
                                   std::span<std::uint8_t>(b1.data() + off1, b1.size() - off1));
        h3a::auth_request req1(mr);
        EXPECT_FALSE(h3a::parse_auth_request(std::span<const std::uint8_t>(b1.data(), off1), req1, mr));

        // 缺少 hysteria-auth
        std::array<std::uint8_t, 128> b2{};
        std::size_t off2 = qp::encode_prefix(b2);
        off2 += qp::encode_literal(":method", "POST",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        off2 += qp::encode_literal(":path", "/auth",
                                   std::span<std::uint8_t>(b2.data() + off2, b2.size() - off2));
        h3a::auth_request req2(mr);
        EXPECT_FALSE(h3a::parse_auth_request(std::span<const std::uint8_t>(b2.data(), off2), req2, mr));

        // 垃圾字节（QPACK 解码失败 → 字段为空）
        const std::array<std::uint8_t, 4> junk{0xFF, 0xFF, 0xFF, 0xFF};
        h3a::auth_request req3(mr);
        EXPECT_FALSE(h3a::parse_auth_request(junk, req3, mr));

        // 空输入
        h3a::auth_request req4(mr);
        EXPECT_FALSE(h3a::parse_auth_request({}, req4, mr));
    }

    TEST(Http3Auth, EncodeAuthResponseRoundtrip)
    {
        const auto mr = preview::memory::current_resource();
        std::array<std::byte, 256> out{};
        const auto n = h3a::encode_auth_response(h3a::status_auth_ok, true, 1000000, out);
        ASSERT_GT(n, 2);

        // HTTP/3 帧头：type=HEADERS(1) + 单字节长度（块 < 128）
        const auto *hdr = reinterpret_cast<const std::uint8_t *>(out.data());
        EXPECT_EQ(hdr[0], h3a::frame_headers);
        const auto len = hdr[1];
        ASSERT_LE(len, n - 2);

        // 帧载荷即 QPACK 块 → 解码回环
        const auto fields =
            qp::decode_header_block(std::span<const std::uint8_t>(hdr + 2, len), mr);
        ASSERT_EQ(fields.size(), 4);
        EXPECT_EQ(std::string_view(fields[0].value.data(), fields[0].value.size()), "233");
        EXPECT_EQ(std::string_view(fields[1].name.data(), fields[1].name.size()), "hysteria-udp");
        EXPECT_EQ(std::string_view(fields[1].value.data(), fields[1].value.size()), "true");
        EXPECT_EQ(std::string_view(fields[2].name.data(), fields[2].name.size()), "hysteria-cc-rx");
        EXPECT_EQ(std::string_view(fields[2].value.data(), fields[2].value.size()), "1000000");
        EXPECT_EQ(std::string_view(fields[3].name.data(), fields[3].name.size()), "hysteria-padding");
        EXPECT_EQ(std::string_view(fields[3].value.data(), fields[3].value.size()), "0");

        // udp 关闭分支
        std::array<std::byte, 256> out2{};
        const auto n2 = h3a::encode_auth_response(233, false, 0, out2);
        ASSERT_GT(n2, 2);
        const auto *hdr2 = reinterpret_cast<const std::uint8_t *>(out2.data());
        const auto fields2 =
            qp::decode_header_block(std::span<const std::uint8_t>(hdr2 + 2, hdr2[1]), mr);
        ASSERT_EQ(fields2.size(), 4);
        EXPECT_EQ(std::string_view(fields2[1].value.data(), fields2[1].value.size()), "false");
        EXPECT_EQ(std::string_view(fields2[2].value.data(), fields2[2].value.size()), "0");

        // 缓冲不足 → 0
        std::array<std::byte, 1> tiny{};
        EXPECT_EQ(h3a::encode_auth_response(233, true, 0, tiny), 0);
    }

    // ── http3/server：nghttp3 服务端骨架 ──

    TEST(Http3Server, InitFailureAndGuards)
    {
        auto srv = h3::make_server({});
        // 未初始化：feed 直接协议错误（conn 为空）
        EXPECT_EQ(srv->feed(0, {}, false), preview::fault::code::protocol_error);

        // open_uni_stream 失败 → init 失败
        EXPECT_FALSE(srv->init([]() -> std::int64_t { return -1; }));

        // 正常初始化：控制流 3 / encoder 7 / decoder 11（服务器 uni 流）
        int next = 3;
        ASSERT_TRUE(srv->init([&]() -> std::int64_t
                              {
                                  const auto id = next;
                                  next += 4;
                                  return id;
                              }));
        EXPECT_NE(srv->native(), nullptr);
        EXPECT_FALSE(srv->auth_headers_complete());
        EXPECT_EQ(srv->method(), "");
        EXPECT_EQ(srv->auth_stream_id(), -1);

        // 重复 init 幂等
        EXPECT_TRUE(srv->init([&]() -> std::int64_t { return -1; }));
        srv->close();
        EXPECT_EQ(srv->native(), nullptr);
    }

    TEST(Http3Server, AuthFlowEndToEnd)
    {
        const auto mr = preview::memory::current_resource();
        h3::server_options opts;
        opts.authenticate = [](std::string_view method, std::string_view path,
                               std::string_view auth)
        {
            return method == "POST" && path == "/auth" && auth == "password123";
        };
        auto srv = h3::make_server(opts);
        int next = 3;
        ASSERT_TRUE(srv->init([&]() -> std::int64_t
                              {
                                  const auto id = next;
                                  next += 4;
                                  return id;
                              }));

        // 客户端控制流（stream 2）：空 SETTINGS
        const std::array<std::byte, 2> settings{std::byte{0x04}, std::byte{0x00}};
        EXPECT_EQ(srv->feed(2, settings, false), preview::fault::code::success);

        // 客户端 QPACK encoder 流（stream 6）：Set Dynamic Table Capacity=0
        const std::array<std::byte, 1> qenc{std::byte{0x20}};
        EXPECT_EQ(srv->feed(6, qenc, false), preview::fault::code::success);

        // 认证请求流（stream 0）：QPACK 编码的 HEADERS 帧。
        // nghttp3 要求请求含 :method+:path+:scheme 且 :authority/Host 至少其一
        std::array<std::uint8_t, 512> block{};
        std::size_t off = qp::encode_prefix(block);
        off += qp::encode_literal(":method", "POST",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::encode_literal(":scheme", "https",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::encode_literal(":authority", "hysteria",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::encode_literal(":path", "/auth",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::encode_literal("hysteria-auth", "password123",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        off += qp::encode_literal("hysteria-cc-rx", "12345",
                                  std::span<std::uint8_t>(block.data() + off, block.size() - off));
        ASSERT_LT(off, 128);
        std::array<std::byte, 600> frame{};
        frame[0] = std::byte{0x01}; // HEADERS 帧类型
        frame[1] = static_cast<std::byte>(off);
        std::memcpy(frame.data() + 2, block.data(), off);
        EXPECT_EQ(srv->feed(0, std::span<const std::byte>(frame.data(), off + 2), true),
                  preview::fault::code::success);

        // 认证头解析结果
        EXPECT_TRUE(srv->auth_headers_complete());
        EXPECT_EQ(srv->method(), "POST");
        EXPECT_EQ(srv->path(), "/auth");
        EXPECT_EQ(srv->auth(), "password123");
        EXPECT_EQ(srv->rx(), 12345);
        EXPECT_EQ(srv->auth_stream_id(), 0);
        EXPECT_TRUE(srv->check_auth());

        // 认证响应提交并泵出（响应 HEADERS 帧发往 stream 0）
        EXPECT_EQ(srv->submit_auth_response(), preview::fault::code::success);
        memory::vector<h3::out_packet> out(mr);
        ASSERT_TRUE(srv->pump_output(out));
        ASSERT_FALSE(out.empty());
        bool found_response = false;
        for (const auto &p : out)
        {
            if (p.stream_id == 0 && !p.data.empty() &&
                std::to_integer<std::uint8_t>(p.data[0]) == 0x01)
            {
                found_response = true;
            }
        }
        EXPECT_TRUE(found_response);
        srv->close();
    }

    TEST(Http3Server, CheckAuthWrapperBehavior)
    {
        // 未配置回调 → 默认放行
        auto srv = h3::make_server({});
        EXPECT_TRUE(srv->check_auth());
        EXPECT_EQ(srv->options().mr, nullptr);

        // 配置回调 → 委托判定
        h3::server_options opts;
        int calls = 0;
        opts.authenticate = [&calls](std::string_view, std::string_view, std::string_view)
        {
            ++calls;
            return false;
        };
        auto srv2 = h3::make_server(opts);
        EXPECT_FALSE(srv2->check_auth());
        EXPECT_EQ(calls, 1);
        srv2->close();
    }

    // ── quic/gateway_common：分流与连接表 ──

    TEST(QuicGateway, GuessProtocolFirstByte)
    {
        // 空输入 → unknown
        EXPECT_EQ(quic::guess_protocol({}), quic::protocol_guess::unknown);
        // 0x04 = HTTP/3 SETTINGS → hysteria2
        const std::array<std::byte, 1> h3{std::byte{0x04}};
        const std::array<std::byte, 2> h3two{std::byte{0x04}, std::byte{0x01}};
        const std::array<std::byte, 1> tuic{std::byte{0x40}};
        EXPECT_EQ(quic::guess_protocol(h3), quic::protocol_guess::hysteria2);
        EXPECT_EQ(quic::guess_protocol(h3two), quic::protocol_guess::hysteria2);
        // 0x40 = tuic
        EXPECT_EQ(quic::guess_protocol(tuic), quic::protocol_guess::tuic);
        // 其余字节 → unknown
        for (const auto fb : {std::byte{0x00}, std::byte{0x05}, std::byte{0x3F}, std::byte{0x41}})
        {
            const std::array<std::byte, 1> b{fb};
            EXPECT_EQ(quic::guess_protocol(b), quic::protocol_guess::unknown);
        }
    }

    TEST(QuicGateway, ConnectionTableLifecycle)
    {
        quic::gateway_common gw;
        EXPECT_EQ(gw.size(), 0);

        const auto key = quic::gateway_common::conn_key{42};
        EXPECT_TRUE(gw.register_connection(key));
        EXPECT_FALSE(gw.register_connection(key)); // 重复登记拒绝
        EXPECT_EQ(gw.size(), 1);

        // 新登记连接状态默认值
        auto *st = gw.lookup(key);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->type, quic::protocol_guess::unknown);
        EXPECT_FALSE(st->authenticated);
        EXPECT_EQ(st->stream_count, 0);

        // 未登记键查询为 nullptr（可变与只读两版本）
        EXPECT_EQ(gw.lookup(0xDEAD), nullptr);
        const auto *cst = static_cast<const quic::gateway_common &>(gw).lookup(key);
        ASSERT_NE(cst, nullptr);
        EXPECT_EQ(cst->type, quic::protocol_guess::unknown);

        EXPECT_TRUE(gw.erase_connection(key));
        EXPECT_FALSE(gw.erase_connection(key)); // 重复移除返回 false
        EXPECT_EQ(gw.lookup(key), nullptr);
        EXPECT_EQ(gw.size(), 0);
    }

    /**
     * @class recording_gateway
     * @brief 记录分发钩子调用次数的 gateway_common 子类
     */
    class recording_gateway final : public quic::gateway_common
    {
    public:
        int h3_calls{0};
        int tuic_calls{0};
        std::vector<conn_key> h3_keys;
        std::vector<conn_key> tuic_keys;

    protected:
        void on_h3_stream(conn_key key, std::span<const std::byte>) override
        {
            ++h3_calls;
            h3_keys.push_back(key);
        }

        void on_tuic_stream(conn_key key, std::span<const std::byte>) override
        {
            ++tuic_calls;
            tuic_keys.push_back(key);
        }
    };

    TEST(QuicGateway, DispatchRoutesToHooks)
    {
        recording_gateway gw;
        const auto key = quic::gateway_common::conn_key{0x1122};
        const std::array<std::byte, 1> fb_h3{std::byte{0x04}};
        const std::array<std::byte, 1> fb_tuic{std::byte{0x40}};
        const std::array<std::byte, 1> fb_unk{std::byte{0x05}};
        // 未登记连接 → 分发拒绝
        EXPECT_FALSE(gw.dispatch(key, fb_h3));
        ASSERT_TRUE(gw.register_connection(key));

        // 0x04 → hysteria2 钩子
        EXPECT_TRUE(gw.dispatch(key, fb_h3));
        auto *st = gw.lookup(key);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->type, quic::protocol_guess::hysteria2);
        EXPECT_EQ(gw.h3_calls, 1);
        EXPECT_EQ(gw.tuic_calls, 0);
        ASSERT_EQ(gw.h3_keys.size(), 1);
        EXPECT_EQ(gw.h3_keys[0], key);

        // 0x40 → tuic 钩子（同一连接可切换判定）
        EXPECT_TRUE(gw.dispatch(key, fb_tuic));
        EXPECT_EQ(st->type, quic::protocol_guess::tuic);
        EXPECT_EQ(gw.tuic_calls, 1);
        ASSERT_EQ(gw.tuic_keys.size(), 1);
        EXPECT_EQ(gw.tuic_keys[0], key);

        // 未知首字节 → false，钩子不触发
        EXPECT_FALSE(gw.dispatch(key, fb_unk));
        EXPECT_EQ(st->type, quic::protocol_guess::unknown);
        EXPECT_EQ(gw.h3_calls, 1);
        EXPECT_EQ(gw.tuic_calls, 1);
    }

    // ── quic/stream_adapter：传输适配 ──

    /**
     * @class mock_stream_provider
     * @brief 同步完成的内存流提供者（无 ngtcp2 依赖）
     */
    class mock_stream_provider final : public quic::stream_provider
    {
    public:
        std::vector<std::byte> read_data;
        std::vector<std::byte> written;
        bool closed{false};
        std::int64_t sid{7};
        std::size_t write_limit{std::numeric_limits<std::size_t>::max()};

        auto read(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            const auto n = std::min(buffer.size(), read_data.size());
            if (n > 0)
            {
                std::memcpy(buffer.data(), read_data.data(), n);
                read_data.erase(read_data.begin(),
                                read_data.begin() + static_cast<std::ptrdiff_t>(n));
            }
            co_return n;
        }

        auto write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            const auto n = std::min(buffer.size(), write_limit);
            written.insert(written.end(), buffer.begin(),
                           buffer.begin() + static_cast<std::ptrdiff_t>(n));
            co_return n;
        }

        void close() override
        {
            closed = true;
        }

        auto stream_id() const noexcept -> std::int64_t override
        {
            return sid;
        }

        auto is_closed() const noexcept -> bool override
        {
            return closed;
        }
    };

    TEST(QuicStreamAdapter, ReadDelegatesToProvider)
    {
        net::io_context ioc;
        auto provider = std::make_shared<mock_stream_provider>();
        provider->read_data = {std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
        auto adapter = std::make_shared<quic::stream_adapter>(ioc.get_executor(), provider);

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
        auto adapter = std::make_shared<quic::stream_adapter>(ioc.get_executor(), provider);

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
        auto adapter = std::make_shared<quic::stream_adapter>(ioc.get_executor(), nullptr);

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
        adapter->close();
    }

    TEST(QuicStreamAdapter, CloseAndTypePropagation)
    {
        net::io_context ioc;
        auto provider = std::make_shared<mock_stream_provider>();
        auto adapter = std::make_shared<quic::stream_adapter>(ioc.get_executor(), provider);

        // 传输类型与执行器传播
        EXPECT_EQ(adapter->transport_type(), preview::transmission::type::tcp);
        EXPECT_EQ(adapter->executor(), ioc.get_executor());
        EXPECT_EQ(adapter->next_layer(), nullptr);

        // close 委托给提供者
        EXPECT_FALSE(provider->closed);
        adapter->close();
        EXPECT_TRUE(provider->closed);
        EXPECT_TRUE(provider->is_closed());
    }

} // namespace
