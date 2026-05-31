/**
 * @file TlsSignal.cpp
 * @brief TLS ClientHello 信号解析器单元测试
 * @details 测试 psm::recognition::tls::parse_client_hello 的纯函数逻辑，
 * 覆盖 SNI 提取、key_share 解析、版本解析、扩展解析和各类边界条件。
 * 同时使用 MockTransport 测试 read_tls_record 异步 I/O 路径。
 */

#include <prism/memory.hpp>
#include <prism/recognition/tls/signal.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>
#include <prism/transport/transmission.hpp>

#include <array>
#include <cstring>
#include <cstdint>
#include <span>
#include <vector>

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace fault = psm::fault;
    namespace net = boost::asio;
    void write_u16(std::vector<std::uint8_t> &buf, std::uint16_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    void write_u24(std::vector<std::uint8_t> &buf, std::size_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    struct hello_builder
    {
        std::string sni_value;
        bool include_x25519{true};
        std::array<std::uint8_t, 32> x25519_key{};
        bool include_versions{true};
        std::vector<std::uint16_t> extra_versions;
        std::uint8_t session_id_len{0};
        bool include_ech{false};
        bool include_extensions{true};

        hello_builder()
        {
            x25519_key.fill(0x42);
        }

        [[nodiscard]] auto build() const -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> body;
            body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

            std::vector<std::uint8_t> hs_body;
            hs_body.push_back(0x03);
            hs_body.push_back(0x03);
            hs_body.insert(hs_body.end(), 32, 0x00); // random

            hs_body.push_back(session_id_len);
            hs_body.insert(hs_body.end(), session_id_len, 0xAA);

            write_u16(hs_body, 2);
            write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);

            hs_body.push_back(1);
            hs_body.push_back(0x00);

            if (include_extensions)
            {
                std::vector<std::uint8_t> ext_data;

                if (!sni_value.empty())
                {
                    std::vector<std::uint8_t> sni_ext;
                    write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + sni_value.size()));
                    sni_ext.push_back(0x00);
                    write_u16(sni_ext, static_cast<std::uint16_t>(sni_value.size()));
                    sni_ext.insert(sni_ext.end(), sni_value.begin(), sni_value.end());
                    write_u16(ext_data, psm::protocol::tls::EXT_SERVER_NAME);
                    write_u16(ext_data, static_cast<std::uint16_t>(sni_ext.size()));
                    ext_data.insert(ext_data.end(), sni_ext.begin(), sni_ext.end());
                }

                if (include_x25519)
                {
                    std::vector<std::uint8_t> ks_ext;
                    write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + 32));
                    write_u16(ks_ext, psm::protocol::tls::GROUP_X25519);
                    write_u16(ks_ext, 32);
                    ks_ext.insert(ks_ext.end(), x25519_key.begin(), x25519_key.end());
                    write_u16(ext_data, psm::protocol::tls::EXT_KEY_SHARE);
                    write_u16(ext_data, static_cast<std::uint16_t>(ks_ext.size()));
                    ext_data.insert(ext_data.end(), ks_ext.begin(), ks_ext.end());
                }

                if (include_versions)
                {
                    std::vector<std::uint16_t> vers;
                    vers.push_back(psm::protocol::tls::VERSION_TLS13);
                    for (auto v : extra_versions)
                        vers.push_back(v);

                    std::vector<std::uint8_t> sv_ext;
                    sv_ext.push_back(static_cast<std::uint8_t>(vers.size() * 2));
                    for (auto v : vers)
                        write_u16(sv_ext, v);

                    write_u16(ext_data, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
                    write_u16(ext_data, static_cast<std::uint16_t>(sv_ext.size()));
                    ext_data.insert(ext_data.end(), sv_ext.begin(), sv_ext.end());
                }

                if (include_ech)
                {
                    write_u16(ext_data, psm::protocol::tls::EXT_ENCRYPTED_CLIENT_HELLO);
                    write_u16(ext_data, 4);
                    ext_data.push_back(0x00);
                    ext_data.push_back(0x01);
                    ext_data.push_back(0x00);
                    ext_data.push_back(0x02);
                }

                write_u16(hs_body, static_cast<std::uint16_t>(ext_data.size()));
                hs_body.insert(hs_body.end(), ext_data.begin(), ext_data.end());
            }

            write_u24(body, hs_body.size());
            body.insert(body.end(), hs_body.begin(), hs_body.end());

            std::vector<std::uint8_t> record;
            record.push_back(psm::protocol::tls::CT_HANDSHAKE);
            write_u16(record, 0x0303);
            write_u16(record, static_cast<std::uint16_t>(body.size()));
            record.insert(record.end(), body.begin(), body.end());
            return record;
        }
    };

    void TestParseValidHello(TestRunner &runner)
    {
        hello_builder builder;
        builder.sni_value = "example.com";
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "valid hello parses");
        runner.Check(feat.server_name == "example.com", "SNI extracted");
        runner.Check(feat.has_x25519 == true, "X25519 detected");
        runner.Check(!feat.versions.empty(), "versions not empty");
        runner.Check(feat.session_id.empty(), "session_id empty");
    }

    void TestParseWithSessionId(TestRunner &runner)
    {
        hello_builder builder;
        builder.sni_value = "sid.test";
        builder.session_id_len = 16;
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "hello with session_id parses");
        runner.Check(feat.session_id_len == 16, "session_id_len is 16");
        runner.Check(feat.session_id.size() == 16, "session_id size is 16");
    }

    void TestParseEchExtension(TestRunner &runner)
    {
        hello_builder builder;
        builder.sni_value = "ech.test";
        builder.include_ech = true;
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "hello with ECH parses");
        runner.Check(feat.has_ech == true, "ECH extension detected");
    }

    void TestParseNoExtensions(TestRunner &runner)
    {
        hello_builder builder;
        builder.include_extensions = false;
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "hello without extensions parses");
        runner.Check(feat.server_name.empty(), "no SNI");
        runner.Check(feat.has_x25519 == false, "no key_share");
        runner.Check(feat.versions.empty(), "no versions");
    }

    void TestParseRecordTooShort(TestRunner &runner)
    {
        std::vector<std::uint8_t> short_buf(10, 0x16);
        auto [ec, feat] = psm::recognition::tls::parse_client_hello(short_buf);
        runner.Check(psm::fault::failed(ec), "record < 44 bytes rejected");
    }

    void TestParseWrongContentType(TestRunner &runner)
    {
        hello_builder builder;
        auto raw = builder.build();
        raw[0] = 0x17;

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "wrong content type rejected");
    }

    void TestParseWrongHandshakeType(TestRunner &runner)
    {
        hello_builder builder;
        auto raw = builder.build();
        raw[5] = 0x02;

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "wrong handshake type rejected");
    }

    void TestParseSessionIdTooLong(TestRunner &runner)
    {
        hello_builder builder;
        builder.session_id_len = 33;
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "session_id > 32 rejected");
    }

    void TestParseMaxSessionId(TestRunner &runner)
    {
        hello_builder builder;
        builder.session_id_len = 32;
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "session_id = 32 accepted");
        runner.Check(feat.session_id_len == 32, "session_id_len is 32");
    }

    void TestParseRecordBodyTruncated(TestRunner &runner)
    {
        hello_builder builder;
        auto raw = builder.build();
        raw[3] = 0xFF;
        raw[4] = 0xFF;

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "truncated record body rejected");
    }

    void TestParseHandshakeTruncated(TestRunner &runner)
    {
        hello_builder builder;
        auto raw = builder.build();
        // Keep only first 10 bytes
        raw.resize(10);

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "truncated handshake rejected");
    }

    void TestParseCipherLenOdd(TestRunner &runner)
    {
        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(raw, 0x0303);

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03); hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 3); // odd cipher_len
        hs_body.push_back(0x13); hs_body.push_back(0x01); hs_body.push_back(0x00);
        hs_body.push_back(1); hs_body.push_back(0x00);

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::failed(ec), "odd cipher_suites length rejected");
    }

    void TestParseMultipleVersions(TestRunner &runner)
    {
        hello_builder builder;
        builder.extra_versions.push_back(psm::protocol::tls::VERSION_TLS12);
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "multiple versions parse");
        runner.Check(feat.versions.size() == 2, "two versions extracted");
    }

    void TestParseX25519Mlkem768(TestRunner &runner)
    {
        std::vector<std::uint8_t> ks_ext;
        const std::uint16_t hybrid_key_len = 1216;
        write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + hybrid_key_len));
        write_u16(ks_ext, psm::protocol::tls::GROUP_X25519_MLKEM768);
        write_u16(ks_ext, hybrid_key_len);
        for (std::size_t i = 0; i < 32; ++i)
            ks_ext.push_back(0x42);
        for (std::size_t i = 32; i < hybrid_key_len; ++i)
            ks_ext.push_back(0x00);

        std::vector<std::uint8_t> ext_block;
        write_u16(ext_block, psm::protocol::tls::EXT_KEY_SHARE);
        write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
        ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());

        std::vector<std::uint8_t> sv_ext;
        sv_ext.push_back(2);
        write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
        write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
        ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());

        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03); hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1); hs_body.push_back(0x00);
        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(record);
        runner.Check(psm::fault::succeeded(ec), "X25519MLKEM768 hybrid parses");
        runner.Check(feat.has_x25519 == true, "hybrid sets has_x25519");
    }

    void TestParseRawMsgPreserved(TestRunner &runner)
    {
        hello_builder builder;
        builder.sni_value = "raw.test";
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "parse for raw_msg test");
        runner.Check(!feat.raw_msg.empty(), "raw_msg preserved");
        runner.Check(!feat.raw_record.empty(), "raw_record preserved");
        runner.Check(feat.raw_msg.size() < feat.raw_record.size(), "raw_msg < raw_record");
    }

    void TestParseEmptySni(TestRunner &runner)
    {
        hello_builder builder;
        builder.sni_value = "";
        auto raw = builder.build();

        auto [ec, feat] = psm::recognition::tls::parse_client_hello(raw);
        runner.Check(psm::fault::succeeded(ec), "empty SNI hello parses");
        runner.Check(feat.server_name.empty(), "SNI is empty");
    }

    // === read_tls_record 异步 I/O 测试 ===

    /**
     * @brief 辅助函数：构造最小合法 Handshake TLS record
     */
    auto make_handshake_record(std::uint8_t hs_type = psm::protocol::tls::HS_CLIENT_HELLO)
        -> std::vector<std::byte>
    {
        std::vector<std::uint8_t> body;
        body.push_back(hs_type);
        // handshake body: version(2) + random(32) + session_id_len(1)
        std::vector<std::uint8_t> hs_body(35, 0x00);
        hs_body[0] = 0x03;
        hs_body[1] = 0x03;
        // cipher_suites(2) + compression(2)
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::byte> record;
        record.push_back(std::byte{psm::protocol::tls::CT_HANDSHAKE});
        record.push_back(std::byte{0x03});
        record.push_back(std::byte{0x03});
        record.push_back(std::byte{static_cast<std::uint8_t>((body.size() >> 8) & 0xFF)});
        record.push_back(std::byte{static_cast<std::uint8_t>(body.size() & 0xFF)});
        for (auto b : body)
            record.push_back(std::byte{b});
        return record;
    }

    /**
     * @brief 辅助：限时运行 io_context，防止挂起
     */
    void run_with_timeout(net::io_context &ioc, std::chrono::milliseconds timeout = std::chrono::milliseconds(500))
    {
        net::steady_timer timer(ioc);
        timer.expires_after(timeout);
        timer.async_wait([&](const boost::system::error_code &) { ioc.stop(); });
        ioc.run();
    }

    void TestReadTlsRecordFromTransport(TestRunner &runner)
    {
        auto wire = make_handshake_record();
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        fault::code result_ec = fault::code::success;
        psm::memory::vector<std::uint8_t> result_data;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(*mock);
                result_ec = ec;
                result_data = std::move(data);
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(psm::fault::succeeded(result_ec), "read_tls_record: success");
        runner.Check(result_data.size() == wire.size(), "read_tls_record: full record size");
        runner.Check(std::memcmp(result_data.data(), wire.data(),
                     (std::min)(result_data.size(), wire.size())) == 0,
                     "read_tls_record: data matches wire");
    }

    void TestReadTlsRecordNonHandshake(TestRunner &runner)
    {
        // 构造非 Handshake 记录（Application Data）
        std::vector<std::byte> wire = {
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03},
            std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        fault::code result_ec = fault::code::success;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(*mock);
                result_ec = ec;
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(result_ec == psm::fault::code::recorderr,
                     "read_tls_record: non-handshake → recorderr");
    }

    void TestReadTlsRecordError(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->set_read_error(std::make_error_code(std::errc::connection_reset));

        fault::code result_ec = fault::code::success;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(*mock);
                result_ec = ec;
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(psm::fault::failed(result_ec),
                     "read_tls_record: read error → failed");
    }

    void TestReadTlsRecordWithPrereadFull(TestRunner &runner)
    {
        // preread 包含完整的 TLS record → 零 I/O
        auto wire = make_handshake_record();
        std::span<const std::byte> preread(wire.data(), wire.size());

        auto mock = std::make_shared<psm::testing::MockTransport>();
        // 不注入任何数据 — preread 已包含全部

        fault::code result_ec = fault::code::success;
        psm::memory::vector<std::uint8_t> result_data;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(*mock, preread);
                result_ec = ec;
                result_data = std::move(data);
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(psm::fault::succeeded(result_ec), "preread full: success");
        runner.Check(result_data.size() == wire.size(), "preread full: correct size");
    }

    void TestReadTlsRecordWithPrereadPartial(TestRunner &runner)
    {
        // preread 仅包含 header (5 字节)，剩余部分从 transport 读
        auto wire = make_handshake_record();
        std::span<const std::byte> preread(wire.data(), 5);

        auto mock = std::make_shared<psm::testing::MockTransport>();
        // 注入剩余部分
        std::vector<std::byte> rest(wire.begin() + 5, wire.end());
        mock->inject_read(std::move(rest));

        fault::code result_ec = fault::code::success;
        psm::memory::vector<std::uint8_t> result_data;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(*mock, preread);
                result_ec = ec;
                result_data = std::move(data);
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(psm::fault::succeeded(result_ec), "preread partial: success");
        runner.Check(result_data.size() == wire.size(), "preread partial: correct size");
    }

    void TestReadTlsRecordPrereadTooShort(TestRunner &runner)
    {
        // preread < 5 字节 → 回退到无 preread 路径
        std::array<std::byte, 3> short_preread = {std::byte{0x16}, std::byte{0x03}, std::byte{0x03}};

        auto wire = make_handshake_record();
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        fault::code result_ec = fault::code::success;
        psm::memory::vector<std::uint8_t> result_data;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(
                    *mock, std::span<const std::byte>{short_preread.data(), short_preread.size()});
                result_ec = ec;
                result_data = std::move(data);
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(psm::fault::succeeded(result_ec), "preread too short: falls back to read");
    }

    void TestReadTlsRecordPrereadNonHandshake(TestRunner &runner)
    {
        // preread 中 content_type != 0x16 → recorderr
        std::array<std::byte, 5> non_hs_preread = {
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03},
            std::byte{0x00}, std::byte{0x04}};

        auto mock = std::make_shared<psm::testing::MockTransport>();

        fault::code result_ec = fault::code::success;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(
                    *mock, std::span<const std::byte>{non_hs_preread.data(), non_hs_preread.size()});
                result_ec = ec;
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(result_ec == psm::fault::code::recorderr,
                     "preread non-handshake: recorderr");
    }

    void TestReadTlsRecordPrereadOversized(TestRunner &runner)
    {
        // preread header 声称 length > MAX_RECORD_PAYLOAD → recorderr
        std::array<std::byte, 5> oversized_preread = {
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03},
            std::byte{0x40}, std::byte{0x01}}; // length=16385

        auto mock = std::make_shared<psm::testing::MockTransport>();

        fault::code result_ec = fault::code::success;

        net::co_spawn(mock->get_io_context(),
            [&]() -> net::awaitable<void>
            {
                auto [ec, data] = co_await psm::recognition::tls::read_tls_record(
                    *mock, std::span<const std::byte>{oversized_preread.data(), oversized_preread.size()});
                result_ec = ec;
            },
            net::detached);

        run_with_timeout(mock->get_io_context());

        runner.Check(result_ec == psm::fault::code::recorderr,
                     "preread oversized: recorderr");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TlsSignal");

    TestParseValidHello(runner);
    TestParseWithSessionId(runner);
    TestParseEchExtension(runner);
    TestParseNoExtensions(runner);
    TestParseRecordTooShort(runner);
    TestParseWrongContentType(runner);
    TestParseWrongHandshakeType(runner);
    TestParseSessionIdTooLong(runner);
    TestParseMaxSessionId(runner);
    TestParseRecordBodyTruncated(runner);
    TestParseHandshakeTruncated(runner);
    TestParseCipherLenOdd(runner);
    TestParseMultipleVersions(runner);
    TestParseX25519Mlkem768(runner);
    TestParseRawMsgPreserved(runner);
    TestParseEmptySni(runner);

    // === read_tls_record 异步 I/O 测试 ===
    TestReadTlsRecordFromTransport(runner);
    TestReadTlsRecordNonHandshake(runner);
    TestReadTlsRecordError(runner);
    TestReadTlsRecordWithPrereadFull(runner);
    TestReadTlsRecordWithPrereadPartial(runner);
    TestReadTlsRecordPrereadTooShort(runner);
    TestReadTlsRecordPrereadNonHandshake(runner);
    TestReadTlsRecordPrereadOversized(runner);

    return runner.Summary();
}
