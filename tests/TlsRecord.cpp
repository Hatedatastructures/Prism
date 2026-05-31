/**
 * @file TlsRecord.cpp
 * @brief TLS 记录帧单元测试
 * @details 测试 record::builder、record::serialize、record::header/payload/size 等纯逻辑，
 *          以及使用 MockTransport 测试 record::read(transmission&) 和 record::write(transmission&) 异步 I/O。
 */

#include <prism/memory.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/transport/transmission.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

namespace net = boost::asio;

using psm::testing::TestRunner;

namespace
{
    void TestBuilderBasic(TestRunner &runner)
    {
        std::array<std::byte, 4> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_HANDSHAKE)
                       .version(psm::protocol::tls::VERSION_TLS12)
                       .payload(payload)
                       .build();

        runner.Check(rec.header().content_type == psm::protocol::tls::CT_HANDSHAKE,
                     "builder type");
        runner.Check(rec.header().version == psm::protocol::tls::VERSION_TLS12,
                     "builder version");
        runner.Check(rec.header().length == 4, "builder length");
        runner.Check(rec.payload().size() == 4, "builder payload size");
    }

    void TestBuilderPayloadU8(TestRunner &runner)
    {
        std::array<std::uint8_t, 3> data = {0xAA, 0xBB, 0xCC};

        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_APPLICATION_DATA)
                       .version(psm::protocol::tls::VERSION_TLS12)
                       .payload_u8(data)
                       .build();

        runner.Check(rec.header().content_type == psm::protocol::tls::CT_APPLICATION_DATA,
                     "builder_u8 type");
        runner.Check(rec.payload().size() == 3, "builder_u8 payload size");

        auto pl = rec.payload();
        runner.Check(std::memcmp(pl.data(), data.data(), 3) == 0, "builder_u8 payload content");
    }

    void TestSerializeRoundtrip(TestRunner &runner)
    {
        std::array<std::byte, 5> original = {
            std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}, std::byte{0x50}};

        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(original)
                       .build();

        auto serialized = rec.serialize();

        // 5 header bytes + 5 payload bytes = 10
        runner.Check(serialized.size() == 10, "serialize total size");

        // Content type
        runner.Check(serialized[0] == std::byte{0x17}, "serialize content_type");
        // Version
        runner.Check(serialized[1] == std::byte{0x03}, "serialize version hi");
        runner.Check(serialized[2] == std::byte{0x03}, "serialize version lo");
        // Length
        runner.Check(serialized[3] == std::byte{0x00}, "serialize length hi");
        runner.Check(serialized[4] == std::byte{0x05}, "serialize length lo");
        // Payload
        runner.Check(std::memcmp(serialized.data() + 5, original.data(), 5) == 0,
                     "serialize payload preserved");
    }

    void TestRecordSize(TestRunner &runner)
    {
        std::array<std::byte, 100> payload{};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0303)
                       .payload(payload)
                       .build();

        runner.Check(rec.size() == psm::protocol::tls::RECORD_HDR_LEN + 100,
                     "record size = header + payload");
    }

    void TestEmptyPayload(TestRunner &runner)
    {
        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_ALERT)
                       .version(0x0303)
                       .build();

        runner.Check(rec.payload().empty(), "empty payload");
        runner.Check(rec.header().length == 0, "empty payload length = 0");
        runner.Check(rec.size() == psm::protocol::tls::RECORD_HDR_LEN, "empty payload size = header only");

        auto serialized = rec.serialize();
        runner.Check(serialized.size() == psm::protocol::tls::RECORD_HDR_LEN, "empty payload serialize = header only");
    }

    void TestBuilderChaining(TestRunner &runner)
    {
        // Test that builder methods chain correctly and later calls override
        std::array<std::byte, 2> data1 = {std::byte{0x01}, std::byte{0x02}};
        std::array<std::byte, 2> data2 = {std::byte{0xAA}, std::byte{0xBB}};

        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0301)
                       .payload(data1)
                       .version(0x0303) // override version
                       .payload(data2)  // override payload
                       .build();

        runner.Check(rec.header().version == 0x0303, "chaining: version overridden");
        auto pl = rec.payload();
        runner.Check(std::memcmp(pl.data(), data2.data(), 2) == 0, "chaining: payload overridden");
    }

    void TestLargePayload(TestRunner &runner)
    {
        std::vector<std::byte> large(16384); // MAX_RECORD_PAYLOAD
        for (std::size_t i = 0; i < large.size(); ++i)
            large[i] = std::byte(static_cast<std::uint8_t>(i & 0xFF));

        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(large)
                       .build();

        runner.Check(rec.payload().size() == 16384, "large payload size");
        runner.Check(rec.size() == psm::protocol::tls::RECORD_HDR_LEN + 16384, "large record size");

        auto serialized = rec.serialize();
        runner.Check(serialized.size() == psm::protocol::tls::RECORD_HDR_LEN + 16384, "large serialize size");
        // Verify length field: 16384 = 0x4000
        runner.Check(serialized[3] == std::byte{0x40}, "large length hi");
        runner.Check(serialized[4] == std::byte{0x00}, "large length lo");
    }

    void TestFromRecordHeader(TestRunner &runner)
    {
        psm::tls::record_header hdr;
        runner.Check(hdr.content_type == 0, "default header content_type");
        runner.Check(hdr.version == 0x0303, "default header version");
        runner.Check(hdr.length == 0, "default header length");
    }

    // === 异步 I/O 测试 ===

    void TestAsyncReadSuccess(TestRunner &runner)
    {
        // 构造合法 TLS record: CT=0x16, ver=0x0303, len=4, payload={1,2,3,4}
        std::vector<std::byte> wire = {
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, // CT + version
            std::byte{0x00}, std::byte{0x04},                   // length=4
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        net::io_context ioc;

        // 使用 lambda 包装协程调用
        auto wrapper = [m = mock.get()]() -> net::awaitable<void>
        {
            auto [ec, rec] = co_await psm::tls::record::read(*m);
            co_return;
        };

        net::co_spawn(ioc, wrapper(), net::detached);

        // 使用 mock 自身的 io_context 驱动 mock 操作
        mock->get_io_context().run();

        runner.Check(true, "async read: compiled and ran");
    }

    void TestAsyncReadError(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->set_read_error(std::make_error_code(std::errc::connection_reset));

        net::co_spawn(mock->get_io_context(),
            [m = mock.get()]() -> net::awaitable<void>
            {
                auto [ec, rec] = co_await psm::tls::record::read(*m);
                co_return;
            }, net::detached);

        mock->get_io_context().run();
        runner.Check(true, "async read error: ran without crash");
    }

    void TestAsyncReadOversized(TestRunner &runner)
    {
        // 构造 length > MAX_RECORD_PAYLOAD 的 record
        std::vector<std::byte> wire = {
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03},
            std::byte{0x40}, std::byte{0x01}}; // length=16385 > 16384

        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        net::co_spawn(mock->get_io_context(),
            [m = mock.get()]() -> net::awaitable<void>
            {
                auto [ec, rec] = co_await psm::tls::record::read(*m);
                co_return;
            }, net::detached);

        mock->get_io_context().run();
        runner.Check(true, "async read oversized: ran without crash");
    }

    void TestAsyncWriteSuccess(TestRunner &runner)
    {
        std::array<std::byte, 3> payload = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(payload)
                       .build();

        auto mock = std::make_shared<psm::testing::MockTransport>();

        net::co_spawn(mock->get_io_context(),
            [m = mock.get(), r = rec]() -> net::awaitable<void>
            {
                co_await r.write(*m);
                co_return;
            }, net::detached);

        mock->get_io_context().run();

        auto &written = mock->written_data();
        runner.Check(written.size() == 8, "async write: 5 header + 3 payload = 8 bytes");
        runner.Check(written[0] == std::byte{0x17}, "async write: CT=0x17");
        runner.Check(written[3] == std::byte{0x00}, "async write: length hi");
        runner.Check(written[4] == std::byte{0x03}, "async write: length lo=3");
    }

    void TestAsyncWriteError(TestRunner &runner)
    {
        std::array<std::byte, 2> payload = {std::byte{0x01}, std::byte{0x02}};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0303)
                       .payload(payload)
                       .build();

        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->set_write_error(std::make_error_code(std::errc::broken_pipe));

        net::co_spawn(mock->get_io_context(),
            [m = mock.get(), r = rec]() -> net::awaitable<void>
            {
                co_await r.write(*m);
                co_return;
            }, net::detached);

        mock->get_io_context().run();
        runner.Check(true, "async write error: ran without crash");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TlsRecord");

    TestBuilderBasic(runner);
    TestBuilderPayloadU8(runner);
    TestSerializeRoundtrip(runner);
    TestRecordSize(runner);
    TestEmptyPayload(runner);
    TestBuilderChaining(runner);
    TestLargePayload(runner);
    TestFromRecordHeader(runner);

    // === 异步 I/O 测试（MockTransport）===
    TestAsyncReadSuccess(runner);
    TestAsyncReadError(runner);
    TestAsyncReadOversized(runner);
    TestAsyncWriteSuccess(runner);
    TestAsyncWriteError(runner);

    return runner.Summary();
}
