/**
 * @file TlsRecord.cpp
 * @brief TLS 记录帧单元测试
 * @details 测试 record::builder、record::serialize、record::header/payload/size 等纯逻辑，
 *          以及使用 MockTransport 测试 record::read(transmission&) 和 record::write(transmission&) 异步 I/O。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/tls/record.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/net/transport/transmission.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

#include <gtest/gtest.h>
#include "common/MockTransport.hpp"

namespace net = boost::asio;

namespace
{
    TEST(TlsRecord, BuilderBasic)
    {
        std::array<std::byte, 4> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_HANDSHAKE)
                       .version(psm::protocol::tls::VERSION_TLS12)
                       .payload(payload)
                       .build();

        EXPECT_TRUE(rec.header().content_type == psm::protocol::tls::CT_HANDSHAKE)
            << "builder type";
        EXPECT_TRUE(rec.header().version == psm::protocol::tls::VERSION_TLS12)
            << "builder version";
        EXPECT_TRUE(rec.header().length == 4) << "builder length";
        EXPECT_TRUE(rec.payload().size() == 4) << "builder payload size";
    }

    TEST(TlsRecord, BuilderPayloadU8)
    {
        std::array<std::uint8_t, 3> data = {0xAA, 0xBB, 0xCC};

        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_APPLICATION_DATA)
                       .version(psm::protocol::tls::VERSION_TLS12)
                       .payload_u8(data)
                       .build();

        EXPECT_TRUE(rec.header().content_type == psm::protocol::tls::CT_APPLICATION_DATA)
            << "builder_u8 type";
        EXPECT_TRUE(rec.payload().size() == 3) << "builder_u8 payload size";

        auto pl = rec.payload();
        EXPECT_TRUE(std::memcmp(pl.data(), data.data(), 3) == 0) << "builder_u8 payload content";
    }

    TEST(TlsRecord, SerializeRoundtrip)
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
        EXPECT_TRUE(serialized.size() == 10) << "serialize total size";

        // Content type
        EXPECT_TRUE(serialized[0] == std::byte{0x17}) << "serialize content_type";
        // Version
        EXPECT_TRUE(serialized[1] == std::byte{0x03}) << "serialize version hi";
        EXPECT_TRUE(serialized[2] == std::byte{0x03}) << "serialize version lo";
        // Length
        EXPECT_TRUE(serialized[3] == std::byte{0x00}) << "serialize length hi";
        EXPECT_TRUE(serialized[4] == std::byte{0x05}) << "serialize length lo";
        // Payload
        EXPECT_TRUE(std::memcmp(serialized.data() + 5, original.data(), 5) == 0)
            << "serialize payload preserved";
    }

    TEST(TlsRecord, RecordSize)
    {
        std::array<std::byte, 100> payload{};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0303)
                       .payload(payload)
                       .build();

        EXPECT_TRUE(rec.size() == psm::protocol::tls::RECORD_HDR_LEN + 100)
            << "record size = header + payload";
    }

    TEST(TlsRecord, EmptyPayload)
    {
        auto rec = psm::tls::record::builder()
                       .type(psm::protocol::tls::CT_ALERT)
                       .version(0x0303)
                       .build();

        EXPECT_TRUE(rec.payload().empty()) << "empty payload";
        EXPECT_TRUE(rec.header().length == 0) << "empty payload length = 0";
        EXPECT_TRUE(rec.size() == psm::protocol::tls::RECORD_HDR_LEN) << "empty payload size = header only";

        auto serialized = rec.serialize();
        EXPECT_TRUE(serialized.size() == psm::protocol::tls::RECORD_HDR_LEN) << "empty payload serialize = header only";
    }

    TEST(TlsRecord, BuilderChaining)
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

        EXPECT_TRUE(rec.header().version == 0x0303) << "chaining: version overridden";
        auto pl = rec.payload();
        EXPECT_TRUE(std::memcmp(pl.data(), data2.data(), 2) == 0) << "chaining: payload overridden";
    }

    TEST(TlsRecord, LargePayload)
    {
        std::vector<std::byte> large(16384); // MAX_RECORD_PAYLOAD
        for (std::size_t i = 0; i < large.size(); ++i)
            large[i] = std::byte(static_cast<std::uint8_t>(i & 0xFF));

        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(large)
                       .build();

        EXPECT_TRUE(rec.payload().size() == 16384) << "large payload size";
        EXPECT_TRUE(rec.size() == psm::protocol::tls::RECORD_HDR_LEN + 16384) << "large record size";

        auto serialized = rec.serialize();
        EXPECT_TRUE(serialized.size() == psm::protocol::tls::RECORD_HDR_LEN + 16384) << "large serialize size";
        // Verify length field: 16384 = 0x4000
        EXPECT_TRUE(serialized[3] == std::byte{0x40}) << "large length hi";
        EXPECT_TRUE(serialized[4] == std::byte{0x00}) << "large length lo";
    }

    TEST(TlsRecord, FromRecordHeader)
    {
        psm::tls::record_header hdr;
        EXPECT_TRUE(hdr.content_type == 0) << "default header content_type";
        EXPECT_TRUE(hdr.version == 0x0303) << "default header version";
        EXPECT_TRUE(hdr.length == 0) << "default header length";
    }

    // === 异步 I/O 测试 ===

    TEST(TlsRecord, AsyncReadSuccess)
    {
        // 构造合法 TLS record: CT=0x16, ver=0x0303, len=4, payload={1,2,3,4}
        std::vector<std::byte> wire = {
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, // CT + version
            std::byte{0x00}, std::byte{0x04},                   // length=4
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        auto result_rec = std::make_shared<psm::tls::record>();
        auto result_ec = std::make_shared<std::error_code>();

        net::co_spawn(mock->get_io_context(),
            [m = mock.get(), result_rec, result_ec]() -> net::awaitable<void>
            {
                auto [ec, rec] = co_await psm::tls::record::read(*m);
                *result_ec = ec;
                *result_rec = std::move(rec);
                co_return;
            }, net::detached);

        mock->get_io_context().run();

        EXPECT_TRUE(!*result_ec) << "async read: success without error";
        EXPECT_TRUE(result_rec->header().content_type == 0x16)
            << "async read: content type matches";
    }

    TEST(TlsRecord, AsyncReadError)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->set_read_error(std::make_error_code(std::errc::connection_reset));

        auto result_ec = std::make_shared<psm::fault::code>();

        net::co_spawn(mock->get_io_context(),
            [m = mock.get(), result_ec]() -> net::awaitable<void>
            {
                auto [ec, rec] = co_await psm::tls::record::read(*m);
                *result_ec = ec;
                co_return;
            }, net::detached);

        mock->get_io_context().run();
        EXPECT_TRUE(*result_ec == psm::fault::code::io_error)
            << "async read error: returns io_error on read failure";
    }

    TEST(TlsRecord, AsyncReadOversized)
    {
        // 构造 length > MAX_RECORD_PAYLOAD 的 record
        std::vector<std::byte> wire = {
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03},
            std::byte{0x40}, std::byte{0x01}}; // length=16385 > 16384

        auto mock = std::make_shared<psm::testing::MockTransport>();
        mock->inject_read(wire);

        auto result_ec = std::make_shared<std::error_code>();

        net::co_spawn(mock->get_io_context(),
            [m = mock.get(), result_ec]() -> net::awaitable<void>
            {
                auto [ec, rec] = co_await psm::tls::record::read(*m);
                *result_ec = ec;
                co_return;
            }, net::detached);

        mock->get_io_context().run();
        EXPECT_TRUE(!!*result_ec) << "async read oversized: error code set for oversized record";
    }

    TEST(TlsRecord, AsyncWriteSuccess)
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
        EXPECT_TRUE(written.size() == 8) << "async write: 5 header + 3 payload = 8 bytes";
        EXPECT_TRUE(written[0] == std::byte{0x17}) << "async write: CT=0x17";
        EXPECT_TRUE(written[3] == std::byte{0x00}) << "async write: length hi";
        EXPECT_TRUE(written[4] == std::byte{0x03}) << "async write: length lo=3";
    }

    TEST(TlsRecord, AsyncWriteError)
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
        EXPECT_TRUE(mock->written_data().empty())
            << "async write error: no data written on write failure";
    }

} // namespace
