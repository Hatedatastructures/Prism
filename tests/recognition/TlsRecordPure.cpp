/**
 * @file TlsRecordPure.cpp
 * @brief TLS record 序列化/构建器纯函数测试
 * @details 测试 record::serialize/builder 全部方法/getter
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/tls/record.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(TlsRecordPure, BuilderBasic)
    {
        std::array<std::byte, 4> data = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0303)
                       .payload(data)
                       .build();

        EXPECT_TRUE(rec.header().content_type == 0x16) << "builder: type=0x16";
        EXPECT_TRUE(rec.header().version == 0x0303) << "builder: version=0x0303";
        EXPECT_TRUE(rec.header().length == 4) << "builder: length=4";
        EXPECT_TRUE(rec.payload().size() == 4) << "builder: payload size=4";
    }

    TEST(TlsRecordPure, BuilderPayloadU8)
    {
        std::array<std::uint8_t, 3> data = {0xAA, 0xBB, 0xCC};
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0301)
                       .payload_u8(data)
                       .build();

        EXPECT_TRUE(rec.header().length == 3) << "builder_u8: length=3";
        EXPECT_TRUE(rec.payload().size() == 3) << "builder_u8: payload size=3";
        EXPECT_TRUE(rec.payload()[0] == std::byte{0xAA}) << "builder_u8: byte[0]";
        EXPECT_TRUE(rec.payload()[2] == std::byte{0xCC}) << "builder_u8: byte[2]";
    }

    TEST(TlsRecordPure, BuilderEmptyPayload)
    {
        auto rec = psm::tls::record::builder()
                       .type(0x14)
                       .version(0x0303)
                       .build();

        EXPECT_TRUE(rec.header().length == 0) << "builder empty: length=0";
        EXPECT_TRUE(rec.payload().empty()) << "builder empty: no payload";
        EXPECT_TRUE(rec.size() == psm::protocol::tls::RECORD_HDR_LEN) << "builder empty: size=5";
    }

    TEST(TlsRecordPure, SerializeRoundtrip)
    {
        std::array<std::byte, 2> data = {std::byte{0xDE}, std::byte{0xAD}};
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(data)
                       .build();

        auto bytes = rec.serialize();
        // Header: type(1) + version(2) + length(2) + payload(2) = 7
        EXPECT_TRUE(bytes.size() == 7) << "serialize: total size=7";
        EXPECT_TRUE(bytes[0] == std::byte{0x17}) << "serialize: type byte";
        EXPECT_TRUE(bytes[1] == std::byte{0x03}) << "serialize: version hi";
        EXPECT_TRUE(bytes[2] == std::byte{0x03}) << "serialize: version lo";
        EXPECT_TRUE(bytes[3] == std::byte{0x00}) << "serialize: length hi";
        EXPECT_TRUE(bytes[4] == std::byte{0x02}) << "serialize: length lo";
        EXPECT_TRUE(bytes[5] == std::byte{0xDE}) << "serialize: payload[0]";
        EXPECT_TRUE(bytes[6] == std::byte{0xAD}) << "serialize: payload[1]";
    }

    TEST(TlsRecordPure, RecordSizeCalc)
    {
        std::array<std::byte, 10> data{};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .payload(data)
                       .build();

        EXPECT_TRUE(rec.size() == 15) << "record size: 5+10=15";
    }

    TEST(TlsRecordPure, BuilderChaining)
    {
        std::array<std::byte, 1> data = {std::byte{0xFF}};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0301)
                       .payload(data)
                       .build();
        EXPECT_TRUE(rec.header().content_type == 0x16) << "chain: type preserved";
        EXPECT_TRUE(rec.header().version == 0x0301) << "chain: version preserved";
        EXPECT_TRUE(rec.header().length == 1) << "chain: length=1";
    }
} // namespace
