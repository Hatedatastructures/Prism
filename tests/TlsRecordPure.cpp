/**
 * @file TlsRecordPure.cpp
 * @brief TLS record 序列化/构建器纯函数测试
 * @details 测试 record::serialize/builder 全部方法/getter
 */

#include <prism/memory.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestBuilderBasic(TestRunner &runner)
    {
        std::array<std::byte, 4> data = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0303)
                       .payload(data)
                       .build();

        runner.Check(rec.header().content_type == 0x16, "builder: type=0x16");
        runner.Check(rec.header().version == 0x0303, "builder: version=0x0303");
        runner.Check(rec.header().length == 4, "builder: length=4");
        runner.Check(rec.payload().size() == 4, "builder: payload size=4");
    }

    void TestBuilderPayloadU8(TestRunner &runner)
    {
        std::array<std::uint8_t, 3> data = {0xAA, 0xBB, 0xCC};
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0301)
                       .payload_u8(data)
                       .build();

        runner.Check(rec.header().length == 3, "builder_u8: length=3");
        runner.Check(rec.payload().size() == 3, "builder_u8: payload size=3");
        runner.Check(rec.payload()[0] == std::byte{0xAA}, "builder_u8: byte[0]");
        runner.Check(rec.payload()[2] == std::byte{0xCC}, "builder_u8: byte[2]");
    }

    void TestBuilderEmptyPayload(TestRunner &runner)
    {
        auto rec = psm::tls::record::builder()
                       .type(0x14)
                       .version(0x0303)
                       .build();

        runner.Check(rec.header().length == 0, "builder empty: length=0");
        runner.Check(rec.payload().empty(), "builder empty: no payload");
        runner.Check(rec.size() == psm::protocol::tls::RECORD_HDR_LEN, "builder empty: size=5");
    }

    void TestSerializeRoundtrip(TestRunner &runner)
    {
        std::array<std::byte, 2> data = {std::byte{0xDE}, std::byte{0xAD}};
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(data)
                       .build();

        auto bytes = rec.serialize();
        // Header: type(1) + version(2) + length(2) + payload(2) = 7
        runner.Check(bytes.size() == 7, "serialize: total size=7");
        runner.Check(bytes[0] == std::byte{0x17}, "serialize: type byte");
        runner.Check(bytes[1] == std::byte{0x03}, "serialize: version hi");
        runner.Check(bytes[2] == std::byte{0x03}, "serialize: version lo");
        runner.Check(bytes[3] == std::byte{0x00}, "serialize: length hi");
        runner.Check(bytes[4] == std::byte{0x02}, "serialize: length lo");
        runner.Check(bytes[5] == std::byte{0xDE}, "serialize: payload[0]");
        runner.Check(bytes[6] == std::byte{0xAD}, "serialize: payload[1]");
    }

    void TestRecordSizeCalc(TestRunner &runner)
    {
        std::array<std::byte, 10> data{};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .payload(data)
                       .build();

        runner.Check(rec.size() == 15, "record size: 5+10=15");
    }

    void TestBuilderChaining(TestRunner &runner)
    {
        std::array<std::byte, 1> data = {std::byte{0xFF}};
        auto rec = psm::tls::record::builder()
                       .type(0x16)
                       .version(0x0301)
                       .payload(data)
                       .build();
        runner.Check(rec.header().content_type == 0x16, "chain: type preserved");
        runner.Check(rec.header().version == 0x0301, "chain: version preserved");
        runner.Check(rec.header().length == 1, "chain: length=1");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TlsRecordPure");

    TestBuilderBasic(runner);
    TestBuilderPayloadU8(runner);
    TestBuilderEmptyPayload(runner);
    TestSerializeRoundtrip(runner);
    TestRecordSizeCalc(runner);
    TestBuilderChaining(runner);

    return runner.Summary();
}
