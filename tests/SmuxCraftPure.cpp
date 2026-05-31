/**
 * @file SmuxCraftPure.cpp
 * @brief smux craft 纯函数单元测试
 * @details 测试 make_data_frame、make_syn、make_fin 帧构建函数，
 *          以及 build_header 的字节序正确性。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/smux/frame.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace smux = psm::multiplex::smux;

    // ─── make_syn ──────────────────────────────────

    void TestMakeSyn(TestRunner &runner)
    {
        auto syn = smux::make_syn(42);
        runner.Check(syn.size() == 8, "make_syn: size=8");
        runner.Check(syn[0] == std::byte{smux::protocol_version},
                     "make_syn: version byte");
        runner.Check(syn[1] == static_cast<std::byte>(smux::command::syn),
                     "make_syn: cmd=syn");
        // length=0 → LE
        runner.Check(syn[2] == std::byte{0}, "make_syn: length LSB=0");
        runner.Check(syn[3] == std::byte{0}, "make_syn: length MSB=0");
        // stream_id=42 LE
        runner.Check(syn[4] == std::byte{42}, "make_syn: stream_id byte 0");
        runner.Check(syn[5] == std::byte{0}, "make_syn: stream_id byte 1");
        runner.Check(syn[6] == std::byte{0}, "make_syn: stream_id byte 2");
        runner.Check(syn[7] == std::byte{0}, "make_syn: stream_id byte 3");
    }

    // ─── make_fin ──────────────────────────────────

    void TestMakeFin(TestRunner &runner)
    {
        auto fin = smux::make_fin(7);
        runner.Check(fin.size() == 8, "make_fin: size=8");
        runner.Check(fin[1] == static_cast<std::byte>(smux::command::fin),
                     "make_fin: cmd=fin");
        runner.Check(fin[4] == std::byte{7}, "make_fin: stream_id=7");
    }

    // ─── make_data_frame ───────────────────────────

    void TestMakeDataFrame(TestRunner &runner)
    {
        psm::memory::vector<std::byte> payload;
        payload.push_back(std::byte{0x01});
        payload.push_back(std::byte{0x02});
        payload.push_back(std::byte{0x03});

        auto frame = smux::make_data_frame(100, payload);

        runner.Check(frame.size() == 8 + 3, "make_data: total size=11");
        runner.Check(frame[1] == static_cast<std::byte>(smux::command::push),
                     "make_data: cmd=push");
        // length=3 LE
        runner.Check(frame[2] == std::byte{3}, "make_data: length LSB=3");
        runner.Check(frame[3] == std::byte{0}, "make_data: length MSB=0");
        // stream_id=100 LE
        runner.Check(frame[4] == std::byte{100}, "make_data: stream_id byte 0");
        // payload follows
        runner.Check(frame[8] == std::byte{0x01}, "make_data: payload[0]");
        runner.Check(frame[9] == std::byte{0x02}, "make_data: payload[1]");
        runner.Check(frame[10] == std::byte{0x03}, "make_data: payload[2]");
    }

    void TestMakeDataFrameEmpty(TestRunner &runner)
    {
        psm::memory::vector<std::byte> payload;
        auto frame = smux::make_data_frame(0, payload);
        runner.Check(frame.size() == 8, "make_data empty: header only");
    }

    // ─── stream_id 字节序（大 ID） ─────────────────

    void TestMakeSynLargeStreamId(TestRunner &runner)
    {
        auto syn = smux::make_syn(0x01020304);
        runner.Check(syn[4] == std::byte{0x04}, "syn: stream_id LE byte 0");
        runner.Check(syn[5] == std::byte{0x03}, "syn: stream_id LE byte 1");
        runner.Check(syn[6] == std::byte{0x02}, "syn: stream_id LE byte 2");
        runner.Check(syn[7] == std::byte{0x01}, "syn: stream_id LE byte 3");
    }

    // ─── frame deserialization roundtrip ────────────

    void TestFrameRoundtrip(TestRunner &runner)
    {
        // Construct a SYN frame and deserialize it
        auto syn = smux::make_syn(1234);
        auto hdr = smux::deserialization(syn);
        runner.Check(hdr.has_value(), "roundtrip: deserialization success");
        runner.Check(hdr->cmd == smux::command::syn, "roundtrip: cmd=syn");
        runner.Check(hdr->stream_id == 1234, "roundtrip: stream_id=1234");
        runner.Check(hdr->length == 0, "roundtrip: length=0");
    }

    void TestDataFrameRoundtrip(TestRunner &runner)
    {
        psm::memory::vector<std::byte> payload;
        for (int i = 0; i < 100; ++i)
            payload.push_back(std::byte{static_cast<unsigned char>(i)});

        auto frame = smux::make_data_frame(5678, payload);

        // Deserialize header only (first 8 bytes)
        std::array<std::byte, 8> hdr_bytes;
        std::memcpy(hdr_bytes.data(), frame.data(), 8);
        auto hdr = smux::deserialization(hdr_bytes);
        runner.Check(hdr.has_value(), "data roundtrip: deserialization success");
        runner.Check(hdr->cmd == smux::command::push, "data roundtrip: cmd=push");
        runner.Check(hdr->stream_id == 5678, "data roundtrip: stream_id=5678");
        runner.Check(hdr->length == 100, "data roundtrip: length=100");

        // Verify payload matches
        bool payload_match = true;
        for (int i = 0; i < 100; ++i)
        {
            if (frame[8 + i] != std::byte{static_cast<unsigned char>(i)})
            {
                payload_match = false;
                break;
            }
        }
        runner.Check(payload_match, "data roundtrip: payload matches");
    }

    // ─── make_fin roundtrip ────────────────────────

    void TestFinRoundtrip(TestRunner &runner)
    {
        auto fin = smux::make_fin(0xFFFFFFFF);
        auto hdr = smux::deserialization(fin);
        runner.Check(hdr.has_value(), "fin roundtrip: success");
        runner.Check(hdr->cmd == smux::command::fin, "fin roundtrip: cmd=fin");
        runner.Check(hdr->stream_id == 0xFFFFFFFF, "fin roundtrip: max stream_id");
    }

} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("SmuxCraftPure");

    TestMakeSyn(runner);
    TestMakeFin(runner);
    TestMakeDataFrame(runner);
    TestMakeDataFrameEmpty(runner);
    TestMakeSynLargeStreamId(runner);
    TestFrameRoundtrip(runner);
    TestDataFrameRoundtrip(runner);
    TestFinRoundtrip(runner);

    return runner.Summary();
}
