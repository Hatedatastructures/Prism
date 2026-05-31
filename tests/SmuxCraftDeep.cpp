/**
 * @file SmuxCraftDeep.cpp
 * @brief smux craft 深度纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 build_header，
 *          以及公开的 make_data_frame、make_syn、make_fin。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/multiplex/smux/craft.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace smux = psm::multiplex::smux;

    // ─── build_header ──────────────────────────

    void TestBuildHeaderPush(TestRunner &runner)
    {
        auto hdr = psm::multiplex::smux::build_header(smux::command::push, 1, 4);
        runner.Check(hdr.size() == smux::frame_hdrsize, "build_header: size=8");
        runner.Check(hdr[0] == std::byte{smux::protocol_version}, "build_header: version");
        runner.Check(hdr[1] == std::byte{0x02}, "build_header: push cmd=2");
        // length=4, LE
        runner.Check(hdr[2] == std::byte{0x04}, "build_header: length low");
        runner.Check(hdr[3] == std::byte{0x00}, "build_header: length high");
        // stream_id=1, LE
        runner.Check(hdr[4] == std::byte{0x01}, "build_header: stream_id byte0");
        runner.Check(hdr[5] == std::byte{0x00}, "build_header: stream_id byte1");
        runner.Check(hdr[6] == std::byte{0x00}, "build_header: stream_id byte2");
        runner.Check(hdr[7] == std::byte{0x00}, "build_header: stream_id byte3");
    }

    void TestBuildHeaderSyn(TestRunner &runner)
    {
        auto hdr = psm::multiplex::smux::build_header(smux::command::syn, 42, 0);
        runner.Check(hdr[1] == std::byte{0x00}, "build_header: syn cmd=0");
        // length=0
        runner.Check(hdr[2] == std::byte{0x00}, "build_header: syn length low");
        runner.Check(hdr[3] == std::byte{0x00}, "build_header: syn length high");
        // stream_id=42, LE
        runner.Check(hdr[4] == std::byte{42}, "build_header: syn stream_id byte0");
    }

    void TestBuildHeaderFin(TestRunner &runner)
    {
        auto hdr = psm::multiplex::smux::build_header(smux::command::fin, 7, 0);
        runner.Check(hdr[1] == std::byte{0x01}, "build_header: fin cmd=1");
        runner.Check(hdr[4] == std::byte{0x07}, "build_header: fin stream_id=7");
    }

    void TestBuildHeaderNop(TestRunner &runner)
    {
        auto hdr = psm::multiplex::smux::build_header(smux::command::nop, 0, 0);
        runner.Check(hdr[1] == std::byte{0x03}, "build_header: nop cmd=3");
    }

    void TestBuildHeaderLargeLength(TestRunner &runner)
    {
        constexpr std::uint16_t len = 0xABCD;
        auto hdr = psm::multiplex::smux::build_header(smux::command::push, 1, len);
        runner.Check(hdr[2] == std::byte{0xCD}, "build_header: large length low");
        runner.Check(hdr[3] == std::byte{0xAB}, "build_header: large length high");
    }

    void TestBuildHeaderLargeStreamId(TestRunner &runner)
    {
        constexpr std::uint32_t sid = 0x12345678;
        auto hdr = psm::multiplex::smux::build_header(smux::command::push, sid, 0);
        runner.Check(hdr[4] == std::byte{0x78}, "build_header: stream_id byte0");
        runner.Check(hdr[5] == std::byte{0x56}, "build_header: stream_id byte1");
        runner.Check(hdr[6] == std::byte{0x34}, "build_header: stream_id byte2");
        runner.Check(hdr[7] == std::byte{0x12}, "build_header: stream_id byte3");
    }

    // ─── make_data_frame ────────────────────────

    void TestMakeDataFrameBasic(TestRunner &runner)
    {
        const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        auto frame = smux::make_data_frame(5, payload);
        runner.Check(frame.size() == smux::frame_hdrsize + 3, "make_data_frame: header+payload");
        // 检查 header 部分是 push 帧
        runner.Check(frame[0] == std::byte{smux::protocol_version}, "make_data_frame: version");
        runner.Check(frame[1] == std::byte{0x02}, "make_data_frame: push cmd");
        runner.Check(frame[2] == std::byte{0x03}, "make_data_frame: length=3 low");
        runner.Check(frame[3] == std::byte{0x00}, "make_data_frame: length=3 high");
        // stream_id=5, LE
        runner.Check(frame[4] == std::byte{0x05}, "make_data_frame: stream_id=5");
        // payload
        runner.Check(frame[8] == std::byte{0xAA}, "make_data_frame: payload[0]");
        runner.Check(frame[9] == std::byte{0xBB}, "make_data_frame: payload[1]");
        runner.Check(frame[10] == std::byte{0xCC}, "make_data_frame: payload[2]");
    }

    void TestMakeDataFrameEmpty(TestRunner &runner)
    {
        std::span<const std::byte> empty;
        auto frame = smux::make_data_frame(1, empty);
        runner.Check(frame.size() == smux::frame_hdrsize, "make_data_frame: empty payload -> header only");
    }

    void TestMakeDataFrameLargeStreamId(TestRunner &runner)
    {
        const std::byte payload[] = {std::byte{0xFF}};
        auto frame = smux::make_data_frame(0xDEAD, payload);
        runner.Check(frame[4] == std::byte{0xAD}, "make_data_frame: large stream_id low");
        runner.Check(frame[5] == std::byte{0xDE}, "make_data_frame: large stream_id high");
    }

    // ─── make_syn ────────────────────────────────

    void TestMakeSynBasic(TestRunner &runner)
    {
        auto hdr = smux::make_syn(1);
        runner.Check(hdr.size() == smux::frame_hdrsize, "make_syn: size=8");
        runner.Check(hdr[0] == std::byte{smux::protocol_version}, "make_syn: version");
        runner.Check(hdr[1] == std::byte{0x00}, "make_syn: syn cmd=0");
        // length=0
        runner.Check(hdr[2] == std::byte{0x00}, "make_syn: length low");
        runner.Check(hdr[3] == std::byte{0x00}, "make_syn: length high");
        // stream_id=1, LE
        runner.Check(hdr[4] == std::byte{0x01}, "make_syn: stream_id=1");
    }

    void TestMakeSynZeroStreamId(TestRunner &runner)
    {
        auto hdr = smux::make_syn(0);
        runner.Check(hdr[4] == std::byte{0x00}, "make_syn: zero stream_id");
        runner.Check(hdr[5] == std::byte{0x00}, "make_syn: zero stream_id byte1");
    }

    // ─── make_fin ────────────────────────────────

    void TestMakeFinBasic(TestRunner &runner)
    {
        auto hdr = smux::make_fin(3);
        runner.Check(hdr.size() == smux::frame_hdrsize, "make_fin: size=8");
        runner.Check(hdr[1] == std::byte{0x01}, "make_fin: fin cmd=1");
        runner.Check(hdr[2] == std::byte{0x00}, "make_fin: length=0");
        runner.Check(hdr[4] == std::byte{0x03}, "make_fin: stream_id=3");
    }

    void TestMakeFinMaxStreamId(TestRunner &runner)
    {
        auto hdr = smux::make_fin(0xFFFFFFFF);
        runner.Check(hdr[4] == std::byte{0xFF}, "make_fin: max stream_id byte0");
        runner.Check(hdr[5] == std::byte{0xFF}, "make_fin: max stream_id byte1");
        runner.Check(hdr[6] == std::byte{0xFF}, "make_fin: max stream_id byte2");
        runner.Check(hdr[7] == std::byte{0xFF}, "make_fin: max stream_id byte3");
    }

    // ─── log_spawn_error ────────────────────────

    void TestLogSpawnErrorException(TestRunner &runner)
    {
        try
        {
            throw std::runtime_error("test error");
        }
        catch (...)
        {
            auto ep = std::current_exception();
            // 不崩溃即可
            psm::multiplex::smux::log_spawn_error(ep, 42, "test_label");
            runner.Check(true, "log_spawn_error: std::exception no crash");
        }
    }

    void TestLogSpawnErrorUnknown(TestRunner &runner)
    {
        try
        {
            throw 42;
        }
        catch (...)
        {
            auto ep = std::current_exception();
            psm::multiplex::smux::log_spawn_error(ep, 1, "unknown");
            runner.Check(true, "log_spawn_error: unknown exception no crash");
        }
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("SmuxCraftDeep");

    TestBuildHeaderPush(runner);
    TestBuildHeaderSyn(runner);
    TestBuildHeaderFin(runner);
    TestBuildHeaderNop(runner);
    TestBuildHeaderLargeLength(runner);
    TestBuildHeaderLargeStreamId(runner);

    TestMakeDataFrameBasic(runner);
    TestMakeDataFrameEmpty(runner);
    TestMakeDataFrameLargeStreamId(runner);

    TestMakeSynBasic(runner);
    TestMakeSynZeroStreamId(runner);

    TestMakeFinBasic(runner);
    TestMakeFinMaxStreamId(runner);

    TestLogSpawnErrorException(runner);
    TestLogSpawnErrorUnknown(runner);

    return runner.Summary();
}
