/**
 * @file YamuxFrameError.cpp
 * @brief yamux 帧格式错误路径与往返测试
 */

#include <prism/memory.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::multiplex::yamux;

    void TestParseHeaderTooShort(TestRunner &runner)
    {
        std::array<std::byte, 6> short_buf{};
        auto result = parse_header(short_buf);
        runner.Check(!result.has_value(), "parse_header: too short -> nullopt");
    }

    void TestParseHeaderBadVersion(TestRunner &runner)
    {
        std::array<std::byte, frame_hdrsize> buf{};
        buf[0] = std::byte{0x99};
        auto result = parse_header(buf);
        runner.Check(!result.has_value(), "parse_header: bad version -> nullopt");
    }

    void TestParseHeaderBadType(TestRunner &runner)
    {
        std::array<std::byte, frame_hdrsize> buf{};
        buf[0] = std::byte{protocol_version};
        buf[1] = std::byte{0xFF};
        auto result = parse_header(buf);
        runner.Check(!result.has_value(), "parse_header: bad type -> nullopt");
    }

    void TestRoundtripDataSyn(TestRunner &runner)
    {
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}};
        auto frame = build_syn(1, data);

        auto parsed = parse_header(frame.header);
        runner.Check(parsed.has_value(), "roundtrip syn: parsed");
        runner.Check(parsed->type == message_type::data, "roundtrip syn: type=data");
        runner.Check(static_cast<int>(parsed->flag) == static_cast<int>(flags::syn),
                     "roundtrip syn: flag=syn");
        runner.Check(parsed->stream_id == 1, "roundtrip syn: stream_id=1");
    }

    void TestRoundtripFin(TestRunner &runner)
    {
        auto buf = build_fin(42);
        auto parsed = parse_header(buf);
        runner.Check(parsed.has_value(), "roundtrip fin: parsed");
        runner.Check(parsed->type == message_type::data, "roundtrip fin: type=data");
        runner.Check(static_cast<int>(parsed->flag) == static_cast<int>(flags::fin),
                     "roundtrip fin: flag=fin");
        runner.Check(parsed->stream_id == 42, "roundtrip fin: stream_id=42");
        runner.Check(parsed->length == 0, "roundtrip fin: length=0");
    }

    void TestRoundtripWindowUpdate(TestRunner &runner)
    {
        auto buf = build_winupd(flags::none, 5, 32768);
        auto parsed = parse_header(buf);
        runner.Check(parsed.has_value(), "roundtrip winupd: parsed");
        runner.Check(parsed->type == message_type::window_update,
                     "roundtrip winupd: type=window_update");
        runner.Check(parsed->stream_id == 5, "roundtrip winupd: stream_id=5");
        runner.Check(parsed->length == 32768, "roundtrip winupd: length=delta");
    }

    void TestRoundtripPing(TestRunner &runner)
    {
        auto buf = build_ping(flags::syn, 12345);
        auto parsed = parse_header(buf);
        runner.Check(parsed.has_value(), "roundtrip ping: parsed");
        runner.Check(parsed->type == message_type::ping, "roundtrip ping: type=ping");
        runner.Check(parsed->stream_id == 0, "roundtrip ping: stream_id=0");
        runner.Check(parsed->length == 12345, "roundtrip ping: length=ping_id");
    }

    void TestRoundtripGoaway(TestRunner &runner)
    {
        auto buf = build_goaway(away_code::protocol_error);
        auto parsed = parse_header(buf);
        runner.Check(parsed.has_value(), "roundtrip goaway: parsed");
        runner.Check(parsed->type == message_type::go_away,
                     "roundtrip goaway: type=go_away");
        runner.Check(parsed->stream_id == 0, "roundtrip goaway: stream_id=0");
        runner.Check(parsed->length == static_cast<std::uint32_t>(away_code::protocol_error),
                     "roundtrip goaway: length=protocol_error");
    }

    void TestRoundtripDataWithPayload(TestRunner &runner)
    {
        const std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        auto frame = build_data(flags::none, 10, data);
        auto parsed = parse_header(frame.header);
        runner.Check(parsed.has_value(), "roundtrip data: parsed");
        runner.Check(parsed->type == message_type::data, "roundtrip data: type=data");
        runner.Check(parsed->stream_id == 10, "roundtrip data: stream_id=10");
        runner.Check(parsed->length == 3, "roundtrip data: length=3");
    }

    void TestIsSession(TestRunner &runner)
    {
        frame_header hdr;
        hdr.stream_id = 0;
        runner.Check(hdr.is_session(), "is_session: stream 0 is session");
        hdr.stream_id = 1;
        runner.Check(!hdr.is_session(), "is_session: stream 1 is not session");
        hdr.stream_id = 999;
        runner.Check(!hdr.is_session(), "is_session: stream 999 is not session");
    }

    void TestParseHeaderEmpty(TestRunner &runner)
    {
        std::span<const std::byte> empty;
        auto result = parse_header(empty);
        runner.Check(!result.has_value(), "parse_header: empty -> nullopt");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("YamuxFrameError");

    TestParseHeaderTooShort(runner);
    TestParseHeaderBadVersion(runner);
    TestParseHeaderBadType(runner);
    TestRoundtripDataSyn(runner);
    TestRoundtripFin(runner);
    TestRoundtripWindowUpdate(runner);
    TestRoundtripPing(runner);
    TestRoundtripGoaway(runner);
    TestRoundtripDataWithPayload(runner);
    TestIsSession(runner);
    TestParseHeaderEmpty(runner);

    return runner.Summary();
}
