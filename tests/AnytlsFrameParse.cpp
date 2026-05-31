/**
 * @file AnytlsFrameParse.cpp
 * @brief AnyTLS 帧头 parse/serialize/roundtrip 测试
 */

#include <prism/memory.hpp>
#include <prism/stealth/stack/anytls/mux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::stealth::anytls::command;
    using psm::stealth::anytls::frame_header;
    using psm::stealth::anytls::frame_header_size;

    void TestParseTooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 4> short_buf{};
        auto result = frame_header::parse(short_buf);
        runner.Check(!result.has_value(), "parse: too short -> nullopt");
    }

    void TestParseEmpty(TestRunner &runner)
    {
        std::span<const std::uint8_t> empty;
        auto result = frame_header::parse(empty);
        runner.Check(!result.has_value(), "parse: empty -> nullopt");
    }

    void TestParse6Bytes(TestRunner &runner)
    {
        std::array<std::uint8_t, 6> buf{};
        auto result = frame_header::parse(buf);
        runner.Check(!result.has_value(), "parse: 6 bytes -> nullopt");
    }

    void TestParseValidSyn(TestRunner &runner)
    {
        frame_header hdr;
        hdr.cmd = command::syn;
        hdr.stream_id = 42;
        hdr.length = 100;

        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        runner.Check(parsed.has_value(), "parse: valid syn -> has_value");
        runner.Check(parsed->cmd == command::syn, "parse: syn cmd");
        runner.Check(parsed->stream_id == 42, "parse: syn stream_id");
        runner.Check(parsed->length == 100, "parse: syn length");
    }

    void TestSerializeAllCommands(TestRunner &runner)
    {
        for (auto cmd : {command::waste, command::syn, command::psh, command::fin,
                         command::settings, command::alert, command::update_padding,
                         command::synack, command::heart_req, command::heart_resp,
                         command::server_settings})
        {
            frame_header hdr;
            hdr.cmd = cmd;
            hdr.stream_id = 0;
            hdr.length = 0;
            auto ser = hdr.serialize();
            runner.Check(ser.size() == frame_header_size, "serialize: 7 bytes");
            runner.Check(ser[0] == static_cast<std::uint8_t>(cmd),
                         "serialize: cmd byte correct");
        }
    }

    void TestRoundtripAllCommands(TestRunner &runner)
    {
        for (auto cmd : {command::waste, command::syn, command::psh, command::fin,
                         command::settings, command::alert, command::update_padding,
                         command::synack, command::heart_req, command::heart_resp,
                         command::server_settings})
        {
            frame_header hdr;
            hdr.cmd = cmd;
            hdr.stream_id = 0x12345678;
            hdr.length = 0xABCD;

            auto ser = hdr.serialize();
            auto parsed = frame_header::parse(ser);
            runner.Check(parsed.has_value(), "roundtrip: has_value");
            runner.Check(parsed->cmd == cmd, "roundtrip: cmd matches");
            runner.Check(parsed->stream_id == 0x12345678, "roundtrip: stream_id matches");
            runner.Check(parsed->length == 0xABCD, "roundtrip: length matches");
        }
    }

    void TestZeroValues(TestRunner &runner)
    {
        frame_header hdr;
        hdr.cmd = command::waste;
        hdr.stream_id = 0;
        hdr.length = 0;
        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        runner.Check(parsed.has_value(), "zero: parsed");
        runner.Check(parsed->cmd == command::waste, "zero: cmd=waste");
        runner.Check(parsed->stream_id == 0, "zero: stream_id=0");
        runner.Check(parsed->length == 0, "zero: length=0");
    }

    void TestMaxValues(TestRunner &runner)
    {
        frame_header hdr;
        hdr.cmd = command::server_settings;
        hdr.stream_id = 0xFFFFFFFF;
        hdr.length = 0xFFFF;
        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        runner.Check(parsed.has_value(), "max: parsed");
        runner.Check(parsed->stream_id == 0xFFFFFFFF, "max: stream_id=max");
        runner.Check(parsed->length == 0xFFFF, "max: length=max");
    }

    void TestSerializeByteLayout(TestRunner &runner)
    {
        frame_header hdr;
        hdr.cmd = command::psh;
        hdr.stream_id = 0x01020304;
        hdr.length = 0x0506;
        auto ser = hdr.serialize();
        runner.Check(ser[0] == 0x02, "layout: cmd byte");
        runner.Check(ser[1] == 0x01, "layout: stream_id[0]");
        runner.Check(ser[2] == 0x02, "layout: stream_id[1]");
        runner.Check(ser[3] == 0x03, "layout: stream_id[2]");
        runner.Check(ser[4] == 0x04, "layout: stream_id[3]");
        runner.Check(ser[5] == 0x05, "layout: length[0]");
        runner.Check(ser[6] == 0x06, "layout: length[1]");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsFrameParse");

    TestParseTooShort(runner);
    TestParseEmpty(runner);
    TestParse6Bytes(runner);
    TestParseValidSyn(runner);
    TestSerializeAllCommands(runner);
    TestRoundtripAllCommands(runner);
    TestZeroValues(runner);
    TestMaxValues(runner);
    TestSerializeByteLayout(runner);

    return runner.Summary();
}
