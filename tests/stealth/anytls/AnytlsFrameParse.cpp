/**
 * @file AnytlsFrameParse.cpp
 * @brief AnyTLS 帧头 parse/serialize/roundtrip 测试
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/stack/anytls/mux/frame.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace
{
    using psm::stealth::anytls::command;
    using psm::stealth::anytls::frame_header;
    using psm::stealth::anytls::frame_header_size;

    TEST(AnytlsFrameParse, ParseTooShort)
    {
        std::array<std::uint8_t, 4> short_buf{};
        auto result = frame_header::parse(short_buf);
        EXPECT_TRUE(!result.has_value()) << "parse: too short -> nullopt";
    }

    TEST(AnytlsFrameParse, ParseEmpty)
    {
        std::span<const std::uint8_t> empty;
        auto result = frame_header::parse(empty);
        EXPECT_TRUE(!result.has_value()) << "parse: empty -> nullopt";
    }

    TEST(AnytlsFrameParse, Parse6Bytes)
    {
        std::array<std::uint8_t, 6> buf{};
        auto result = frame_header::parse(buf);
        EXPECT_TRUE(!result.has_value()) << "parse: 6 bytes -> nullopt";
    }

    TEST(AnytlsFrameParse, ParseValidSyn)
    {
        frame_header hdr;
        hdr.cmd = command::syn;
        hdr.stream_id = 42;
        hdr.length = 100;

        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        EXPECT_TRUE(parsed.has_value()) << "parse: valid syn -> has_value";
        EXPECT_TRUE(parsed->cmd == command::syn) << "parse: syn cmd";
        EXPECT_TRUE(parsed->stream_id == 42) << "parse: syn stream_id";
        EXPECT_TRUE(parsed->length == 100) << "parse: syn length";
    }

    TEST(AnytlsFrameParse, SerializeAllCommands)
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
            EXPECT_TRUE(ser.size() == frame_header_size) << "serialize: 7 bytes";
            EXPECT_TRUE(ser[0] == static_cast<std::uint8_t>(cmd))
                << "serialize: cmd byte correct";
        }
    }

    TEST(AnytlsFrameParse, RoundtripAllCommands)
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
            EXPECT_TRUE(parsed.has_value()) << "roundtrip: has_value";
            EXPECT_TRUE(parsed->cmd == cmd) << "roundtrip: cmd matches";
            EXPECT_TRUE(parsed->stream_id == 0x12345678) << "roundtrip: stream_id matches";
            EXPECT_TRUE(parsed->length == 0xABCD) << "roundtrip: length matches";
        }
    }

    TEST(AnytlsFrameParse, ZeroValues)
    {
        frame_header hdr;
        hdr.cmd = command::waste;
        hdr.stream_id = 0;
        hdr.length = 0;
        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        EXPECT_TRUE(parsed.has_value()) << "zero: parsed";
        EXPECT_TRUE(parsed->cmd == command::waste) << "zero: cmd=waste";
        EXPECT_TRUE(parsed->stream_id == 0) << "zero: stream_id=0";
        EXPECT_TRUE(parsed->length == 0) << "zero: length=0";
    }

    TEST(AnytlsFrameParse, MaxValues)
    {
        frame_header hdr;
        hdr.cmd = command::server_settings;
        hdr.stream_id = 0xFFFFFFFF;
        hdr.length = 0xFFFF;
        auto ser = hdr.serialize();
        auto parsed = frame_header::parse(ser);
        EXPECT_TRUE(parsed.has_value()) << "max: parsed";
        EXPECT_TRUE(parsed->stream_id == 0xFFFFFFFF) << "max: stream_id=max";
        EXPECT_TRUE(parsed->length == 0xFFFF) << "max: length=max";
    }

    TEST(AnytlsFrameParse, SerializeByteLayout)
    {
        frame_header hdr;
        hdr.cmd = command::psh;
        hdr.stream_id = 0x01020304;
        hdr.length = 0x0506;
        auto ser = hdr.serialize();
        EXPECT_TRUE(ser[0] == 0x02) << "layout: cmd byte";
        EXPECT_TRUE(ser[1] == 0x01) << "layout: stream_id[0]";
        EXPECT_TRUE(ser[2] == 0x02) << "layout: stream_id[1]";
        EXPECT_TRUE(ser[3] == 0x03) << "layout: stream_id[2]";
        EXPECT_TRUE(ser[4] == 0x04) << "layout: stream_id[3]";
        EXPECT_TRUE(ser[5] == 0x05) << "layout: length[0]";
        EXPECT_TRUE(ser[6] == 0x06) << "layout: length[1]";
    }

} // namespace
