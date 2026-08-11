/**
 * @file MuxCommon.cpp
 * @brief 多路复用帧层 common 模块测试（smux/yamux/h2mux 帧编解码）
 */

#include <common/mock/mux/smux.hpp>
#include <common/mock/mux/yamux.hpp>
#include <common/mock/mux/h2mux.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(SmuxCommon, SynFrameRoundTrip)
{
    const auto frame = smux::build_frame(smux::cmd::syn, 1, {});
    ASSERT_EQ(frame.size(), 8);
    EXPECT_EQ(frame[0], 1); // ver
    EXPECT_EQ(frame[1], 0); // SYN

    const auto parsed = smux::parse_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.cmd, 0);
    EXPECT_EQ(parsed.stream_id, 1);
}

TEST(SmuxCommon, PshFrameWithData)
{
    const std::string payload = "hello smux";
    const auto frame = smux::build_frame(smux::cmd::psh, 7, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
    ASSERT_EQ(frame.size(), 8 + payload.size());

    const auto parsed = smux::parse_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.cmd, 4);
    EXPECT_EQ(parsed.stream_id, 7);
    EXPECT_EQ(frame.size() - parsed.data_offset, payload.size());
}

TEST(SmuxCommon, TruncatedFrame)
{
    const auto frame = smux::build_frame(smux::cmd::fin, 2, {});
    EXPECT_FALSE(smux::parse_frame(view(frame.data(), frame.size() - 1)).valid);
}

TEST(YamuxCommon, SynFrameRoundTrip)
{
    const auto frame = yamux::build_frame(yamux::type::syn, yamux::flag::syn, 1, {});
    ASSERT_EQ(frame.size(), 12);
    EXPECT_EQ(frame[0], 0); // version
    EXPECT_EQ(frame[1], 1); // SYN

    const auto parsed = yamux::parse_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.type, 1);
    EXPECT_EQ(parsed.flags, 0x1);
    EXPECT_EQ(parsed.stream_id, 1);
}

TEST(YamuxCommon, DataFrameWithPayload)
{
    const std::string payload = "hello yamux";
    const auto frame = yamux::build_frame(yamux::type::data, yamux::flag::ack, 3, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

    const auto parsed = yamux::parse_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.type, 0);
    EXPECT_EQ(parsed.flags, 0x2);
    EXPECT_EQ(parsed.stream_id, 3);
    EXPECT_EQ(frame.size() - parsed.data_offset, payload.size());
}

TEST(H2muxCommon, FrameRoundTrip)
{
    const std::string payload = "stream-request";
    const auto frame = h2mux::build_h2_frame(0x0A, 0x00, 1, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
    ASSERT_EQ(frame.size(), 9 + payload.size());

    const auto parsed = h2mux::parse_h2_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.type, 0x0A);
    EXPECT_EQ(parsed.stream_id, 1);
    EXPECT_EQ(frame.size() - parsed.payload_offset, payload.size());
}

TEST(H2muxCommon, StreamIdMask)
{
    // 高位置 1 的 stream id 应被掩码（RESERVED 位）
    const auto frame = h2mux::build_h2_frame(0x00, 0x00, 0x80000001, {});
    const auto parsed = h2mux::parse_h2_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.stream_id, 1);
}
