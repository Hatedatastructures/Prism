/**
 * @file SmuxCraftDeep.cpp
 * @brief smux craft 深度纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 build_header，
 *          以及公开的 make_data_frame、make_syn、make_fin。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include "../../src/prism/multiplex/smux/craft.cpp"

namespace
{
    namespace smux = psm::multiplex::smux;

} // namespace

// ─── build_header ──────────────────────────

TEST(SmuxCraftDeep, BuildHeaderPush)
{
    auto hdr = psm::multiplex::smux::build_header(smux::command::push, 1, 4);
    EXPECT_TRUE(hdr.size() == smux::frame_hdrsize) << "build_header: size=8";
    EXPECT_TRUE(hdr[0] == std::byte{smux::protocol_version}) << "build_header: version";
    EXPECT_TRUE(hdr[1] == std::byte{0x02}) << "build_header: push cmd=2";
    EXPECT_TRUE(hdr[2] == std::byte{0x04}) << "build_header: length low";
    EXPECT_TRUE(hdr[3] == std::byte{0x00}) << "build_header: length high";
    EXPECT_TRUE(hdr[4] == std::byte{0x01}) << "build_header: stream_id byte0";
    EXPECT_TRUE(hdr[5] == std::byte{0x00}) << "build_header: stream_id byte1";
    EXPECT_TRUE(hdr[6] == std::byte{0x00}) << "build_header: stream_id byte2";
    EXPECT_TRUE(hdr[7] == std::byte{0x00}) << "build_header: stream_id byte3";
}

TEST(SmuxCraftDeep, BuildHeaderSyn)
{
    auto hdr = psm::multiplex::smux::build_header(smux::command::syn, 42, 0);
    EXPECT_TRUE(hdr[1] == std::byte{0x00}) << "build_header: syn cmd=0";
    EXPECT_TRUE(hdr[2] == std::byte{0x00}) << "build_header: syn length low";
    EXPECT_TRUE(hdr[3] == std::byte{0x00}) << "build_header: syn length high";
    EXPECT_TRUE(hdr[4] == std::byte{42}) << "build_header: syn stream_id byte0";
}

TEST(SmuxCraftDeep, BuildHeaderFin)
{
    auto hdr = psm::multiplex::smux::build_header(smux::command::fin, 7, 0);
    EXPECT_TRUE(hdr[1] == std::byte{0x01}) << "build_header: fin cmd=1";
    EXPECT_TRUE(hdr[4] == std::byte{0x07}) << "build_header: fin stream_id=7";
}

TEST(SmuxCraftDeep, BuildHeaderNop)
{
    auto hdr = psm::multiplex::smux::build_header(smux::command::nop, 0, 0);
    EXPECT_TRUE(hdr[1] == std::byte{0x03}) << "build_header: nop cmd=3";
}

TEST(SmuxCraftDeep, BuildHeaderLargeLength)
{
    constexpr std::uint16_t len = 0xABCD;
    auto hdr = psm::multiplex::smux::build_header(smux::command::push, 1, len);
    EXPECT_TRUE(hdr[2] == std::byte{0xCD}) << "build_header: large length low";
    EXPECT_TRUE(hdr[3] == std::byte{0xAB}) << "build_header: large length high";
}

TEST(SmuxCraftDeep, BuildHeaderLargeStreamId)
{
    constexpr std::uint32_t sid = 0x12345678;
    auto hdr = psm::multiplex::smux::build_header(smux::command::push, sid, 0);
    EXPECT_TRUE(hdr[4] == std::byte{0x78}) << "build_header: stream_id byte0";
    EXPECT_TRUE(hdr[5] == std::byte{0x56}) << "build_header: stream_id byte1";
    EXPECT_TRUE(hdr[6] == std::byte{0x34}) << "build_header: stream_id byte2";
    EXPECT_TRUE(hdr[7] == std::byte{0x12}) << "build_header: stream_id byte3";
}

// ─── make_data_frame ────────────────────────

TEST(SmuxCraftDeep, MakeDataFrameBasic)
{
    const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    auto frame = smux::make_data_frame(5, payload);
    EXPECT_TRUE(frame.size() == smux::frame_hdrsize + 3) << "make_data_frame: header+payload";
    EXPECT_TRUE(frame[0] == std::byte{smux::protocol_version}) << "make_data_frame: version";
    EXPECT_TRUE(frame[1] == std::byte{0x02}) << "make_data_frame: push cmd";
    EXPECT_TRUE(frame[2] == std::byte{0x03}) << "make_data_frame: length=3 low";
    EXPECT_TRUE(frame[3] == std::byte{0x00}) << "make_data_frame: length=3 high";
    EXPECT_TRUE(frame[4] == std::byte{0x05}) << "make_data_frame: stream_id=5";
    EXPECT_TRUE(frame[8] == std::byte{0xAA}) << "make_data_frame: payload[0]";
    EXPECT_TRUE(frame[9] == std::byte{0xBB}) << "make_data_frame: payload[1]";
    EXPECT_TRUE(frame[10] == std::byte{0xCC}) << "make_data_frame: payload[2]";
}

TEST(SmuxCraftDeep, MakeDataFrameEmpty)
{
    std::span<const std::byte> empty;
    auto frame = smux::make_data_frame(1, empty);
    EXPECT_TRUE(frame.size() == smux::frame_hdrsize) << "make_data_frame: empty payload -> header only";
}

TEST(SmuxCraftDeep, MakeDataFrameLargeStreamId)
{
    const std::byte payload[] = {std::byte{0xFF}};
    auto frame = smux::make_data_frame(0xDEAD, payload);
    EXPECT_TRUE(frame[4] == std::byte{0xAD}) << "make_data_frame: large stream_id low";
    EXPECT_TRUE(frame[5] == std::byte{0xDE}) << "make_data_frame: large stream_id high";
}

// ─── make_syn ────────────────────────────────

TEST(SmuxCraftDeep, MakeSynBasic)
{
    auto hdr = smux::make_syn(1);
    EXPECT_TRUE(hdr.size() == smux::frame_hdrsize) << "make_syn: size=8";
    EXPECT_TRUE(hdr[0] == std::byte{smux::protocol_version}) << "make_syn: version";
    EXPECT_TRUE(hdr[1] == std::byte{0x00}) << "make_syn: syn cmd=0";
    EXPECT_TRUE(hdr[2] == std::byte{0x00}) << "make_syn: length low";
    EXPECT_TRUE(hdr[3] == std::byte{0x00}) << "make_syn: length high";
    EXPECT_TRUE(hdr[4] == std::byte{0x01}) << "make_syn: stream_id=1";
}

TEST(SmuxCraftDeep, MakeSynZeroStreamId)
{
    auto hdr = smux::make_syn(0);
    EXPECT_TRUE(hdr[4] == std::byte{0x00}) << "make_syn: zero stream_id";
    EXPECT_TRUE(hdr[5] == std::byte{0x00}) << "make_syn: zero stream_id byte1";
}

// ─── make_fin ────────────────────────────────

TEST(SmuxCraftDeep, MakeFinBasic)
{
    auto hdr = smux::make_fin(3);
    EXPECT_TRUE(hdr.size() == smux::frame_hdrsize) << "make_fin: size=8";
    EXPECT_TRUE(hdr[1] == std::byte{0x01}) << "make_fin: fin cmd=1";
    EXPECT_TRUE(hdr[2] == std::byte{0x00}) << "make_fin: length=0";
    EXPECT_TRUE(hdr[4] == std::byte{0x03}) << "make_fin: stream_id=3";
}

TEST(SmuxCraftDeep, MakeFinMaxStreamId)
{
    auto hdr = smux::make_fin(0xFFFFFFFF);
    EXPECT_TRUE(hdr[4] == std::byte{0xFF}) << "make_fin: max stream_id byte0";
    EXPECT_TRUE(hdr[5] == std::byte{0xFF}) << "make_fin: max stream_id byte1";
    EXPECT_TRUE(hdr[6] == std::byte{0xFF}) << "make_fin: max stream_id byte2";
    EXPECT_TRUE(hdr[7] == std::byte{0xFF}) << "make_fin: max stream_id byte3";
}

// ─── log_spawn_error ────────────────────────

TEST(SmuxCraftDeep, LogSpawnErrorException)
{
    try
    {
        throw std::runtime_error("test error");
    }
    catch (...)
    {
        auto ep = std::current_exception();
        psm::multiplex::smux::log_spawn_error(ep, 42, "test_label");
    }
}

TEST(SmuxCraftDeep, LogSpawnErrorUnknown)
{
    try
    {
        throw 42;
    }
    catch (...)
    {
        auto ep = std::current_exception();
        psm::multiplex::smux::log_spawn_error(ep, 1, "unknown");
    }
}
