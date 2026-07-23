/**
 * @file SmuxCraftPure.cpp
 * @brief smux craft 纯函数单元测试
 * @details 测试 make_data_frame、make_syn、make_fin 帧构建函数，
 *          以及 build_header 的字节序正确性。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/multiplex/smux/craft.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace smux = psm::multiplex::smux;

} // namespace

// ─── make_syn ──────────────────────────────────

TEST(SmuxCraftPure, MakeSyn)
{
    auto syn = smux::make_syn(42);
    EXPECT_TRUE(syn.size() == 8) << "make_syn: size=8";
    EXPECT_TRUE(syn[0] == std::byte{smux::protocol_version}) << "make_syn: version byte";
    EXPECT_TRUE(syn[1] == static_cast<std::byte>(smux::command::syn)) << "make_syn: cmd=syn";
    EXPECT_TRUE(syn[2] == std::byte{0}) << "make_syn: length LSB=0";
    EXPECT_TRUE(syn[3] == std::byte{0}) << "make_syn: length MSB=0";
    EXPECT_TRUE(syn[4] == std::byte{42}) << "make_syn: stream_id byte 0";
    EXPECT_TRUE(syn[5] == std::byte{0}) << "make_syn: stream_id byte 1";
    EXPECT_TRUE(syn[6] == std::byte{0}) << "make_syn: stream_id byte 2";
    EXPECT_TRUE(syn[7] == std::byte{0}) << "make_syn: stream_id byte 3";
}

// ─── make_fin ──────────────────────────────────

TEST(SmuxCraftPure, MakeFin)
{
    auto fin = smux::make_fin(7);
    EXPECT_TRUE(fin.size() == 8) << "make_fin: size=8";
    EXPECT_TRUE(fin[1] == static_cast<std::byte>(smux::command::fin)) << "make_fin: cmd=fin";
    EXPECT_TRUE(fin[4] == std::byte{7}) << "make_fin: stream_id=7";
}

// ─── make_data_frame ───────────────────────────

TEST(SmuxCraftPure, MakeDataFrame)
{
    psm::memory::vector<std::byte> payload;
    payload.push_back(std::byte{0x01});
    payload.push_back(std::byte{0x02});
    payload.push_back(std::byte{0x03});

    auto frame = smux::make_data_frame(100, payload);

    EXPECT_TRUE(frame.size() == 8 + 3) << "make_data: total size=11";
    EXPECT_TRUE(frame[1] == static_cast<std::byte>(smux::command::push)) << "make_data: cmd=push";
    EXPECT_TRUE(frame[2] == std::byte{3}) << "make_data: length LSB=3";
    EXPECT_TRUE(frame[3] == std::byte{0}) << "make_data: length MSB=0";
    EXPECT_TRUE(frame[4] == std::byte{100}) << "make_data: stream_id byte 0";
    EXPECT_TRUE(frame[8] == std::byte{0x01}) << "make_data: payload[0]";
    EXPECT_TRUE(frame[9] == std::byte{0x02}) << "make_data: payload[1]";
    EXPECT_TRUE(frame[10] == std::byte{0x03}) << "make_data: payload[2]";
}

TEST(SmuxCraftPure, MakeDataFrameEmpty)
{
    psm::memory::vector<std::byte> payload;
    auto frame = smux::make_data_frame(0, payload);
    EXPECT_TRUE(frame.size() == 8) << "make_data empty: header only";
}

// ─── stream_id 字节序（大 ID） ─────────────────

TEST(SmuxCraftPure, MakeSynLargeStreamId)
{
    auto syn = smux::make_syn(0x01020304);
    EXPECT_TRUE(syn[4] == std::byte{0x04}) << "syn: stream_id LE byte 0";
    EXPECT_TRUE(syn[5] == std::byte{0x03}) << "syn: stream_id LE byte 1";
    EXPECT_TRUE(syn[6] == std::byte{0x02}) << "syn: stream_id LE byte 2";
    EXPECT_TRUE(syn[7] == std::byte{0x01}) << "syn: stream_id LE byte 3";
}

// ─── frame deserialization roundtrip ────────────

TEST(SmuxCraftPure, FrameRoundtrip)
{
    auto syn = smux::make_syn(1234);
    auto hdr = smux::deserialization(syn);
    EXPECT_TRUE(hdr.has_value()) << "roundtrip: deserialization success";
    EXPECT_TRUE(hdr->cmd == smux::command::syn) << "roundtrip: cmd=syn";
    EXPECT_TRUE(hdr->stream_id == 1234) << "roundtrip: stream_id=1234";
    EXPECT_TRUE(hdr->length == 0) << "roundtrip: length=0";
}

TEST(SmuxCraftPure, DataFrameRoundtrip)
{
    psm::memory::vector<std::byte> payload;
    for (int i = 0; i < 100; ++i)
        payload.push_back(std::byte{static_cast<unsigned char>(i)});

    auto frame = smux::make_data_frame(5678, payload);

    // 反序列化头部（前 8 字节）
    std::array<std::byte, 8> hdr_bytes;
    std::memcpy(hdr_bytes.data(), frame.data(), 8);
    auto hdr = smux::deserialization(hdr_bytes);
    EXPECT_TRUE(hdr.has_value()) << "data roundtrip: deserialization success";
    EXPECT_TRUE(hdr->cmd == smux::command::push) << "data roundtrip: cmd=push";
    EXPECT_TRUE(hdr->stream_id == 5678) << "data roundtrip: stream_id=5678";
    EXPECT_TRUE(hdr->length == 100) << "data roundtrip: length=100";

    // 验证 payload 一致
    bool payload_match = true;
    for (int i = 0; i < 100; ++i)
    {
        if (frame[8 + i] != std::byte{static_cast<unsigned char>(i)})
        {
            payload_match = false;
            break;
        }
    }
    EXPECT_TRUE(payload_match) << "data roundtrip: payload matches";
}

// ─── make_fin roundtrip ────────────────────────

TEST(SmuxCraftPure, FinRoundtrip)
{
    auto fin = smux::make_fin(0xFFFFFFFF);
    auto hdr = smux::deserialization(fin);
    EXPECT_TRUE(hdr.has_value()) << "fin roundtrip: success";
    EXPECT_TRUE(hdr->cmd == smux::command::fin) << "fin roundtrip: cmd=fin";
    EXPECT_TRUE(hdr->stream_id == 0xFFFFFFFF) << "fin roundtrip: max stream_id";
}
