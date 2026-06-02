/**
 * @file YamuxCraftPure.cpp
 * @brief yamux frame 纯函数单元测试
 * @details 测试 build_header、parse_header、build_winupd、build_ping、
 *          build_goaway、build_data、build_syn、build_fin 帧构建与解析函数，
 *          验证 12 字节大端序编码正确性和往返一致性。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/yamux/frame.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace yamux = psm::multiplex::yamux;

    // ─── build_header 字节序正确性 ─────────────────

    TEST(YamuxCraftPure, BuildHeaderByteOrder)
    {
        yamux::frame_header hdr{};
        hdr.version = yamux::protocol_version;
        hdr.type = yamux::message_type::data;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 0x01020304;
        hdr.length = 0x0A0B0C0D;

        auto bytes = yamux::build_header(hdr);

        // 12 字节总长
        EXPECT_TRUE(bytes.size() == 12) << "build_header: 总长 12 字节";

        // Version=0
        EXPECT_TRUE(bytes[0] == std::byte{0x00}) << "build_header: version=0";

        // Type=data=0x00
        EXPECT_TRUE(bytes[1] == std::byte{0x00}) << "build_header: type=data";

        // Flags=syn=0x0001, 大端序
        EXPECT_TRUE(bytes[2] == std::byte{0x00}) << "build_header: flags 高字节";
        EXPECT_TRUE(bytes[3] == std::byte{0x01}) << "build_header: flags 低字节";

        // StreamID=0x01020304, 大端序
        EXPECT_TRUE(bytes[4] == std::byte{0x01}) << "build_header: stream_id[0]";
        EXPECT_TRUE(bytes[5] == std::byte{0x02}) << "build_header: stream_id[1]";
        EXPECT_TRUE(bytes[6] == std::byte{0x03}) << "build_header: stream_id[2]";
        EXPECT_TRUE(bytes[7] == std::byte{0x04}) << "build_header: stream_id[3]";

        // Length=0x0A0B0C0D, 大端序
        EXPECT_TRUE(bytes[8] == std::byte{0x0A}) << "build_header: length[0]";
        EXPECT_TRUE(bytes[9] == std::byte{0x0B}) << "build_header: length[1]";
        EXPECT_TRUE(bytes[10] == std::byte{0x0C}) << "build_header: length[2]";
        EXPECT_TRUE(bytes[11] == std::byte{0x0D}) << "build_header: length[3]";
    }

    // ─── parse_header 正常解析 ─────────────────────

    TEST(YamuxCraftPure, ParseHeaderBasic)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0x00}; // version
        buf[1] = std::byte{0x01}; // type=window_update
        buf[2] = std::byte{0x00}; // flags 高字节
        buf[3] = std::byte{0x02}; // flags 低字节 = ack
        buf[4] = std::byte{0x00}; // stream_id[0]
        buf[5] = std::byte{0x00}; // stream_id[1]
        buf[6] = std::byte{0x01}; // stream_id[2]
        buf[7] = std::byte{0x00}; // stream_id[3] => 256
        buf[8] = std::byte{0x00}; // length[0]
        buf[9] = std::byte{0x04}; // length[1]
        buf[10] = std::byte{0x00}; // length[2]
        buf[11] = std::byte{0x00}; // length[3] => 0x040000 = 262144

        auto hdr = yamux::parse_header(buf);
        ASSERT_TRUE(hdr.has_value()) << "parse_header: 解析成功";
        EXPECT_TRUE(hdr->version == 0) << "parse_header: version=0";
        EXPECT_TRUE(hdr->type == yamux::message_type::window_update) << "parse_header: type=window_update";
        EXPECT_TRUE(hdr->flag == yamux::flags::ack) << "parse_header: flag=ack";
        EXPECT_TRUE(hdr->stream_id == 256) << "parse_header: stream_id=256";
        EXPECT_TRUE(hdr->length == 262144) << "parse_header: length=262144";
    }

    // ─── parse_header 非法输入 ─────────────────────

    TEST(YamuxCraftPure, ParseHeaderBufferTooSmall)
    {
        std::array<std::byte, 8> small{};
        auto hdr = yamux::parse_header(small);
        EXPECT_TRUE(!hdr.has_value()) << "parse_header: 缓冲区不足返回 nullopt";
    }

    TEST(YamuxCraftPure, ParseHeaderBadVersion)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0x01}; // 非法版本
        buf[1] = std::byte{0x00}; // type=data
        auto hdr = yamux::parse_header(buf);
        EXPECT_TRUE(!hdr.has_value()) << "parse_header: 非法版本返回 nullopt";
    }

    TEST(YamuxCraftPure, ParseHeaderBadType)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0x00}; // version=0
        buf[1] = std::byte{0xFF}; // 非法 type
        auto hdr = yamux::parse_header(buf);
        EXPECT_TRUE(!hdr.has_value()) << "parse_header: 非法 type 返回 nullopt";
    }

    // ─── build_header <-> parse_header 往返验证 ──────

    TEST(YamuxCraftPure, RoundtripData)
    {
        yamux::frame_header original{};
        original.version = yamux::protocol_version;
        original.type = yamux::message_type::data;
        original.flag = yamux::flags::none;
        original.stream_id = 42;
        original.length = 1024;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        ASSERT_TRUE(decoded.has_value()) << "roundtrip data: 解析成功";
        EXPECT_TRUE(decoded->type == yamux::message_type::data) << "roundtrip data: type=data";
        EXPECT_TRUE(decoded->flag == yamux::flags::none) << "roundtrip data: flag=none";
        EXPECT_TRUE(decoded->stream_id == 42) << "roundtrip data: stream_id=42";
        EXPECT_TRUE(decoded->length == 1024) << "roundtrip data: length=1024";
    }

    TEST(YamuxCraftPure, RoundtripWindowUpdate)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::window_update;
        original.flag = yamux::flags::syn;
        original.stream_id = 1;
        original.length = yamux::default_window;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        ASSERT_TRUE(decoded.has_value()) << "roundtrip winupd: 解析成功";
        EXPECT_TRUE(decoded->type == yamux::message_type::window_update) << "roundtrip winupd: type";
        EXPECT_TRUE(decoded->flag == yamux::flags::syn) << "roundtrip winupd: flag=syn";
        EXPECT_TRUE(decoded->stream_id == 1) << "roundtrip winupd: stream_id=1";
        EXPECT_TRUE(decoded->length == yamux::default_window) << "roundtrip winupd: length=default_window";
    }

    TEST(YamuxCraftPure, RoundtripPing)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::ping;
        original.flag = yamux::flags::syn;
        original.stream_id = 0;
        original.length = 12345;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        ASSERT_TRUE(decoded.has_value()) << "roundtrip ping: 解析成功";
        EXPECT_TRUE(decoded->type == yamux::message_type::ping) << "roundtrip ping: type=ping";
        EXPECT_TRUE(decoded->flag == yamux::flags::syn) << "roundtrip ping: flag=syn";
        EXPECT_TRUE(decoded->stream_id == 0) << "roundtrip ping: stream_id=0";
        EXPECT_TRUE(decoded->length == 12345) << "roundtrip ping: length=12345";
        EXPECT_TRUE(decoded->is_session()) << "roundtrip ping: is_session=true";
    }

    TEST(YamuxCraftPure, RoundtripGoAway)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::go_away;
        original.flag = yamux::flags::none;
        original.stream_id = 0;
        original.length = static_cast<std::uint32_t>(yamux::away_code::protocol_error);

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        ASSERT_TRUE(decoded.has_value()) << "roundtrip goaway: 解析成功";
        EXPECT_TRUE(decoded->type == yamux::message_type::go_away) << "roundtrip goaway: type=go_away";
        EXPECT_TRUE(decoded->flag == yamux::flags::none) << "roundtrip goaway: flag=none";
        EXPECT_TRUE(decoded->stream_id == 0) << "roundtrip goaway: stream_id=0";
        EXPECT_TRUE(decoded->length == 1) << "roundtrip goaway: length=protocol_error=1";
    }

    // ─── build_winupd 测试 ─────────────────────────

    TEST(YamuxCraftPure, BuildWinupdSyn)
    {
        auto bytes = yamux::build_winupd(yamux::flags::syn, 1, yamux::default_window);

        EXPECT_TRUE(bytes.size() == 12) << "build_winupd syn: 总长 12 字节";
        EXPECT_TRUE(bytes[0] == std::byte{0x00}) << "build_winupd syn: version=0";
        EXPECT_TRUE(bytes[1] == std::byte{0x01}) << "build_winupd syn: type=window_update";

        auto hdr = yamux::parse_header(bytes);
        ASSERT_TRUE(hdr.has_value()) << "build_winupd syn: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::window_update) << "build_winupd syn: type";
        EXPECT_TRUE(hdr->flag == yamux::flags::syn) << "build_winupd syn: flag=syn";
        EXPECT_TRUE(hdr->stream_id == 1) << "build_winupd syn: stream_id=1";
        EXPECT_TRUE(hdr->length == yamux::default_window) << "build_winupd syn: length=default_window";
    }

    TEST(YamuxCraftPure, BuildWinupdAck)
    {
        auto bytes = yamux::build_winupd(yamux::flags::ack, 5, 32768);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "build_winupd ack: 解析成功";
        EXPECT_TRUE(hdr->flag == yamux::flags::ack) << "build_winupd ack: flag=ack";
        EXPECT_TRUE(hdr->stream_id == 5) << "build_winupd ack: stream_id=5";
        EXPECT_TRUE(hdr->length == 32768) << "build_winupd ack: length=32768";
    }

    TEST(YamuxCraftPure, BuildWinupdRst)
    {
        auto bytes = yamux::build_winupd(yamux::flags::rst, 99, 0);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "build_winupd rst: 解析成功";
        EXPECT_TRUE(hdr->flag == yamux::flags::rst) << "build_winupd rst: flag=rst";
        EXPECT_TRUE(hdr->stream_id == 99) << "build_winupd rst: stream_id=99";
        EXPECT_TRUE(hdr->length == 0) << "build_winupd rst: length=0";
    }

    // ─── build_ping 测试 ───────────────────────────

    TEST(YamuxCraftPure, BuildPingSyn)
    {
        auto bytes = yamux::build_ping(yamux::flags::syn, 42);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "build_ping syn: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::ping) << "build_ping syn: type=ping";
        EXPECT_TRUE(hdr->flag == yamux::flags::syn) << "build_ping syn: flag=syn";
        EXPECT_TRUE(hdr->stream_id == 0) << "build_ping syn: stream_id=0";
        EXPECT_TRUE(hdr->length == 42) << "build_ping syn: length=42";
    }

    TEST(YamuxCraftPure, BuildPingAck)
    {
        auto bytes = yamux::build_ping(yamux::flags::ack, 42);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "build_ping ack: 解析成功";
        EXPECT_TRUE(hdr->flag == yamux::flags::ack) << "build_ping ack: flag=ack";
        EXPECT_TRUE(hdr->length == 42) << "build_ping ack: length 与请求相同";
    }

    // ─── build_goaway 测试 ─────────────────────────

    TEST(YamuxCraftPure, BuildGoaway)
    {
        auto bytes = yamux::build_goaway(yamux::away_code::protocol_error);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "build_goaway: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::go_away) << "build_goaway: type=go_away";
        EXPECT_TRUE(hdr->flag == yamux::flags::none) << "build_goaway: flag=none";
        EXPECT_TRUE(hdr->stream_id == 0) << "build_goaway: stream_id=0";
        EXPECT_TRUE(hdr->length == static_cast<std::uint32_t>(yamux::away_code::protocol_error)) << "build_goaway: length=protocol_error";
    }

    // ─── build_data 测试 ───────────────────────────

    TEST(YamuxCraftPure, BuildDataWithPayload)
    {
        psm::memory::vector<std::byte> payload;
        payload.push_back(std::byte{0xAA});
        payload.push_back(std::byte{0xBB});
        payload.push_back(std::byte{0xCC});

        auto frame = yamux::build_data(yamux::flags::none, 10, payload);

        EXPECT_TRUE(frame.header.size() == 12) << "build_data: header 12 字节";
        auto hdr = yamux::parse_header(frame.header);
        ASSERT_TRUE(hdr.has_value()) << "build_data: header 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::data) << "build_data: type=data";
        EXPECT_TRUE(hdr->flag == yamux::flags::none) << "build_data: flag=none";
        EXPECT_TRUE(hdr->stream_id == 10) << "build_data: stream_id=10";
        EXPECT_TRUE(hdr->length == 3) << "build_data: length=3";

        EXPECT_TRUE(frame.payload.size() == 3) << "build_data: payload 3 字节";
        EXPECT_TRUE(frame.payload[0] == std::byte{0xAA}) << "build_data: payload[0]";
        EXPECT_TRUE(frame.payload[1] == std::byte{0xBB}) << "build_data: payload[1]";
        EXPECT_TRUE(frame.payload[2] == std::byte{0xCC}) << "build_data: payload[2]";
    }

    TEST(YamuxCraftPure, BuildDataEmpty)
    {
        auto frame = yamux::build_data(yamux::flags::fin, 7, {});
        auto hdr = yamux::parse_header(frame.header);

        ASSERT_TRUE(hdr.has_value()) << "build_data empty: header 解析成功";
        EXPECT_TRUE(hdr->flag == yamux::flags::fin) << "build_data empty: flag=fin";
        EXPECT_TRUE(hdr->length == 0) << "build_data empty: length=0";
        EXPECT_TRUE(frame.payload.empty()) << "build_data empty: payload 为空";
    }

    // ─── build_syn 测试 ────────────────────────────

    TEST(YamuxCraftPure, BuildSyn)
    {
        std::array<std::byte, 4> addr_data = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto frame = yamux::build_syn(3, addr_data);
        auto hdr = yamux::parse_header(frame.header);

        ASSERT_TRUE(hdr.has_value()) << "build_syn: header 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::data) << "build_syn: type=data";
        EXPECT_TRUE(hdr->flag == yamux::flags::syn) << "build_syn: flag=syn";
        EXPECT_TRUE(hdr->stream_id == 3) << "build_syn: stream_id=3";
        EXPECT_TRUE(hdr->length == 4) << "build_syn: length=4";
        EXPECT_TRUE(frame.payload.size() == 4) << "build_syn: payload 4 字节";
    }

    // ─── build_fin 测试 ────────────────────────────

    TEST(YamuxCraftPure, BuildFin)
    {
        auto bytes = yamux::build_fin(42);
        auto hdr = yamux::parse_header(bytes);

        EXPECT_TRUE(bytes.size() == 12) << "build_fin: 总长 12 字节";
        ASSERT_TRUE(hdr.has_value()) << "build_fin: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::data) << "build_fin: type=data";
        EXPECT_TRUE(hdr->flag == yamux::flags::fin) << "build_fin: flag=fin";
        EXPECT_TRUE(hdr->stream_id == 42) << "build_fin: stream_id=42";
        EXPECT_TRUE(hdr->length == 0) << "build_fin: length=0";
    }

    // ─── 边界值：stream_id=0（会话级） ─────────────

    TEST(YamuxCraftPure, SessionLevelFrame)
    {
        yamux::frame_header hdr{};
        hdr.type = yamux::message_type::ping;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 0;
        hdr.length = 1;

        EXPECT_TRUE(hdr.is_session()) << "session level: stream_id=0 -> is_session";

        auto encoded = yamux::build_header(hdr);
        auto decoded = yamux::parse_header(encoded);
        ASSERT_TRUE(decoded.has_value()) << "session level: 往返解析成功";
        EXPECT_TRUE(decoded->is_session()) << "session level: 解析后 is_session";
    }

    // ─── 边界值：最大 stream_id 和 length ──────────

    TEST(YamuxCraftPure, MaxValues)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::data;
        original.flag = static_cast<yamux::flags>(
            static_cast<std::uint16_t>(yamux::flags::syn) |
            static_cast<std::uint16_t>(yamux::flags::fin));
        original.stream_id = 0xFFFFFFFF;
        original.length = 0xFFFFFFFF;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        ASSERT_TRUE(decoded.has_value()) << "max values: 解析成功";
        EXPECT_TRUE(decoded->stream_id == 0xFFFFFFFF) << "max values: stream_id=max";
        EXPECT_TRUE(decoded->length == 0xFFFFFFFF) << "max values: length=max";

        // syn+fin 组合标志位
        const auto combined = static_cast<yamux::flags>(
            static_cast<std::uint16_t>(yamux::flags::syn) |
            static_cast<std::uint16_t>(yamux::flags::fin));
        EXPECT_TRUE(yamux::has_flag(combined, yamux::flags::syn)) << "max values: 包含 syn";
        EXPECT_TRUE(yamux::has_flag(combined, yamux::flags::fin)) << "max values: 包含 fin";
        EXPECT_TRUE(decoded->flag == combined) << "max values: flag=syn|fin";
    }

    // ─── has_flag 辅助函数 ─────────────────────────

    TEST(YamuxCraftPure, HasFlag)
    {
        const auto none = yamux::flags::none;
        const auto syn = yamux::flags::syn;
        const auto syn_fin = static_cast<yamux::flags>(
            static_cast<std::uint16_t>(yamux::flags::syn) |
            static_cast<std::uint16_t>(yamux::flags::fin));

        EXPECT_TRUE(!yamux::has_flag(none, yamux::flags::syn)) << "has_flag: none 不含 syn";
        EXPECT_TRUE(yamux::has_flag(syn, yamux::flags::syn)) << "has_flag: syn 含 syn";
        EXPECT_TRUE(!yamux::has_flag(syn, yamux::flags::fin)) << "has_flag: syn 不含 fin";
        EXPECT_TRUE(yamux::has_flag(syn_fin, yamux::flags::syn)) << "has_flag: syn|fin 含 syn";
        EXPECT_TRUE(yamux::has_flag(syn_fin, yamux::flags::fin)) << "has_flag: syn|fin 含 fin";
    }

    // ─── build_winupd 大端序字节级验证 ─────────────

    TEST(YamuxCraftPure, BuildWinupdByteLevel)
    {
        auto bytes = yamux::build_winupd(yamux::flags::ack, 256, 262144);

        EXPECT_TRUE(bytes[0] == std::byte{0x00}) << "winupd bytes: version=0";
        EXPECT_TRUE(bytes[1] == std::byte{0x01}) << "winupd bytes: type=window_update";
        // flags=ack=0x0002, 大端
        EXPECT_TRUE(bytes[2] == std::byte{0x00}) << "winupd bytes: flags 高字节";
        EXPECT_TRUE(bytes[3] == std::byte{0x02}) << "winupd bytes: flags 低字节=ack";
        // stream_id=256, 大端
        EXPECT_TRUE(bytes[4] == std::byte{0x00}) << "winupd bytes: sid[0]";
        EXPECT_TRUE(bytes[5] == std::byte{0x00}) << "winupd bytes: sid[1]";
        EXPECT_TRUE(bytes[6] == std::byte{0x01}) << "winupd bytes: sid[2]";
        EXPECT_TRUE(bytes[7] == std::byte{0x00}) << "winupd bytes: sid[3]";
        // length=262144, 大端
        EXPECT_TRUE(bytes[8] == std::byte{0x00}) << "winupd bytes: len[0]";
        EXPECT_TRUE(bytes[9] == std::byte{0x04}) << "winupd bytes: len[1]";
        EXPECT_TRUE(bytes[10] == std::byte{0x00}) << "winupd bytes: len[2]";
        EXPECT_TRUE(bytes[11] == std::byte{0x00}) << "winupd bytes: len[3]";
    }

    // ─── build_goaway 往返验证 ─────────────────────

    TEST(YamuxCraftPure, GoawayRoundtrip)
    {
        auto bytes = yamux::build_goaway(yamux::away_code::protocol_error);
        auto hdr = yamux::parse_header(bytes);

        ASSERT_TRUE(hdr.has_value()) << "goaway roundtrip: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::go_away) << "goaway roundtrip: type";
        EXPECT_TRUE(hdr->flag == yamux::flags::none) << "goaway roundtrip: flag=none";
        EXPECT_TRUE(hdr->stream_id == 0) << "goaway roundtrip: stream_id=0";
        EXPECT_TRUE(hdr->length == 1) << "goaway roundtrip: length=1";
    }

    // ─── build_data 往返验证（带载荷） ─────────────

    TEST(YamuxCraftPure, DataRoundtripWithPayload)
    {
        psm::memory::vector<std::byte> payload;
        for (int i = 0; i < 50; ++i)
        {
            payload.push_back(std::byte{static_cast<unsigned char>(i)});
        }

        auto frame = yamux::build_data(yamux::flags::none, 5678, payload);
        auto hdr = yamux::parse_header(frame.header);

        ASSERT_TRUE(hdr.has_value()) << "data roundtrip: 解析成功";
        EXPECT_TRUE(hdr->type == yamux::message_type::data) << "data roundtrip: type=data";
        EXPECT_TRUE(hdr->stream_id == 5678) << "data roundtrip: stream_id=5678";
        EXPECT_TRUE(hdr->length == 50) << "data roundtrip: length=50";

        // 载荷逐字节验证
        bool match = true;
        for (int i = 0; i < 50; ++i)
        {
            if (frame.payload[i] != std::byte{static_cast<unsigned char>(i)})
            {
                match = false;
                break;
            }
        }
        EXPECT_TRUE(match) << "data roundtrip: 载荷逐字节匹配";
    }

    // ─── build_syn 等价于 build_data(syn) ──────────

    TEST(YamuxCraftPure, BuildSynEquivalent)
    {
        std::array<std::byte, 3> data = {std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};

        auto syn_frame = yamux::build_syn(7, data);
        auto data_frame = yamux::build_data(yamux::flags::syn, 7, data);

        auto syn_hdr = yamux::parse_header(syn_frame.header);
        auto data_hdr = yamux::parse_header(data_frame.header);

        ASSERT_TRUE(syn_hdr.has_value() && data_hdr.has_value()) << "syn equiv: 均解析成功";
        EXPECT_TRUE(syn_hdr->type == data_hdr->type) << "syn equiv: type 相同";
        EXPECT_TRUE(syn_hdr->flag == data_hdr->flag) << "syn equiv: flag 相同";
        EXPECT_TRUE(syn_hdr->stream_id == data_hdr->stream_id) << "syn equiv: stream_id 相同";
        EXPECT_TRUE(syn_hdr->length == data_hdr->length) << "syn equiv: length 相同";
        EXPECT_TRUE(syn_frame.payload == data_frame.payload) << "syn equiv: payload 相同";
    }

    // ─── 所有合法 message_type 往返 ────────────────

    TEST(YamuxCraftPure, AllMessageTypesRoundtrip)
    {
        const yamux::message_type types[] = {
            yamux::message_type::data,
            yamux::message_type::window_update,
            yamux::message_type::ping,
            yamux::message_type::go_away,
        };

        for (const auto t : types)
        {
            yamux::frame_header original{};
            original.type = t;
            original.flag = yamux::flags::none;
            original.stream_id = 1;
            original.length = 100;

            auto encoded = yamux::build_header(original);
            auto decoded = yamux::parse_header(encoded);

            ASSERT_TRUE(decoded.has_value()) << "all types: 解析成功";
            EXPECT_TRUE(decoded->type == t) << "all types: type 一致";
        }
    }

} // namespace
