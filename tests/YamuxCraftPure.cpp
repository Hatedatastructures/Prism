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

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace yamux = psm::multiplex::yamux;

    // ─── build_header 字节序正确性 ─────────────────

    void TestBuildHeaderByteOrder(TestRunner &runner)
    {
        yamux::frame_header hdr{};
        hdr.version = yamux::protocol_version;
        hdr.type = yamux::message_type::data;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 0x01020304;
        hdr.length = 0x0A0B0C0D;

        auto bytes = yamux::build_header(hdr);

        // 12 字节总长
        runner.Check(bytes.size() == 12, "build_header: 总长 12 字节");

        // Version=0
        runner.Check(bytes[0] == std::byte{0x00}, "build_header: version=0");

        // Type=data=0x00
        runner.Check(bytes[1] == std::byte{0x00}, "build_header: type=data");

        // Flags=syn=0x0001, 大端序
        runner.Check(bytes[2] == std::byte{0x00}, "build_header: flags 高字节");
        runner.Check(bytes[3] == std::byte{0x01}, "build_header: flags 低字节");

        // StreamID=0x01020304, 大端序
        runner.Check(bytes[4] == std::byte{0x01}, "build_header: stream_id[0]");
        runner.Check(bytes[5] == std::byte{0x02}, "build_header: stream_id[1]");
        runner.Check(bytes[6] == std::byte{0x03}, "build_header: stream_id[2]");
        runner.Check(bytes[7] == std::byte{0x04}, "build_header: stream_id[3]");

        // Length=0x0A0B0C0D, 大端序
        runner.Check(bytes[8] == std::byte{0x0A}, "build_header: length[0]");
        runner.Check(bytes[9] == std::byte{0x0B}, "build_header: length[1]");
        runner.Check(bytes[10] == std::byte{0x0C}, "build_header: length[2]");
        runner.Check(bytes[11] == std::byte{0x0D}, "build_header: length[3]");
    }

    // ─── parse_header 正常解析 ─────────────────────

    void TestParseHeaderBasic(TestRunner &runner)
    {
        // 手工构造 12 字节大端帧
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
        runner.Check(hdr.has_value(), "parse_header: 解析成功");
        runner.Check(hdr->version == 0, "parse_header: version=0");
        runner.Check(hdr->type == yamux::message_type::window_update, "parse_header: type=window_update");
        runner.Check(hdr->flag == yamux::flags::ack, "parse_header: flag=ack");
        runner.Check(hdr->stream_id == 256, "parse_header: stream_id=256");
        runner.Check(hdr->length == 262144, "parse_header: length=262144");
    }

    // ─── parse_header 非法输入 ─────────────────────

    void TestParseHeaderBufferTooSmall(TestRunner &runner)
    {
        std::array<std::byte, 8> small{};
        auto hdr = yamux::parse_header(small);
        runner.Check(!hdr.has_value(), "parse_header: 缓冲区不足返回 nullopt");
    }

    void TestParseHeaderBadVersion(TestRunner &runner)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0x01}; // 非法版本
        buf[1] = std::byte{0x00}; // type=data
        auto hdr = yamux::parse_header(buf);
        runner.Check(!hdr.has_value(), "parse_header: 非法版本返回 nullopt");
    }

    void TestParseHeaderBadType(TestRunner &runner)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0x00}; // version=0
        buf[1] = std::byte{0xFF}; // 非法 type
        auto hdr = yamux::parse_header(buf);
        runner.Check(!hdr.has_value(), "parse_header: 非法 type 返回 nullopt");
    }

    // ─── build_header ↔ parse_header 往返验证 ──────

    void TestRoundtripData(TestRunner &runner)
    {
        yamux::frame_header original{};
        original.version = yamux::protocol_version;
        original.type = yamux::message_type::data;
        original.flag = yamux::flags::none;
        original.stream_id = 42;
        original.length = 1024;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        runner.Check(decoded.has_value(), "roundtrip data: 解析成功");
        runner.Check(decoded->type == yamux::message_type::data, "roundtrip data: type=data");
        runner.Check(decoded->flag == yamux::flags::none, "roundtrip data: flag=none");
        runner.Check(decoded->stream_id == 42, "roundtrip data: stream_id=42");
        runner.Check(decoded->length == 1024, "roundtrip data: length=1024");
    }

    void TestRoundtripWindowUpdate(TestRunner &runner)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::window_update;
        original.flag = yamux::flags::syn;
        original.stream_id = 1;
        original.length = yamux::default_window;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        runner.Check(decoded.has_value(), "roundtrip winupd: 解析成功");
        runner.Check(decoded->type == yamux::message_type::window_update, "roundtrip winupd: type");
        runner.Check(decoded->flag == yamux::flags::syn, "roundtrip winupd: flag=syn");
        runner.Check(decoded->stream_id == 1, "roundtrip winupd: stream_id=1");
        runner.Check(decoded->length == yamux::default_window, "roundtrip winupd: length=default_window");
    }

    void TestRoundtripPing(TestRunner &runner)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::ping;
        original.flag = yamux::flags::syn;
        original.stream_id = 0;
        original.length = 12345;

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        runner.Check(decoded.has_value(), "roundtrip ping: 解析成功");
        runner.Check(decoded->type == yamux::message_type::ping, "roundtrip ping: type=ping");
        runner.Check(decoded->flag == yamux::flags::syn, "roundtrip ping: flag=syn");
        runner.Check(decoded->stream_id == 0, "roundtrip ping: stream_id=0");
        runner.Check(decoded->length == 12345, "roundtrip ping: length=12345");
        runner.Check(decoded->is_session(), "roundtrip ping: is_session=true");
    }

    void TestRoundtripGoAway(TestRunner &runner)
    {
        yamux::frame_header original{};
        original.type = yamux::message_type::go_away;
        original.flag = yamux::flags::none;
        original.stream_id = 0;
        original.length = static_cast<std::uint32_t>(yamux::away_code::protocol_error);

        auto encoded = yamux::build_header(original);
        auto decoded = yamux::parse_header(encoded);

        runner.Check(decoded.has_value(), "roundtrip goaway: 解析成功");
        runner.Check(decoded->type == yamux::message_type::go_away, "roundtrip goaway: type=go_away");
        runner.Check(decoded->flag == yamux::flags::none, "roundtrip goaway: flag=none");
        runner.Check(decoded->stream_id == 0, "roundtrip goaway: stream_id=0");
        runner.Check(decoded->length == 1, "roundtrip goaway: length=protocol_error=1");
    }

    // ─── build_winupd 测试 ─────────────────────────

    void TestBuildWinupdSyn(TestRunner &runner)
    {
        auto bytes = yamux::build_winupd(yamux::flags::syn, 1, yamux::default_window);

        runner.Check(bytes.size() == 12, "build_winupd syn: 总长 12 字节");
        runner.Check(bytes[0] == std::byte{0x00}, "build_winupd syn: version=0");
        runner.Check(bytes[1] == std::byte{0x01}, "build_winupd syn: type=window_update");

        auto hdr = yamux::parse_header(bytes);
        runner.Check(hdr.has_value(), "build_winupd syn: 解析成功");
        runner.Check(hdr->type == yamux::message_type::window_update, "build_winupd syn: type");
        runner.Check(hdr->flag == yamux::flags::syn, "build_winupd syn: flag=syn");
        runner.Check(hdr->stream_id == 1, "build_winupd syn: stream_id=1");
        runner.Check(hdr->length == yamux::default_window, "build_winupd syn: length=default_window");
    }

    void TestBuildWinupdAck(TestRunner &runner)
    {
        auto bytes = yamux::build_winupd(yamux::flags::ack, 5, 32768);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "build_winupd ack: 解析成功");
        runner.Check(hdr->flag == yamux::flags::ack, "build_winupd ack: flag=ack");
        runner.Check(hdr->stream_id == 5, "build_winupd ack: stream_id=5");
        runner.Check(hdr->length == 32768, "build_winupd ack: length=32768");
    }

    void TestBuildWinupdRst(TestRunner &runner)
    {
        auto bytes = yamux::build_winupd(yamux::flags::rst, 99, 0);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "build_winupd rst: 解析成功");
        runner.Check(hdr->flag == yamux::flags::rst, "build_winupd rst: flag=rst");
        runner.Check(hdr->stream_id == 99, "build_winupd rst: stream_id=99");
        runner.Check(hdr->length == 0, "build_winupd rst: length=0");
    }

    // ─── build_ping 测试 ───────────────────────────

    void TestBuildPingSyn(TestRunner &runner)
    {
        auto bytes = yamux::build_ping(yamux::flags::syn, 42);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "build_ping syn: 解析成功");
        runner.Check(hdr->type == yamux::message_type::ping, "build_ping syn: type=ping");
        runner.Check(hdr->flag == yamux::flags::syn, "build_ping syn: flag=syn");
        runner.Check(hdr->stream_id == 0, "build_ping syn: stream_id=0");
        runner.Check(hdr->length == 42, "build_ping syn: length=42");
    }

    void TestBuildPingAck(TestRunner &runner)
    {
        auto bytes = yamux::build_ping(yamux::flags::ack, 42);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "build_ping ack: 解析成功");
        runner.Check(hdr->flag == yamux::flags::ack, "build_ping ack: flag=ack");
        runner.Check(hdr->length == 42, "build_ping ack: length 与请求相同");
    }

    // ─── build_goaway 测试 ─────────────────────────

    void TestBuildGoaway(TestRunner &runner)
    {
        auto bytes = yamux::build_goaway(yamux::away_code::protocol_error);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "build_goaway: 解析成功");
        runner.Check(hdr->type == yamux::message_type::go_away, "build_goaway: type=go_away");
        runner.Check(hdr->flag == yamux::flags::none, "build_goaway: flag=none");
        runner.Check(hdr->stream_id == 0, "build_goaway: stream_id=0");
        runner.Check(hdr->length == static_cast<std::uint32_t>(yamux::away_code::protocol_error),
                     "build_goaway: length=protocol_error");
    }

    // ─── build_data 测试 ───────────────────────────

    void TestBuildDataWithPayload(TestRunner &runner)
    {
        psm::memory::vector<std::byte> payload;
        payload.push_back(std::byte{0xAA});
        payload.push_back(std::byte{0xBB});
        payload.push_back(std::byte{0xCC});

        auto frame = yamux::build_data(yamux::flags::none, 10, payload);

        // 帧头检查
        runner.Check(frame.header.size() == 12, "build_data: header 12 字节");
        auto hdr = yamux::parse_header(frame.header);
        runner.Check(hdr.has_value(), "build_data: header 解析成功");
        runner.Check(hdr->type == yamux::message_type::data, "build_data: type=data");
        runner.Check(hdr->flag == yamux::flags::none, "build_data: flag=none");
        runner.Check(hdr->stream_id == 10, "build_data: stream_id=10");
        runner.Check(hdr->length == 3, "build_data: length=3");

        // 载荷检查
        runner.Check(frame.payload.size() == 3, "build_data: payload 3 字节");
        runner.Check(frame.payload[0] == std::byte{0xAA}, "build_data: payload[0]");
        runner.Check(frame.payload[1] == std::byte{0xBB}, "build_data: payload[1]");
        runner.Check(frame.payload[2] == std::byte{0xCC}, "build_data: payload[2]");
    }

    void TestBuildDataEmpty(TestRunner &runner)
    {
        auto frame = yamux::build_data(yamux::flags::fin, 7, {});
        auto hdr = yamux::parse_header(frame.header);

        runner.Check(hdr.has_value(), "build_data empty: header 解析成功");
        runner.Check(hdr->flag == yamux::flags::fin, "build_data empty: flag=fin");
        runner.Check(hdr->length == 0, "build_data empty: length=0");
        runner.Check(frame.payload.empty(), "build_data empty: payload 为空");
    }

    // ─── build_syn 测试 ────────────────────────────

    void TestBuildSyn(TestRunner &runner)
    {
        std::array<std::byte, 4> addr_data = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto frame = yamux::build_syn(3, addr_data);
        auto hdr = yamux::parse_header(frame.header);

        runner.Check(hdr.has_value(), "build_syn: header 解析成功");
        runner.Check(hdr->type == yamux::message_type::data, "build_syn: type=data");
        runner.Check(hdr->flag == yamux::flags::syn, "build_syn: flag=syn");
        runner.Check(hdr->stream_id == 3, "build_syn: stream_id=3");
        runner.Check(hdr->length == 4, "build_syn: length=4");
        runner.Check(frame.payload.size() == 4, "build_syn: payload 4 字节");
    }

    // ─── build_fin 测试 ────────────────────────────

    void TestBuildFin(TestRunner &runner)
    {
        auto bytes = yamux::build_fin(42);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(bytes.size() == 12, "build_fin: 总长 12 字节");
        runner.Check(hdr.has_value(), "build_fin: 解析成功");
        runner.Check(hdr->type == yamux::message_type::data, "build_fin: type=data");
        runner.Check(hdr->flag == yamux::flags::fin, "build_fin: flag=fin");
        runner.Check(hdr->stream_id == 42, "build_fin: stream_id=42");
        runner.Check(hdr->length == 0, "build_fin: length=0");
    }

    // ─── 边界值：stream_id=0（会话级） ─────────────

    void TestSessionLevelFrame(TestRunner &runner)
    {
        yamux::frame_header hdr{};
        hdr.type = yamux::message_type::ping;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 0;
        hdr.length = 1;

        runner.Check(hdr.is_session(), "session level: stream_id=0 → is_session");

        auto encoded = yamux::build_header(hdr);
        auto decoded = yamux::parse_header(encoded);
        runner.Check(decoded.has_value(), "session level: 往返解析成功");
        runner.Check(decoded->is_session(), "session level: 解析后 is_session");
    }

    // ─── 边界值：最大 stream_id 和 length ──────────

    void TestMaxValues(TestRunner &runner)
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

        runner.Check(decoded.has_value(), "max values: 解析成功");
        runner.Check(decoded->stream_id == 0xFFFFFFFF, "max values: stream_id=max");
        runner.Check(decoded->length == 0xFFFFFFFF, "max values: length=max");

        // syn+fin 组合标志位
        const auto combined = static_cast<yamux::flags>(
            static_cast<std::uint16_t>(yamux::flags::syn) |
            static_cast<std::uint16_t>(yamux::flags::fin));
        runner.Check(yamux::has_flag(combined, yamux::flags::syn), "max values: 包含 syn");
        runner.Check(yamux::has_flag(combined, yamux::flags::fin), "max values: 包含 fin");
        runner.Check(decoded->flag == combined, "max values: flag=syn|fin");
    }

    // ─── has_flag 辅助函数 ─────────────────────────

    void TestHasFlag(TestRunner &runner)
    {
        const auto none = yamux::flags::none;
        const auto syn = yamux::flags::syn;
        const auto syn_fin = static_cast<yamux::flags>(
            static_cast<std::uint16_t>(yamux::flags::syn) |
            static_cast<std::uint16_t>(yamux::flags::fin));

        runner.Check(!yamux::has_flag(none, yamux::flags::syn), "has_flag: none 不含 syn");
        runner.Check(yamux::has_flag(syn, yamux::flags::syn), "has_flag: syn 含 syn");
        runner.Check(!yamux::has_flag(syn, yamux::flags::fin), "has_flag: syn 不含 fin");
        runner.Check(yamux::has_flag(syn_fin, yamux::flags::syn), "has_flag: syn|fin 含 syn");
        runner.Check(yamux::has_flag(syn_fin, yamux::flags::fin), "has_flag: syn|fin 含 fin");
    }

    // ─── build_winupd 大端序字节级验证 ─────────────

    void TestBuildWinupdByteLevel(TestRunner &runner)
    {
        // stream_id=0x00000100=256, delta=0x00040000=262144
        auto bytes = yamux::build_winupd(yamux::flags::ack, 256, 262144);

        runner.Check(bytes[0] == std::byte{0x00}, "winupd bytes: version=0");
        runner.Check(bytes[1] == std::byte{0x01}, "winupd bytes: type=window_update");
        // flags=ack=0x0002, 大端
        runner.Check(bytes[2] == std::byte{0x00}, "winupd bytes: flags 高字节");
        runner.Check(bytes[3] == std::byte{0x02}, "winupd bytes: flags 低字节=ack");
        // stream_id=256, 大端
        runner.Check(bytes[4] == std::byte{0x00}, "winupd bytes: sid[0]");
        runner.Check(bytes[5] == std::byte{0x00}, "winupd bytes: sid[1]");
        runner.Check(bytes[6] == std::byte{0x01}, "winupd bytes: sid[2]");
        runner.Check(bytes[7] == std::byte{0x00}, "winupd bytes: sid[3]");
        // length=262144, 大端
        runner.Check(bytes[8] == std::byte{0x00}, "winupd bytes: len[0]");
        runner.Check(bytes[9] == std::byte{0x04}, "winupd bytes: len[1]");
        runner.Check(bytes[10] == std::byte{0x00}, "winupd bytes: len[2]");
        runner.Check(bytes[11] == std::byte{0x00}, "winupd bytes: len[3]");
    }

    // ─── build_goaway 往返验证 ─────────────────────

    void TestGoawayRoundtrip(TestRunner &runner)
    {
        auto bytes = yamux::build_goaway(yamux::away_code::protocol_error);
        auto hdr = yamux::parse_header(bytes);

        runner.Check(hdr.has_value(), "goaway roundtrip: 解析成功");
        runner.Check(hdr->type == yamux::message_type::go_away, "goaway roundtrip: type");
        runner.Check(hdr->flag == yamux::flags::none, "goaway roundtrip: flag=none");
        runner.Check(hdr->stream_id == 0, "goaway roundtrip: stream_id=0");
        runner.Check(hdr->length == 1, "goaway roundtrip: length=1");
    }

    // ─── build_data 往返验证（带载荷） ─────────────

    void TestDataRoundtripWithPayload(TestRunner &runner)
    {
        psm::memory::vector<std::byte> payload;
        for (int i = 0; i < 50; ++i)
        {
            payload.push_back(std::byte{static_cast<unsigned char>(i)});
        }

        auto frame = yamux::build_data(yamux::flags::none, 5678, payload);
        auto hdr = yamux::parse_header(frame.header);

        runner.Check(hdr.has_value(), "data roundtrip: 解析成功");
        runner.Check(hdr->type == yamux::message_type::data, "data roundtrip: type=data");
        runner.Check(hdr->stream_id == 5678, "data roundtrip: stream_id=5678");
        runner.Check(hdr->length == 50, "data roundtrip: length=50");

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
        runner.Check(match, "data roundtrip: 载荷逐字节匹配");
    }

    // ─── build_syn 等价于 build_data(syn) ──────────

    void TestBuildSynEquivalent(TestRunner &runner)
    {
        std::array<std::byte, 3> data = {std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};

        auto syn_frame = yamux::build_syn(7, data);
        auto data_frame = yamux::build_data(yamux::flags::syn, 7, data);

        auto syn_hdr = yamux::parse_header(syn_frame.header);
        auto data_hdr = yamux::parse_header(data_frame.header);

        runner.Check(syn_hdr.has_value() && data_hdr.has_value(), "syn equiv: 均解析成功");
        runner.Check(syn_hdr->type == data_hdr->type, "syn equiv: type 相同");
        runner.Check(syn_hdr->flag == data_hdr->flag, "syn equiv: flag 相同");
        runner.Check(syn_hdr->stream_id == data_hdr->stream_id, "syn equiv: stream_id 相同");
        runner.Check(syn_hdr->length == data_hdr->length, "syn equiv: length 相同");
        runner.Check(syn_frame.payload == data_frame.payload, "syn equiv: payload 相同");
    }

    // ─── 所有合法 message_type 往返 ────────────────

    void TestAllMessageTypesRoundtrip(TestRunner &runner)
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

            runner.Check(decoded.has_value(), "all types: 解析成功");
            runner.Check(decoded->type == t, "all types: type 一致");
        }
    }

} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("YamuxCraftPure");

    TestBuildHeaderByteOrder(runner);
    TestParseHeaderBasic(runner);
    TestParseHeaderBufferTooSmall(runner);
    TestParseHeaderBadVersion(runner);
    TestParseHeaderBadType(runner);
    TestRoundtripData(runner);
    TestRoundtripWindowUpdate(runner);
    TestRoundtripPing(runner);
    TestRoundtripGoAway(runner);
    TestBuildWinupdSyn(runner);
    TestBuildWinupdAck(runner);
    TestBuildWinupdRst(runner);
    TestBuildPingSyn(runner);
    TestBuildPingAck(runner);
    TestBuildGoaway(runner);
    TestBuildDataWithPayload(runner);
    TestBuildDataEmpty(runner);
    TestBuildSyn(runner);
    TestBuildFin(runner);
    TestSessionLevelFrame(runner);
    TestMaxValues(runner);
    TestHasFlag(runner);
    TestBuildWinupdByteLevel(runner);
    TestGoawayRoundtrip(runner);
    TestDataRoundtripWithPayload(runner);
    TestBuildSynEquivalent(runner);
    TestAllMessageTypesRoundtrip(runner);

    return runner.Summary();
}
