#include <benchmark/benchmark.h>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>

using namespace psm;

// ============================================================
// 辅助：预构造测试数据
// ============================================================

namespace
{
    // smux 8 字节帧头（小端序）
    // Version=1, Cmd=PSH(2), Length=256(0x0100 LE), StreamID=42(0x2A000000 LE)
    constexpr std::array<std::byte, 8> smux_psh_frame = {
        std::byte{0x01}, std::byte{0x02},
        std::byte{0x00}, std::byte{0x01}, // length=256 LE
        std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    // smux SYN 帧
    constexpr std::array<std::byte, 8> smux_syn_frame = {
        std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    // smux FIN 帧
    constexpr std::array<std::byte, 8> smux_fin_frame = {
        std::byte{0x01}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    // smux NOP 帧
    constexpr std::array<std::byte, 8> smux_nop_frame = {
        std::byte{0x01}, std::byte{0x03},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    // yamux 12 字节帧头（大端序）
    // Version=0, Type=Data(0), Flags=SYN(1), StreamID=1, Length=512
    constexpr std::array<std::byte, 12> yamux_data_syn_frame = {
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, // flags=SYN BE
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, // stream_id=1 BE
        std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, std::byte{0x00}}; // length=512 BE

    // yamux WindowUpdate 帧
    constexpr std::array<std::byte, 12> yamux_window_update_frame = {
        std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x02}, // flags=ACK BE
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}}; // delta=262144 BE

    // smux mux address: IPv4 [Flags 2B][ATYP=0x01][127.0.0.1][Port 8080]
    constexpr std::array<std::byte, 9> smux_addr_ipv4 = {
        std::byte{0x00}, std::byte{0x00}, // flags
        std::byte{0x01},                   // atype=IPv4
        std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x1F}, std::byte{0x90}}; // port=8080 BE

    // smux mux address: domain [Flags 2B][ATYP=0x03][len=11][example.com][Port 443]
    constexpr std::array<std::byte, 18> smux_addr_domain = {
        std::byte{0x00}, std::byte{0x00}, // flags
        std::byte{0x03},                   // atype=domain
        std::byte{11},                     // domain length
        std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'}, std::byte{'p'},
        std::byte{'l'}, std::byte{'e'}, std::byte{'.'}, std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
        std::byte{0x01}, std::byte{0xBB}}; // port=443 BE

    // smux UDP datagram: IPv4 [ATYP=0x01][127.0.0.1][Port 53][Length 2B BE][Payload]
    std::array<std::byte, 13> make_udp_ipv4_datagram()
    {
        std::array<std::byte, 13> buf{};
        buf[0] = std::byte{0x01};                        // atype=IPv4
        buf[1] = std::byte{127};                          // 127.0.0.1
        buf[2] = std::byte{0};
        buf[3] = std::byte{0};
        buf[4] = std::byte{1};
        buf[5] = std::byte{0x00};                         // port=53 BE
        buf[6] = std::byte{0x35};
        buf[7] = std::byte{0x00};                         // length=4 BE
        buf[8] = std::byte{0x04};
        buf[9] = std::byte{0xDE};                         // payload
        buf[10] = std::byte{0xAD};
        buf[11] = std::byte{0xBE};
        buf[12] = std::byte{0xEF};
        return buf;
    }

    // smux UDP length-prefixed: [Length 2B BE][Payload]
    std::array<std::byte, 6> make_udp_length_prefixed()
    {
        std::array<std::byte, 6> buf{};
        buf[0] = std::byte{0x00}; // length=4 BE
        buf[1] = std::byte{0x04};
        buf[2] = std::byte{0xCA};
        buf[3] = std::byte{0xFE};
        buf[4] = std::byte{0xBA};
        buf[5] = std::byte{0xBE};
        return buf;
    }

    // 生成 mux address（域名），参数化域名长度
    std::vector<std::byte> make_mux_domain_address(std::size_t domain_len)
    {
        std::vector<std::byte> buf(3 + 1 + domain_len + 2);
        buf[0] = std::byte{0x00}; // flags high
        buf[1] = std::byte{0x00}; // flags low
        buf[2] = std::byte{0x03}; // atype=domain
        buf[3] = static_cast<std::byte>(domain_len);
        for (std::size_t i = 0; i < domain_len; ++i)
            buf[4 + i] = static_cast<std::byte>('a' + (i % 26));
        const auto port_offset = 4 + domain_len;
        buf[port_offset] = std::byte{0x01};     // port=443 BE
        buf[port_offset + 1] = std::byte{0xBB};
        return buf;
    }

    // 生成 UDP datagram payload
    std::vector<std::byte> make_payload(std::size_t size)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(i & 0xFF);
        return payload;
    }
} // namespace

// ============================================================
// smux 帧头解析基准
// ============================================================

static void BM_SmuxFrameDeserialize_PSH(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(smux_psh_frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_psh_frame.size()));
}

static void BM_SmuxFrameDeserialize_SYN(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(smux_syn_frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_syn_frame.size()));
}

static void BM_SmuxFrameDeserialize_FIN(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(smux_fin_frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_fin_frame.size()));
}

static void BM_SmuxFrameDeserialize_NOP(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(smux_nop_frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_nop_frame.size()));
}

// ============================================================
// smux 地址解析基准
// ============================================================

static void BM_SmuxParseMuxAddress_IPv4(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        auto addr = multiplex::smux::parse_mux_address(smux_addr_ipv4, mr);
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_addr_ipv4.size()));
}

static void BM_SmuxParseMuxAddress_Domain(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        auto addr = multiplex::smux::parse_mux_address(smux_addr_domain, mr);
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(smux_addr_domain.size()));
}

static void BM_SmuxParseMuxAddress_Domain_VarLen(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();
    const auto domain_len = static_cast<std::size_t>(state.range(0));
    const auto data = make_mux_domain_address(domain_len);
    const auto span = std::span<const std::byte>(data.data(), data.size());

    for (auto _ : state)
    {
        arena.reset();
        auto addr = multiplex::smux::parse_mux_address(span, mr);
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(data.size()));
}

// ============================================================
// smux UDP 解析基准
// ============================================================

static void BM_SmuxParseUdpDatagram_IPv4(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();
    const auto data = make_udp_ipv4_datagram();

    for (auto _ : state)
    {
        arena.reset();
        auto dg = multiplex::smux::parse_udp_datagram(data, mr);
        benchmark::DoNotOptimize(dg);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(data.size()));
}

static void BM_SmuxParseUdpLengthPrefixed(benchmark::State &state)
{
    const auto data = make_udp_length_prefixed();

    for (auto _ : state)
    {
        auto dg = multiplex::smux::parse_udp_length_prefixed(data);
        benchmark::DoNotOptimize(dg);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(data.size()));
}

// ============================================================
// smux UDP 构建基准
// ============================================================

static void BM_SmuxBuildUdpDatagram_IPv4(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));

    for (auto _ : state)
    {
        arena.reset();
        auto buf = multiplex::smux::build_udp_datagram("127.0.0.1", 53,
                                                       std::span<const std::byte>(payload.data(), payload.size()), mr);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(9 + 4 + payload.size()));
}

static void BM_SmuxBuildUdpDatagram_Domain(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));

    for (auto _ : state)
    {
        arena.reset();
        auto buf = multiplex::smux::build_udp_datagram("example.com", 443,
                                                       std::span<const std::byte>(payload.data(), payload.size()), mr);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(6 + 11 + payload.size()));
}

static void BM_SmuxBuildUdpLengthPrefixed(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));

    for (auto _ : state)
    {
        arena.reset();
        auto buf = multiplex::smux::build_udp_length_prefixed(
            std::span<const std::byte>(payload.data(), payload.size()), mr);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(2 + payload.size()));
}

// ============================================================
// yamux 帧头编解码基准
// ============================================================

static void BM_YamuxBuildHeader(benchmark::State &state)
{
    multiplex::yamux::frame_header hdr{};
    hdr.version = multiplex::yamux::protocol_version;
    hdr.type = multiplex::yamux::message_type::data;
    hdr.flag = multiplex::yamux::flags::syn;
    hdr.stream_id = 1;
    hdr.length = 4096;

    for (auto _ : state)
    {
        auto buf = multiplex::yamux::build_header(hdr);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(multiplex::yamux::frame_header_size));
}

static void BM_YamuxParseHeader(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hdr = multiplex::yamux::parse_header(yamux_data_syn_frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(yamux_data_syn_frame.size()));
}

static void BM_YamuxBuildWindowUpdateFrame(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto buf = multiplex::yamux::build_window_update_frame(
            multiplex::yamux::flags::ack, 1, 262144);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(multiplex::yamux::frame_header_size));
}

static void BM_YamuxBuildPingFrame(benchmark::State &state)
{
    std::uint32_t ping_id = 12345;
    for (auto _ : state)
    {
        auto buf = multiplex::yamux::build_ping_frame(
            multiplex::yamux::flags::syn, ping_id);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(multiplex::yamux::frame_header_size));
}

static void BM_YamuxBuildGoAwayFrame(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto buf = multiplex::yamux::build_go_away_frame(
            multiplex::yamux::go_away_code::protocol_error);
        benchmark::DoNotOptimize(buf);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(multiplex::yamux::frame_header_size));
}

// ============================================================
// 跨协议帧解码吞吐量对比
// ============================================================

static void BM_MuxFrameDecode_Smux(benchmark::State &state)
{
    // 构造包含指定 payload 大小的 smux 帧
    const auto payload_size = static_cast<std::uint16_t>(state.range(0));
    std::array<std::byte, 8> frame{};
    frame[0] = std::byte{0x01};                             // version
    frame[1] = std::byte{0x02};                             // cmd=PSH
    frame[2] = static_cast<std::byte>(payload_size & 0xFF); // length LE
    frame[3] = static_cast<std::byte>(payload_size >> 8);
    frame[4] = std::byte{0x01}; // stream_id=1 LE
    frame[5] = std::byte{0x00};
    frame[6] = std::byte{0x00};
    frame[7] = std::byte{0x00};

    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(8 + payload_size));
}

static void BM_MuxFrameDecode_Yamux(benchmark::State &state)
{
    const auto payload_size = static_cast<std::uint32_t>(state.range(0));
    std::array<std::byte, 12> frame{};
    frame[0] = std::byte{0x00}; // version
    frame[1] = std::byte{0x00}; // type=Data
    frame[2] = std::byte{0x00}; // flags=none
    frame[3] = std::byte{0x00};
    frame[4] = std::byte{0x00}; // stream_id=1 BE
    frame[5] = std::byte{0x00};
    frame[6] = std::byte{0x00};
    frame[7] = std::byte{0x01};
    frame[8] = static_cast<std::byte>(payload_size >> 24 & 0xFF); // length BE
    frame[9] = static_cast<std::byte>(payload_size >> 16 & 0xFF);
    frame[10] = static_cast<std::byte>(payload_size >> 8 & 0xFF);
    frame[11] = static_cast<std::byte>(payload_size & 0xFF);

    for (auto _ : state)
    {
        auto hdr = multiplex::yamux::parse_header(frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(12 + payload_size));
}

// ============================================================
// 注册
// ============================================================

BENCHMARK(BM_SmuxFrameDeserialize_PSH);
BENCHMARK(BM_SmuxFrameDeserialize_SYN);
BENCHMARK(BM_SmuxFrameDeserialize_FIN);
BENCHMARK(BM_SmuxFrameDeserialize_NOP);

BENCHMARK(BM_SmuxParseMuxAddress_IPv4);
BENCHMARK(BM_SmuxParseMuxAddress_Domain);
BENCHMARK(BM_SmuxParseMuxAddress_Domain_VarLen)->Arg(4)->Arg(16)->Arg(64)->Arg(255);

BENCHMARK(BM_SmuxParseUdpDatagram_IPv4);
BENCHMARK(BM_SmuxParseUdpLengthPrefixed);

BENCHMARK(BM_SmuxBuildUdpDatagram_IPv4)->Arg(0)->Arg(64)->Arg(512)->Arg(4096);
BENCHMARK(BM_SmuxBuildUdpDatagram_Domain)->Arg(0)->Arg(64)->Arg(512)->Arg(4096);
BENCHMARK(BM_SmuxBuildUdpLengthPrefixed)->Arg(0)->Arg(64)->Arg(512)->Arg(4096);

BENCHMARK(BM_YamuxBuildHeader);
BENCHMARK(BM_YamuxParseHeader);
BENCHMARK(BM_YamuxBuildWindowUpdateFrame);
BENCHMARK(BM_YamuxBuildPingFrame);
BENCHMARK(BM_YamuxBuildGoAwayFrame);

BENCHMARK(BM_MuxFrameDecode_Smux)->Arg(0)->Arg(128)->Arg(512)->Arg(4096)->Arg(65535);
BENCHMARK(BM_MuxFrameDecode_Yamux)->Arg(0)->Arg(128)->Arg(512)->Arg(4096)->Arg(65535);

BENCHMARK_MAIN();
