/**
 * @file MuxBench.cpp
 * @brief 多路复用连接吞吐量基准测试
 * @details 测量 smux/yamux 完整连接数据传输吞吐量，
 *          模拟真实多流竞争场景。对标 Go 版 BenchmarkConnSmux。
 */

#include <benchmark/benchmark.h>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <prism/config.hpp>
#include <boost/asio.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

using namespace psm;
namespace net = boost::asio;

// ============================================================
// 辅助：创建一对连接的 pipe（模拟 TCP 连接）
// ============================================================

namespace
{
    struct pipe_pair
    {
        net::io_context &io;
        net::ip::tcp::socket client;
        net::ip::tcp::socket server;

        pipe_pair(net::io_context &ioc)
            : io(ioc), client(ioc), server(ioc)
        {
            net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
            auto port = acceptor.local_endpoint().port();

            client.connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            server = acceptor.accept();
            acceptor.close();

            // 禁用 Nagle 算法
            client.set_option(net::ip::tcp::no_delay(true));
            server.set_option(net::ip::tcp::no_delay(true));
        }
    };

    // 生成测试数据
    std::vector<std::byte> make_payload(std::size_t size)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(i & 0xFF);
        return payload;
    }

    // smux 帧头
    auto make_smux_psh_frame(std::uint16_t length, std::uint32_t stream_id)
    {
        std::array<std::byte, 8> frame{};
        frame[0] = std::byte{0x01};                               // version
        frame[1] = std::byte{0x02};                               // cmd=PSH
        frame[2] = static_cast<std::byte>(length & 0xFF);         // length LE
        frame[3] = static_cast<std::byte>(length >> 8);
        frame[4] = static_cast<std::byte>(stream_id & 0xFF);      // stream_id LE
        frame[5] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
        frame[6] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
        frame[7] = static_cast<std::byte>((stream_id >> 24) & 0xFF);
        return frame;
    }

    // yamux 帧头
    auto make_yamux_data_frame(std::uint32_t length, std::uint32_t stream_id)
    {
        std::array<std::byte, 12> frame{};
        frame[0] = std::byte{0x00}; // version
        frame[1] = std::byte{0x00}; // type=Data
        frame[2] = std::byte{0x00}; // flags=none
        frame[3] = std::byte{0x00};
        frame[4] = static_cast<std::byte>((stream_id >> 24) & 0xFF); // stream_id BE
        frame[5] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
        frame[6] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
        frame[7] = static_cast<std::byte>(stream_id & 0xFF);
        frame[8] = static_cast<std::byte>((length >> 24) & 0xFF);    // length BE
        frame[9] = static_cast<std::byte>((length >> 16) & 0xFF);
        frame[10] = static_cast<std::byte>((length >> 8) & 0xFF);
        frame[11] = static_cast<std::byte>(length & 0xFF);
        return frame;
    }
} // namespace

// ============================================================
// smux 帧编解码吞吐量
// 测试帧头序列化/反序列化性能（零拷贝 scatter-gather 场景）
// ============================================================

static void BM_SmuxFrameSerialization(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto frame = make_smux_psh_frame(65535, 1);
        benchmark::DoNotOptimize(frame);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(8));
}

static void BM_SmuxFrameDeserialization(benchmark::State &state)
{
    auto frame = make_smux_psh_frame(65535, 1);
    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(8));
}

// ============================================================
// yamux 帧编解码吞吐量
// ============================================================

static void BM_YamuxFrameSerialization(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto frame = make_yamux_data_frame(65535, 1);
        benchmark::DoNotOptimize(frame);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(12));
}

static void BM_YamuxFrameDeserialization(benchmark::State &state)
{
    auto frame = make_yamux_data_frame(65535, 1);
    for (auto _ : state)
    {
        auto hdr = multiplex::yamux::parse_header(frame);
        benchmark::DoNotOptimize(hdr);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(12));
}

// ============================================================
// smux UDP 数据报构建吞吐量
// 测试实际数据传输场景下的 UDP 数据报构建性能
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
// BENCHMARK 注册
// ============================================================

// 帧编解码
BENCHMARK(BM_SmuxFrameSerialization);
BENCHMARK(BM_SmuxFrameDeserialization);
BENCHMARK(BM_YamuxFrameSerialization);
BENCHMARK(BM_YamuxFrameDeserialization);

// UDP 数据报构建（真实数据传输场景）
BENCHMARK(BM_SmuxBuildUdpDatagram_IPv4)->Arg(0)->Arg(64)->Arg(512)->Arg(4096)->Arg(16384);
BENCHMARK(BM_SmuxBuildUdpLengthPrefixed)->Arg(0)->Arg(64)->Arg(512)->Arg(4096)->Arg(16384);

BENCHMARK_MAIN();
