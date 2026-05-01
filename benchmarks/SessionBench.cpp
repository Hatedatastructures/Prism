/**
 * @file SessionBench.cpp
 * @brief 协议握手和数据传输吞吐量基准测试
 */

#include <benchmark/benchmark.h>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <boost/asio.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <thread>
#include <vector>

using namespace psm;
namespace net = boost::asio;

namespace
{
    struct pipe_pair
    {
        net::io_context io;
        net::ip::tcp::socket client;
        net::ip::tcp::socket server;

        explicit pipe_pair()
            : client(io), server(io)
        {
            net::ip::tcp::acceptor acceptor(io,
                net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
            acceptor.set_option(net::ip::tcp::acceptor::reuse_address(true));
            auto ep = acceptor.local_endpoint();

            client.open(net::ip::tcp::v4());
            client.set_option(net::ip::tcp::socket::reuse_address(true));
            client.bind(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
            client.connect(ep);
            server = acceptor.accept();
            acceptor.close();

            client.set_option(net::ip::tcp::no_delay(true));
            server.set_option(net::ip::tcp::no_delay(true));
        }

        ~pipe_pair()
        {
            boost::system::error_code ec;
            // linger(true, 0) 强制 RST 关闭，跳过 TIME_WAIT
            client.set_option(net::ip::tcp::socket::linger(true, 0), ec);
            server.set_option(net::ip::tcp::socket::linger(true, 0), ec);
            client.close(ec);
            server.close(ec);
        }
    };

    std::vector<std::uint8_t> make_payload(std::size_t size)
    {
        std::vector<std::uint8_t> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::uint8_t>(i & 0xFF);
        return payload;
    }

    std::array<std::uint8_t, 32> make_key()
    {
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < 32; ++i)
            key[i] = static_cast<std::uint8_t>(i);
        return key;
    }
} // namespace

// ============================================================
// 握手时间测试
// ============================================================

static void BM_HttpHandshakeTime(benchmark::State &state)
{
    for (auto _ : state)
    {
        pipe_pair pipe;

        const std::string request = "CONNECT www.example.com:443 HTTP/1.1\r\n\r\n";
        net::write(pipe.client, net::buffer(request));

        std::vector<char> buf(1024);
        pipe.server.read_some(net::buffer(buf));
        const std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        net::write(pipe.server, net::buffer(response));

        pipe.client.read_some(net::buffer(buf));
        benchmark::DoNotOptimize(buf.data());
    }
    state.SetItemsProcessed(state.iterations());
}

static void BM_Socks5HandshakeTime(benchmark::State &state)
{
    for (auto _ : state)
    {
        pipe_pair pipe;

        const std::array<std::uint8_t, 3> method_req = {0x05, 0x01, 0x00};
        net::write(pipe.client, net::buffer(method_req));

        std::array<std::uint8_t, 2> method_resp{};
        pipe.server.read_some(net::buffer(method_resp));
        const std::array<std::uint8_t, 2> select = {0x05, 0x00};
        net::write(pipe.server, net::buffer(select));

        std::array<std::uint8_t, 10> connect_req{};
        connect_req[0] = 0x05; connect_req[1] = 0x01; connect_req[2] = 0x00; connect_req[3] = 0x01;
        connect_req[4] = 127; connect_req[5] = 0; connect_req[6] = 0; connect_req[7] = 1;
        connect_req[8] = 0x00; connect_req[9] = 0x01;
        net::write(pipe.client, net::buffer(connect_req));

        std::array<std::uint8_t, 10> resp{};
        pipe.server.read_some(net::buffer(resp));
        const std::array<std::uint8_t, 10> success = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        net::write(pipe.server, net::buffer(success));

        pipe.client.read_some(net::buffer(resp));
        benchmark::DoNotOptimize(resp.data());
    }
    state.SetItemsProcessed(state.iterations());
}

static void BM_TrojanHandshakeTime(benchmark::State &state)
{
    for (auto _ : state)
    {
        pipe_pair pipe;

        std::vector<std::uint8_t> handshake(66);
        for (std::size_t i = 0; i < 56; ++i)
            handshake[i] = static_cast<std::uint8_t>('a');
        handshake[56] = '\r'; handshake[57] = '\n';
        handshake[58] = 0x01; handshake[59] = 0x01;
        handshake[60] = 127; handshake[61] = 0; handshake[62] = 0; handshake[63] = 1;
        handshake[64] = 0x00; handshake[65] = 0x01;
        net::write(pipe.client, net::buffer(handshake));

        std::vector<std::uint8_t> buf(66);
        pipe.server.read_some(net::buffer(buf));
        benchmark::DoNotOptimize(buf.data());
    }
    state.SetItemsProcessed(state.iterations());
}

static void BM_VlessHandshakeTime(benchmark::State &state)
{
    for (auto _ : state)
    {
        pipe_pair pipe;

        std::array<std::uint8_t, 26> request{};
        request[0] = 0x00;
        request[17] = 0x00; request[18] = 0x01;
        request[19] = 0x01; request[20] = 0xBB;
        request[21] = 0x01;
        request[22] = 127; request[23] = 0; request[24] = 0; request[25] = 1;
        net::write(pipe.client, net::buffer(request));

        std::vector<std::uint8_t> buf(26);
        pipe.server.read_some(net::buffer(buf));
        const std::array<std::uint8_t, 2> response = {0x00, 0x00};
        net::write(pipe.server, net::buffer(response));

        std::array<std::uint8_t, 2> resp{};
        pipe.client.read_some(net::buffer(resp));
        benchmark::DoNotOptimize(resp.data());
    }
    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// 队道数据传输吞吐量
// ============================================================

static void BM_TunnelThroughput(benchmark::State &state)
{
    pipe_pair pipe;

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
    std::vector<std::uint8_t> response(payload_size);

    std::thread server_thread([&pipe, payload_size]()
    {
        std::vector<std::uint8_t> buf(payload_size);
        boost::system::error_code ec;
        while (true)
        {
            std::size_t n = pipe.server.read_some(net::buffer(buf), ec);
            if (ec)
                break;
            net::write(pipe.server, net::buffer(buf, n), ec);
            if (ec)
                break;
        }
    });

    boost::system::error_code ec;
    for (auto _ : state)
    {
        net::write(pipe.client, net::buffer(payload), ec);
        if (ec)
            break;
        net::read(pipe.client, net::buffer(response), ec);
        if (ec)
            break;
        benchmark::DoNotOptimize(response.data());
    }

    pipe.client.close(ec);
    pipe.server.close(ec);
    server_thread.join();

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(payload_size * 2));
}

// ============================================================
// SS2022 AEAD 持续加密吞吐量
// ============================================================

static void BM_Ss2022AeadThroughput(benchmark::State &state)
{
    const auto key = make_key();

    crypto::aead_context client_ctx(crypto::aead_cipher::aes_256_gcm, key);
    crypto::aead_context server_ctx(crypto::aead_cipher::aes_256_gcm, key);

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    constexpr std::size_t tag_size = 16;
    const std::size_t encrypted_size = payload_size + tag_size;

    std::vector<std::uint8_t> encrypted(encrypted_size);
    std::vector<std::uint8_t> decrypted(payload_size);

    std::array<std::uint8_t, 12> nonce{};
    std::uint64_t counter = 0;

    for (auto _ : state)
    {
        // 客户端加密
        nonce[11] = static_cast<std::uint8_t>(counter & 0xFF);
        nonce[10] = static_cast<std::uint8_t>((counter >> 8) & 0xFF);

        auto seal_ec = client_ctx.seal(
            std::span<std::uint8_t>(encrypted.data(), encrypted_size),
            std::span<const std::uint8_t>(payload.data(), payload_size),
            std::span<const std::uint8_t>(nonce.data(), 12),
            {});
        if (fault::failed(seal_ec))
            state.SkipWithError("AEAD seal failed");

        // 服务端解密
        auto open_ec = server_ctx.open(
            std::span<std::uint8_t>(decrypted.data(), payload_size),
            std::span<const std::uint8_t>(encrypted.data(), encrypted_size),
            std::span<const std::uint8_t>(nonce.data(), 12),
            {});
        if (fault::failed(open_ec))
            state.SkipWithError("AEAD open failed");

        counter++;
        benchmark::DoNotOptimize(decrypted.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(payload_size * 2));
}

static void BM_Ss2022HandshakeTime(benchmark::State &state)
{
    const std::string psk_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    for (auto _ : state)
    {
        auto psk = crypto::base64_decode(psk_b64);
        if (psk.empty())
            state.SkipWithError("PSK decode failed");

        std::vector<std::uint8_t> key_bytes(32);
        for (std::size_t i = 0; i < std::min(psk.size(), std::size_t{32}); ++i)
            key_bytes[i] = static_cast<std::uint8_t>(psk[i]);

        crypto::aead_context ctx(crypto::aead_cipher::aes_256_gcm,
            std::span<const std::uint8_t>(key_bytes.data(), 32));

        benchmark::DoNotOptimize(ctx);
    }

    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_HttpHandshakeTime)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Socks5HandshakeTime)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_TrojanHandshakeTime)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_VlessHandshakeTime)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Ss2022HandshakeTime)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_TunnelThroughput)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_Ss2022AeadThroughput)
    ->Arg(1 * 1024)
    ->Arg(4 * 1024)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();