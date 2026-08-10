/**
 * @file VmessChunk.cpp
 * @brief VMess 数据分块流测试
 * @details 验证 chunk 读写往返、SHAKE128 掩码流、EOF 终止块。
 *          使用本地 TCP socket pair 构建双向管道。
 */

#include <prism/protocol/vmess/codec/chunk.hpp>
#include <prism/net/transport/reliable.hpp>

#include <gtest/gtest.h>

#include <memory>

namespace
{
    using psm::protocol::vmess::codec::read_stream;
    using psm::protocol::vmess::codec::stream_params;
    using psm::protocol::vmess::codec::write_stream;

    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    constexpr std::uint8_t k_option = static_cast<std::uint8_t>(psm::protocol::vmess::option::chunk_stream)
        | static_cast<std::uint8_t>(psm::protocol::vmess::option::chunk_masking);
    constexpr std::uint8_t k_security = static_cast<std::uint8_t>(psm::protocol::vmess::security::aes_128_gcm);

    /// 建立本地 TCP socket pair（client/server 传输层）
    auto make_pair_transport(net::io_context &ioc)
        -> std::pair<psm::transport::shared_transmission,
                     psm::transport::shared_transmission>
    {
        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        const auto ep = acceptor.local_endpoint();

        std::pair<psm::transport::shared_transmission, psm::transport::shared_transmission> result;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_sock = co_await acceptor.async_accept(net::use_awaitable);
            result.second = psm::transport::make_reliable(std::move(server_sock));
        }, net::detached);

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            tcp::socket client_sock(ioc);
            co_await client_sock.async_connect(ep, net::use_awaitable);
            result.first = psm::transport::make_reliable(std::move(client_sock));
        }, net::detached);

        // 驱动到连接建立
        ioc.restart();
        ioc.run();
        ioc.restart();
        return result;
    }
}

TEST(VmessChunk, ShakeStreamIncremental)
{
    // SHAKE128 连续输出：同一 seed 的独立实例输出一致；next() 段不重复
    std::array<std::uint8_t, 16> seed{};
    seed.fill(0xAB);
    psm::protocol::vmess::codec::shake_stream s1(seed);
    psm::protocol::vmess::codec::shake_stream s2(seed);

    const auto a1_view = s1.next();
    std::array<std::uint8_t, 168> a1{};
    std::memcpy(a1.data(), a1_view.data(), a1_view.size());
    const auto a2 = s1.next();
    const auto b = s2.next();

    EXPECT_EQ(b.size(), 168);
    // a1 是流前 168 字节，与另一实例 b 完全一致
    for (std::size_t i = 0; i < 168; ++i)
        EXPECT_EQ(a1[i], b[i]);
    // a2 是后续段，首字节与 a1 不同（连续流不会重复）
    EXPECT_NE(a2[0], a1[0]);
}

TEST(VmessChunk, WriteReadRoundtrip)
{
    net::io_context ioc;
    auto [client, server] = make_pair_transport(ioc);

    stream_params sp_client{.transport = client.get()};
    stream_params sp_server{.transport = server.get()};
    sp_client.key.fill(0x01);
    sp_client.nonce.fill(0x02);
    sp_server.key.fill(0x01);
    sp_server.nonce.fill(0x02);
    sp_client.option = k_option;
    sp_client.security = k_security;
    sp_server.option = k_option;
    sp_server.security = k_security;

    write_stream writer(sp_client);
    read_stream reader(sp_server);

    const std::string payload = "vmess chunk roundtrip payload";
    bool client_ok = false;
    bool server_ok = false;

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        std::error_code ec;
        co_await writer.write_chunk(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
        client_ok = !ec;
        co_await writer.finish(ec);
        client_ok = client_ok && !ec;
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        const auto n = co_await reader.read_chunk(buf, ec);
        server_ok = !ec && n == payload.size()
            && std::string_view(reinterpret_cast<const char *>(buf.data()), n) == payload;
    }, net::detached);

    ioc.run();
    EXPECT_TRUE(client_ok);
    EXPECT_TRUE(server_ok);
}

TEST(VmessChunk, MultipleChunksOrdered)
{
    net::io_context ioc;
    auto [client, server] = make_pair_transport(ioc);

    stream_params sp_client{.transport = client.get()};
    stream_params sp_server{.transport = server.get()};
    sp_client.key.fill(0x11);
    sp_client.nonce.fill(0x12);
    sp_server.key.fill(0x11);
    sp_server.nonce.fill(0x12);
    sp_client.option = k_option;
    sp_client.security = k_security;
    sp_server.option = k_option;
    sp_server.security = k_security;

    write_stream writer(sp_client);
    read_stream reader(sp_server);

    const std::array<std::string, 3> chunks{"first", "second-chunk", "third"};
    std::vector<std::string> received;
    bool ok = false;

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        for (const auto &c : chunks)
        {
            std::error_code ec;
            co_await writer.write_chunk(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(c.data()), c.size()), ec);
            if (ec)
                co_return;
        }
        std::error_code ec;
        co_await writer.finish(ec);
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        while (true)
        {
            std::error_code ec;
            const auto n = co_await reader.read_chunk(buf, ec);
            if (ec || n == 0)
                break;
            received.emplace_back(reinterpret_cast<const char *>(buf.data()), n);
        }
        ok = (received == std::vector<std::string>(chunks.begin(), chunks.end()));
    }, net::detached);

    ioc.run();
    EXPECT_TRUE(ok);
}
