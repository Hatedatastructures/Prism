/**
 * @file VmessConnEcho.cpp
 * @brief VMess 协议端到端测试（模拟客户端 → 服务端 conn）
 * @details 手工构造与 mihomo sing-vmess 兼容的客户端：
 *          1. seal_request 构造首包 → 服务端 handshake()
 *          2. 验证响应头（38 字节）可被客户端解析
 *          3. 客户端写数据块 → 服务端读取回显 → 客户端解密验证
 */

#include <prism/protocol/vmess/vmess.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/transport/reliable.hpp>

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <memory>

namespace
{
    using namespace psm::protocol::vmess;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /// 建立本地 TCP socket pair
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
        ioc.restart();
        ioc.run();
        ioc.restart();
        return result;
    }

    /// 测试用户 cmdKey（UUID 123e4567-e89b-12d3-a456-426614174000）
    auto test_user_key() -> user_key
    {
        std::array<std::uint8_t, 16> uuid_bytes{};
        codec::parse_uuid("123e4567-e89b-12d3-a456-426614174000", uuid_bytes);
        return user_key{codec::cmd_key_from_uuid(uuid_bytes)};
    }

    /// 模拟客户端：构造首包 → 写数据块
    net::awaitable<void> DoClient(
        psm::transport::shared_transmission transport,
        const std::array<std::uint8_t, 16> &cmd_key,
        const std::string &payload, bool *ok)
    {
        try
        {
            // 1. 构造指令头
            codec::request_header header;
            header.version = version;
            header.request_nonce.fill(0x11);
            header.request_key.fill(0x22);
            header.response_header = 0x77;
            header.option = static_cast<std::uint8_t>(option::chunk_stream)
                | static_cast<std::uint8_t>(option::chunk_masking);
            header.security = static_cast<std::uint8_t>(security::aes_128_gcm);
            header.command = static_cast<std::uint8_t>(command::tcp);
            header.destination = psm::protocol::common::domain_address{
                .length = 11,
                .value = []{ std::array<char, 255> v{}; std::memcpy(v.data(), "example.com", 11); return v; }()};
            header.port = 443;

            // 2. 密封首包并发送（只写有效长度：16+18+8+used+16）
            std::array<std::uint8_t, 256> packet{};
            const auto seal_ec = codec::seal_request(
                std::span<const std::uint8_t, 16>(cmd_key.data(), 16), header, packet);
            if (psm::fault::failed(seal_ec))
            {
                *ok = false;
                co_return;
            }
            const auto used = 38U + 4U + 11U + 4U; // 基础 + domain(4+11) + fnv
            const auto wire_len = 16U + 18U + 8U + used + 16U;
            std::error_code ec;
            co_await transport->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(packet.data()), wire_len), ec);
            if (ec)
            {
                *ok = false;
                co_return;
            }

            // 3. 读取 38 字节响应头（AEAD 双段 GCM）
            std::array<std::byte, 38> resp{};
            std::size_t got = 0;
            while (got < resp.size())
            {
                const auto n = co_await transport->async_read_some(
                    std::span<std::byte>(resp.data() + got, resp.size() - got), ec);
                if (ec || n == 0)
                {
                    *ok = false;
                    co_return;
                }
                got += n;
            }

            // 4. 客户端写数据块（请求侧密钥）
            codec::write_stream writer(codec::stream_params{
                .transport = transport.get(),
                .key = header.request_key,
                .nonce = header.request_nonce,
                .option = header.option,
                .security = header.security});
            co_await writer.write_chunk(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
            if (ec)
            {
                *ok = false;
                co_return;
            }

            // 5. 读取回显（响应侧密钥）
            std::array<std::uint8_t, 16> resp_key{};
            std::array<std::uint8_t, 16> resp_nonce{};
            std::array<std::uint8_t, 32> key_hash{};
            std::array<std::uint8_t, 32> nonce_hash{};
            EVP_Digest(header.request_key.data(), 16, key_hash.data(), nullptr, EVP_sha256(), nullptr);
            EVP_Digest(header.request_nonce.data(), 16, nonce_hash.data(), nullptr, EVP_sha256(), nullptr);
            std::memcpy(resp_key.data(), key_hash.data(), 16);
            std::memcpy(resp_nonce.data(), nonce_hash.data(), 16);

            codec::read_stream reader(codec::stream_params{
                .transport = transport.get(),
                .key = resp_key,
                .nonce = resp_nonce,
                .option = header.option,
                .security = header.security});
            std::array<std::byte, 4096> echo{};
            const auto n = co_await reader.read_chunk(echo, ec);
            *ok = !ec && n == payload.size()
                && std::string_view(reinterpret_cast<const char *>(echo.data()), n) == payload;
        }
        catch (const std::exception &)
        {
            *ok = false;
        }
        co_return;
    }

    /// 服务端：make_conn + handshake + 读块回显
    net::awaitable<void> DoServer(
        psm::transport::shared_transmission transport, const std::string &payload, bool *ok)
    {
        try
        {
            config cfg;
            cfg.enable_tcp = true;
            cfg.enable_udp = true;
            auto agent = make_conn(std::move(transport), cfg, {test_user_key()});

            auto [ec, req] = co_await agent->handshake();
            if (psm::fault::failed(ec))
            {
                *ok = false;
                co_return;
            }
            if (req.command != static_cast<std::uint8_t>(command::tcp))
            {
                *ok = false;
                co_return;
            }

            std::array<std::byte, 4096> buf{};
            std::error_code read_ec;
            const auto n = co_await agent->async_read_some(buf, read_ec);
            if (read_ec || n == 0)
            {
                *ok = false;
                co_return;
            }

            std::error_code write_ec;
            co_await agent->async_write_some(std::span<const std::byte>(buf.data(), n), write_ec);
            *ok = !write_ec;
        }
        catch (const std::exception &)
        {
            *ok = false;
        }
        co_return;
    }
} // namespace

TEST(VmessConnEcho, TcpEchoRoundtrip)
{
    net::io_context ioc;
    auto [client_trans, server_trans] = make_pair_transport(ioc);

    const std::string payload = "hello vmess server";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    auto key = test_user_key();

    net::co_spawn(ioc, DoServer(server_trans, payload, server_ok.get()), net::detached);
    net::co_spawn(ioc, DoClient(client_trans, key.cmd_key, payload, client_ok.get()),
                  [&](const std::exception_ptr &) { ioc.stop(); });

    ioc.run();
    EXPECT_TRUE(*server_ok);
    EXPECT_TRUE(*client_ok);
}

TEST(VmessConnEcho, WrongKeyRejected)
{
    net::io_context ioc;
    auto [client_trans, server_trans] = make_pair_transport(ioc);

    auto server_ok = std::make_shared<bool>(true);
    auto key = test_user_key();
    key.cmd_key.fill(0xDE); // 错误密钥

    // 服务端：认证失败应快速返回错误（而非挂起）
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        config cfg;
        cfg.enable_tcp = true;
        auto agent = make_conn(std::move(server_trans), cfg, {test_user_key()});
        auto [ec, req] = co_await agent->handshake();
        *server_ok = psm::fault::failed(ec);
        (void)req;
    }, net::detached);

    // 客户端：发一个用错误密钥密封的首包后关闭
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        codec::request_header header;
        header.version = version;
        header.request_nonce.fill(0x01);
        header.request_key.fill(0x02);
        header.response_header = 0x55;
        header.option = static_cast<std::uint8_t>(option::chunk_stream);
        header.security = static_cast<std::uint8_t>(security::aes_128_gcm);
        header.command = static_cast<std::uint8_t>(command::tcp);
        header.destination = psm::protocol::common::ipv4_address{{8, 8, 8, 8}};
        header.port = 53;

        std::array<std::uint8_t, 256> packet{};
        codec::seal_request(
            std::span<const std::uint8_t, 16>(key.cmd_key.data(), 16), header, packet);
        const auto used = 38U + 7U + 4U; // 基础 + ipv4(7) + fnv
        const auto wire_len = 16U + 18U + 8U + used + 16U;
        std::error_code ec;
        co_await client_trans->async_write_some(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(packet.data()), wire_len), ec);
        client_trans->close();
    }, net::detached);

    ioc.run();
    // 认证失败：handshake 返回错误
    EXPECT_TRUE(*server_ok);
}
