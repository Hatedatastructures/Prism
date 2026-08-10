/**
 * @file WsE2E.cpp
 * @brief WebSocket 传输端到端测试
 * @details 模拟 WS 客户端：
 *          1. HTTP 升级请求（Sec-WebSocket-Key）
 *          2. 验证 101 + Sec-WebSocket-Accept
 *          3. 发送 masked binary 帧
 *          4. 服务端 ws transport 解帧（去掩码）→ echo
 *          5. 客户端验证 echo 帧
 */

#include <prism/foundation/foundation.hpp>
#include <prism/handshake/ws/transport.hpp>
#include <prism/handshake/ws/codec.hpp>
#include <prism/net/transport/reliable.hpp>

#include <gtest/gtest.h>

#include <memory>

namespace
{
    namespace ws = psm::handshake::ws;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /// 客户端：升级 + masked 帧发送 + echo 验证
    net::awaitable<void> DoWsClient(psm::transport::shared_transmission transport,
                                    const std::string &payload, std::shared_ptr<bool> ok)
    {
        try
        {
            // 1. 升级请求
            std::string request =
                "GET /ws HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n";
            std::error_code ec;
            co_await psm::transport::async_write(*transport, std::span<const std::byte>(reinterpret_cast<const std::byte *>(request.data()), request.size()), ec);
            if (ec)
            {
                *ok = false;
                co_return;
            }

            // 2. 读 101 响应
            std::array<std::byte, 1024> resp{};
            std::size_t got = 0;
            std::string_view resp_text;
            while (got < resp.size())
            {
                const auto n = co_await transport->async_read_some(
                    std::span<std::byte>(resp.data() + got, resp.size() - got), ec);
                if (ec || n == 0)
                    break;
                got += n;
                resp_text = std::string_view(reinterpret_cast<const char *>(resp.data()), got);
                if (resp_text.find("\r\n\r\n") != std::string_view::npos)
                    break;
            }
            const bool v101 = resp_text.find("101 Switching Protocols") != std::string_view::npos;
            const bool vacc = resp_text.find("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string_view::npos;
            if (!v101 || !vacc)
            {
                *ok = false;
                co_return;
            }

            // 3. 发送 masked binary 帧
            const std::array<std::uint8_t, 4> mask{0x11, 0x22, 0x33, 0x44};
            std::vector<std::byte> frame;
            frame.push_back(std::byte{0x82}); // FIN + binary
            frame.push_back(std::byte{0x80 | static_cast<std::uint8_t>(payload.size())}); // MASK + len
            for (const auto m : mask)
                frame.push_back(static_cast<std::byte>(m));
            for (std::size_t i = 0; i < payload.size(); ++i)
                frame.push_back(static_cast<std::byte>(
                    static_cast<std::uint8_t>(payload[i]) ^ mask[i % 4]));
            co_await psm::transport::async_write(*transport, frame, ec);
            if (ec)
            {
                *ok = false;
                co_return;
            }

            // 4. 读 echo 帧（服务端不掩码）
            std::array<std::byte, 4096> buf{};
            std::size_t total = 0;
            while (total < payload.size() + 2)
            {
                const auto n = co_await transport->async_read_some(
                    std::span<std::byte>(buf.data() + total, buf.size() - total), ec);
                if (ec || n == 0)
                    break;
                total += n;
            }

            // 解析帧
            ws::codec::frame_header header;
            if (!ws::codec::parse_frame_header(std::span<const std::byte>(buf.data(), total), header))
            {
                *ok = false;
                co_return;
            }
            *ok = header.payload_len == payload.size()
                && std::string_view(reinterpret_cast<const char *>(buf.data() + header.header_len),
                                    header.payload_len) == payload;
        }
        catch (const std::exception &)
        {
            *ok = false;
        }
        co_return;
    }

    /// 服务端：升级响应 + ws transport echo
    net::awaitable<void> DoWsServer(psm::transport::shared_transmission transport,
                                    const std::string &payload, std::shared_ptr<bool> server_ok)
    {
        try
        {
            // 读 HTTP 请求
            std::array<std::byte, 2048> req{};
            std::size_t got = 0;
            while (got < req.size())
            {
                std::error_code ec;
                const auto n = co_await transport->async_read_some(
                    std::span<std::byte>(req.data() + got, req.size() - got), ec);
                if (ec || n == 0)
                    break;
                got += n;
                const std::string_view text(reinterpret_cast<const char *>(req.data()), got);
                if (text.find("\r\n\r\n") != std::string_view::npos)
                    break;
            }

            // 响应 101
            const std::string response =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                "\r\n";
            std::error_code w_ec;
            co_await psm::transport::async_write(*transport, std::span<const std::byte>(reinterpret_cast<const std::byte *>(response.data()), response.size()), w_ec);
            if (w_ec)
            {
                *server_ok = false;
                co_return;
            }

            // WS 传输 echo
            auto ws_transport = ws::make_transport(transport);
            std::array<std::byte, 4096> buf{};
            std::error_code r_ec;
            const auto n = co_await ws_transport->async_read_some(buf, r_ec);
            if (r_ec || n == 0)
            {
                *server_ok = false;
                co_return;
            }
            co_await ws_transport->async_write_some(std::span<const std::byte>(buf.data(), n), w_ec);
            *server_ok = !w_ec;
        }
        catch (const std::exception &)
        {
            *server_ok = false;
        }
        co_return;
    }
} // namespace

TEST(WsE2E, MaskedFrameEcho)
{
    net::io_context ioc;

    tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto ep = acceptor.local_endpoint();

    psm::transport::shared_transmission server_trans;
    psm::transport::shared_transmission client_trans;
    auto pair_ready = std::make_shared<bool>(false);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        auto sock = co_await acceptor.async_accept(net::use_awaitable);
        server_trans = psm::transport::make_reliable(std::move(sock));
        *pair_ready = true;
    }, net::detached);
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        tcp::socket sock(ioc);
        co_await sock.async_connect(ep, net::use_awaitable);
        client_trans = psm::transport::make_reliable(std::move(sock));
    }, net::detached);

    const std::string payload = "websocket echo payload";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        while (!*pair_ready || !client_trans)
        {
            net::steady_timer t(ioc);
            t.expires_after(std::chrono::milliseconds(10));
            co_await t.async_wait(net::use_awaitable);
        }
        net::co_spawn(ioc, DoWsClient(client_trans, payload, client_ok), net::detached);
        co_await DoWsServer(server_trans, payload, server_ok);

        net::steady_timer done(ioc);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!*client_ok && std::chrono::steady_clock::now() < deadline)
        {
            done.expires_after(std::chrono::milliseconds(20));
            co_await done.async_wait(net::use_awaitable);
        }
        client_trans->close();
        server_trans->close();
        ioc.stop();
    }, net::detached);

    ioc.run();
    EXPECT_TRUE(*server_ok) << "ws: server echo";
    EXPECT_TRUE(*client_ok) << "ws: client verified masked frame echo";
}
