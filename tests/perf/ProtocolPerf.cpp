// @file ProtocolPerf.cpp
// @brief 多协议客户端性能测量工具
// @details 连接运行中的 Prism 代理（默认 127.0.0.1:8081），以
// trojan / vless / shadowsocks2022 协议建立隧道，转发到本地后端
// HTTP 服务（默认 127.0.0.1:18080），测量上行/下行吞吐。
// 上行：向隧道写入 size_mb 原始字节；下行：GET /bigfile.bin 读至关闭。
// 用法：ProtocolPerf <protocol> <mode> <size_mb> [conns]
//   protocol: http | socks5 | trojan | trojan-tls | vless | vless-tls | ss2022
//   mode:     up | down
// @note 需先启动 Prism（configuration.json 中的凭据硬编码于此）；
//       -tls 变体经标准 TLS 内层（Native TLS 路径，同 mihomo 客户端行为）
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/base64.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace net = boost::asio;

namespace
{
    constexpr std::string_view k_proxy_host = "127.0.0.1";
    constexpr std::uint16_t k_proxy_port = 8081;
    constexpr std::string_view k_backend = "127.0.0.1";
    constexpr std::uint16_t k_backend_port = 18080;   // http.server（下行）
    constexpr std::uint16_t k_blackhole_port = 18081; // 黑洞 TCP 服务（上行）

    // 与 src/configuration.json 保持一致
    constexpr std::string_view k_password = "prism";
    constexpr std::string_view k_uuid_str = "123e4567-e89b-12d3-a456-426614174000";
    constexpr std::string_view k_psk_b64 = "5n5ESu953i/pjIp02oZvHA==";

    constexpr std::size_t k_write_chunk = 65536;

    // UUID 字符串（含连字符）转 16 字节二进制
    auto uuid_to_bytes(const std::string_view uuid) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> bytes{};
        std::size_t out = 0;
        for (const char c : uuid)
        {
            if (c == '-')
                continue;
            auto nibble = [c]() -> std::uint8_t
            {
                if (c >= '0' && c <= '9')
                    return static_cast<std::uint8_t>(c - '0');
                return static_cast<std::uint8_t>(c - 'a' + 10);
            };
            const auto v = nibble();
            if (out % 2 == 0)
                bytes[out / 2] = static_cast<std::uint8_t>(v << 4);
            else
                bytes[out / 2] |= v;
            ++out;
        }
        return bytes;
    }

    auto port_be(const std::uint16_t port) -> std::array<std::uint8_t, 2>
    {
        return {static_cast<std::uint8_t>(port >> 8),
                static_cast<std::uint8_t>(port & 0xFF)};
    }

    template <typename Stream>
    auto write_all(Stream &sock, const std::uint8_t *data, const std::size_t len)
        -> bool
    {
        std::size_t off = 0;
        while (off < len)
        {
            const auto n = net::write(sock, net::buffer(data + off, len - off));
            if (n == 0)
                return false;
            off += n;
        }
        return true;
    }

    template <typename Stream>
    auto read_all(Stream &sock, std::uint8_t *data, const std::size_t len)
        -> bool
    {
        std::size_t off = 0;
        while (off < len)
        {
            boost::system::error_code ec;
            const auto n = sock.read_some(net::buffer(data + off, len - off), ec);
            if (ec || n == 0)
                return false;
            off += n;
        }
        return true;
    }

    // === trojan ===

    template <typename Stream>
    void trojan_handshake(Stream &sock, const std::uint16_t backend_port)
    {
        // SHA224("prism") 56 hex + CRLF + CMD + ATYP + IPv4 + PORT + CRLF
        const auto cred = psm::crypto::sha224(k_password);
        const auto port = port_be(backend_port);
        std::vector<std::uint8_t> frame;
        frame.reserve(68);
        frame.insert(frame.end(), cred.begin(), cred.end());
        const std::uint8_t tail[] = {'\r', '\n', 0x01, 0x01, 127, 0, 0, 1,
                                     port[0], port[1], '\r', '\n'};
        frame.insert(frame.end(), tail, tail + sizeof(tail));
        write_all(sock, frame.data(), frame.size());
    }

    // === vless ===

    template <typename Stream>
    void vless_handshake(Stream &sock, const std::uint16_t backend_port)
    {
        // Version + UUID(16) + AddnlLen(0) + CMD + PORT + ATYP + IPv4
        const auto uuid = uuid_to_bytes(k_uuid_str);
        const auto port = port_be(backend_port);
        std::array<std::uint8_t, 26> frame{
            0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x01, port[0], port[1], 0x01, 127, 0, 0, 1};
        std::memcpy(frame.data() + 1, uuid.data(), 16);
        write_all(sock, frame.data(), frame.size());

        // 服务端响应：1 字节版本
        std::array<std::uint8_t, 1> resp{};
        read_all(sock, resp.data(), resp.size());
    }

    // === socks5 ===

    template <typename Stream>
    void socks5_handshake(Stream &sock, const std::uint16_t backend_port)
    {
        // greeting：无认证 + 密码认证
        const std::uint8_t greeting[] = {0x05, 0x01, 0x02};
        write_all(sock, greeting, sizeof(greeting));
        std::array<std::uint8_t, 2> gresp{};
        if (!read_all(sock, gresp.data(), gresp.size()))
            throw std::runtime_error("socks5 greeting failed");

        // RFC 1929 认证
        const std::string_view user = "prism";
        const std::string_view pass = "prism";
        std::vector<std::uint8_t> auth;
        auth.push_back(0x01);
        auth.push_back(static_cast<std::uint8_t>(user.size()));
        auth.insert(auth.end(), user.begin(), user.end());
        auth.push_back(static_cast<std::uint8_t>(pass.size()));
        auth.insert(auth.end(), pass.begin(), pass.end());
        write_all(sock, auth.data(), auth.size());
        std::array<std::uint8_t, 2> aresp{};
        if (!read_all(sock, aresp.data(), aresp.size()) || aresp[1] != 0x00)
            throw std::runtime_error("socks5 auth failed");

        // CONNECT
        const auto port = port_be(backend_port);
        const std::uint8_t connect[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                                        port[0], port[1]};
        write_all(sock, connect, sizeof(connect));
        std::array<std::uint8_t, 10> cresp{};
        if (!read_all(sock, cresp.data(), cresp.size()) || cresp[1] != 0x00)
            throw std::runtime_error("socks5 connect failed");
    }

    // === http CONNECT ===

    template <typename Stream>
    void http_handshake(Stream &sock, const std::uint16_t backend_port)
    {
        char port_buf[8];
        const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), backend_port);
        const std::string port_str(port_buf, std::distance(port_buf, pe));
        const std::string_view cred = "prism:prism";
        const auto b64 = psm::crypto::base64_encode(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(cred.data()), cred.size()));

        std::string req = "CONNECT 127.0.0.1:" + port_str + " HTTP/1.1\r\n"
                          "Host: 127.0.0.1:" + port_str + "\r\n"
                          "Proxy-Authorization: Basic " + std::string(b64) + "\r\n\r\n";
        write_all(sock, reinterpret_cast<const std::uint8_t *>(req.data()), req.size());

        std::string resp;
        std::array<std::uint8_t, 256> buf{};
        while (resp.find("\r\n\r\n") == std::string::npos)
        {
            boost::system::error_code ec;
            const auto n = sock.read_some(net::buffer(buf), ec);
            if (ec || n == 0)
                throw std::runtime_error("http CONNECT response failed");
            resp.append(reinterpret_cast<const char *>(buf.data()), n);
        }
        if (resp.find(" 200 ") == std::string::npos)
            throw std::runtime_error("http CONNECT rejected: " + resp.substr(0, 64));
    }

    // === TLS 内层（Native TLS 路径）===

    auto make_tls_stream(net::io_context &ioc, net::ip::tcp::socket &&sock)
        -> boost::asio::ssl::stream<net::ip::tcp::socket>
    {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
        boost::asio::ssl::stream<net::ip::tcp::socket> stream(std::move(sock), ctx);
        SSL_set_tlsext_host_name(stream.native_handle(), "www.bing.com");
        boost::system::error_code ec;
        stream.handshake(boost::asio::ssl::stream_base::client, ec);
        if (ec)
            throw std::runtime_error("TLS handshake failed: " + ec.message());
        return stream;
    }

    // 分段计时输出（stage 调试用）：每段 us
    struct stage_times
    {
        std::uint64_t connect_us{0};
        std::uint64_t handshake_us{0};
        std::uint64_t transfer_us{0};
        std::uint64_t max_block_us{0};
        std::uint64_t max_block_idx{0};
    };

    template <typename Stream>
    auto run_upload_impl(Stream &sock, const std::size_t size_bytes, stage_times *stages = nullptr) -> std::uint64_t
    {
        std::vector<std::uint8_t> buf(k_write_chunk, 0xAB);
        std::size_t remaining = size_bytes;
        std::uint64_t idx = 0;
        while (remaining > 0)
        {
            const auto n = std::min(remaining, buf.size());
            const auto t0 = std::chrono::steady_clock::now();
            if (!write_all(sock, buf.data(), n))
                throw std::runtime_error("upload write failed");
            const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
            if (stages && us > stages->max_block_us)
            {
                stages->max_block_us = us;
                stages->max_block_idx = idx;
            }
            remaining -= n;
            ++idx;
        }
        return size_bytes;
    }

    template <typename Stream>
    auto run_download_impl(Stream &sock) -> std::uint64_t
    {
        std::uint64_t received = 0;
        std::array<std::uint8_t, 65536> buf{};
        while (true)
        {
            boost::system::error_code ec;
            const auto n = sock.read_some(net::buffer(buf), ec);
            if (ec || n == 0)
                break;
            received += n;
        }
        return received;
    }

    // === shadowsocks 2022 ===

    auto derive_session_key(const std::vector<std::uint8_t> &psk,
                            const std::vector<std::uint8_t> &salt) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> material = psk;
        material.insert(material.end(), salt.begin(), salt.end());
        return psm::crypto::derive_key("shadowsocks 2022 session subkey", material, 16);
    }

    void ss2022_handshake(net::ip::tcp::socket &sock,
                          std::unique_ptr<psm::crypto::aead_context> &enc_ctx,
                          std::unique_ptr<psm::crypto::aead_context> &dec_ctx,
                          const std::uint16_t backend_port)
    {
        const auto decoded = psm::crypto::base64_decode(k_psk_b64);
        if (decoded.size() != 16)
        {
            std::cerr << "invalid psk" << std::endl;
            std::exit(1);
        }
        const std::vector<std::uint8_t> psk_vec(decoded.begin(), decoded.end());

        // 1. 生成并发送 client salt（随机源避免两次运行相同 salt 触发重放检测；
        //    首字节避开 0x05/0x16，防止被 probe 误判为 socks5/TLS）
        std::vector<std::uint8_t> client_salt(16);
        {
            std::random_device rd;
            for (auto &b : client_salt)
                b = static_cast<std::uint8_t>(rd());
            while (client_salt[0] == 0x05 || client_salt[0] == 0x16)
                client_salt[0] = static_cast<std::uint8_t>(rd());
        }
        if (!write_all(sock, client_salt.data(), client_salt.size()))
            throw std::runtime_error("write salt failed");

        // 2. 派生加密上下文
        const auto enc_key = derive_session_key(psk_vec, client_salt);
        enc_ctx = std::make_unique<psm::crypto::aead_context>(
            psm::crypto::aead_cipher::aes_128_gcm, enc_key);

        // 3. 加密固定头：type(1) + timestamp(8) + varHeaderLen(2)
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        std::array<std::uint8_t, 11> fixed_plain{};
        fixed_plain[0] = 0x00; // request_type
        const auto ts = static_cast<std::uint64_t>(now);
        for (std::size_t i = 0; i < 8; ++i)
            fixed_plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        fixed_plain[9] = 0x00;  // varHeaderLen 高字节
        fixed_plain[10] = 0x09; // varHeaderLen 低字节（9 字节变长头）
        std::array<std::uint8_t, 27> fixed_enc{};
        if (enc_ctx->seal(fixed_enc, fixed_plain) != psm::fault::code::success)
            throw std::runtime_error("seal fixed header failed");
        if (!write_all(sock, fixed_enc.data(), fixed_enc.size()))
            throw std::runtime_error("write fixed header failed");

        // 4. 加密变长头：atyp(1) + IPv4(4) + port(2) + paddingLen(2)
        const auto port = port_be(backend_port);
        std::array<std::uint8_t, 9> var_plain{0x01, 127, 0, 0, 1,
                                              port[0], port[1], 0x00, 0x00};
        std::array<std::uint8_t, 25> var_enc{};
        if (enc_ctx->seal(var_enc, var_plain) != psm::fault::code::success)
            throw std::runtime_error("seal var header failed");
        if (!write_all(sock, var_enc.data(), var_enc.size()))
            throw std::runtime_error("write var header failed");

        // 5. 读服务端响应：server_salt(16) + seal(27B) + seal(0B) = 75B
        std::array<std::uint8_t, 75> resp{};
        if (!read_all(sock, resp.data(), resp.size()))
            throw std::runtime_error("read response failed");
        const std::vector<std::uint8_t> server_salt(resp.begin(), resp.begin() + 16);
        const auto dec_key = derive_session_key(psk_vec, server_salt);
        dec_ctx = std::make_unique<psm::crypto::aead_context>(
            psm::crypto::aead_cipher::aes_128_gcm, dec_key);
        std::array<std::uint8_t, 27> resp_fixed{};
        if (dec_ctx->open(resp_fixed, std::span<const std::uint8_t>(resp.data() + 16, 43))
            != psm::fault::code::success)
            throw std::runtime_error("open response fixed header failed");
        std::array<std::uint8_t, 0> resp_empty{};
        if (dec_ctx->open(resp_empty, std::span<const std::uint8_t>(resp.data() + 59, 16))
            != psm::fault::code::success)
            throw std::runtime_error("open response empty block failed");
    }

    void ss2022_write(net::ip::tcp::socket &sock, psm::crypto::aead_context &enc_ctx,
                      const std::uint8_t *data, const std::size_t len)
    {
        std::size_t off = 0;
        while (off < len)
        {
            const auto chunk = std::min<std::size_t>(len - off, 0x3FFF);
            const std::array<std::uint8_t, 2> len_plain{
                static_cast<std::uint8_t>(chunk >> 8),
                static_cast<std::uint8_t>(chunk & 0xFF)};
            std::array<std::uint8_t, 18> len_enc{};
            if (enc_ctx.seal(len_enc, len_plain) != psm::fault::code::success)
                throw std::runtime_error("seal length block failed");
            std::vector<std::uint8_t> pay_enc(16 + chunk);
            if (enc_ctx.seal(pay_enc, std::span<const std::uint8_t>(data + off, chunk))
                != psm::fault::code::success)
                throw std::runtime_error("seal payload block failed");
            std::vector<std::uint8_t> combined;
            combined.reserve(len_enc.size() + pay_enc.size());
            combined.insert(combined.end(), len_enc.begin(), len_enc.end());
            combined.insert(combined.end(), pay_enc.begin(), pay_enc.end());
            if (!write_all(sock, combined.data(), combined.size()))
                throw std::runtime_error("write chunk failed");
            off += chunk;
        }
    }

    // === 上行 ===

    // 绑定本地地址（多 worker 验证：不同源 IP → 不同亲和性 → 不同 worker）
    auto bind_local(net::ip::tcp::socket &sock, const std::string_view bind_addr) -> void
    {
        if (bind_addr.empty())
            return;
        boost::system::error_code bec;
        sock.open(net::ip::tcp::v4(), bec);
        if (bec)
        {
            std::cerr << "open failed: " << bec.message() << "\n";
            return;
        }
        sock.bind(net::ip::tcp::endpoint(net::ip::make_address(bind_addr), 0), bec);
        if (bec)
            std::cerr << "bind " << bind_addr << " failed: " << bec.message() << "\n";
    }

    auto run_upload(const std::string_view protocol, const std::size_t size_bytes, const std::string_view proxy_host, const std::uint16_t backend_port, stage_times *stages = nullptr, const std::string_view bind_addr = {})
        -> std::uint64_t
    {
        net::io_context ioc;
        net::ip::tcp::socket sock(ioc);
        bind_local(sock, bind_addr);
        auto t0 = std::chrono::steady_clock::now();
        sock.connect(net::ip::tcp::endpoint(
            net::ip::make_address(proxy_host), k_proxy_port));
        if (stages)
            stages->connect_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t0).count();

        const auto t_handshake0 = std::chrono::steady_clock::now();
        if (protocol == "ss2022")
        {
            std::unique_ptr<psm::crypto::aead_context> enc_ctx;
            std::unique_ptr<psm::crypto::aead_context> dec_ctx;
            ss2022_handshake(sock, enc_ctx, dec_ctx, backend_port);
            std::vector<std::uint8_t> buf(k_write_chunk, 0xAB);
            std::size_t remaining = size_bytes;
            while (remaining > 0)
            {
                const auto n = std::min(remaining, buf.size());
                ss2022_write(sock, *enc_ctx, buf.data(), n);
                remaining -= n;
            }
            if (stages)
            {
                const auto t2 = std::chrono::steady_clock::now();
                stages->handshake_us = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t_handshake0).count();
                stages->transfer_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t2).count();
            }
            return size_bytes;
        }

        if (protocol.ends_with("-tls"))
        {
            auto stream = make_tls_stream(ioc, std::move(sock));
            if (protocol == "trojan-tls")
                trojan_handshake(stream, backend_port);
            else
                vless_handshake(stream, backend_port);
            if (stages)
                stages->handshake_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t_handshake0).count();
            const auto r = run_upload_impl(stream, size_bytes, stages);
            if (stages)
                stages->transfer_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t_handshake0).count() - stages->handshake_us;
            return r;
        }

        if (protocol == "trojan")
            trojan_handshake(sock, backend_port);
        else if (protocol == "vless")
            vless_handshake(sock, backend_port);
        else if (protocol == "socks5")
            socks5_handshake(sock, backend_port);
        else if (protocol == "http")
            http_handshake(sock, backend_port);
        else
            throw std::runtime_error("unknown protocol: " + std::string(protocol));
        if (stages)
            stages->handshake_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_handshake0).count();
        const auto r = run_upload_impl(sock, size_bytes, stages);
        if (stages)
            stages->transfer_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_handshake0).count() - stages->handshake_us;
        return r;
    }

    // === 下行 ===

    auto run_download(const std::string_view protocol, const std::string_view file, const std::string_view proxy_host, const std::uint16_t backend_port, const std::string_view bind_addr = {})
        -> std::uint64_t
    {
        net::io_context ioc;
        net::ip::tcp::socket sock(ioc);
        bind_local(sock, bind_addr);
        sock.connect(net::ip::tcp::endpoint(
            net::ip::make_address(proxy_host), k_proxy_port));

        const std::string request =
            "GET " + std::string(file) + " HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nConnection: close\r\n\r\n";

        if (protocol == "ss2022")
        {
            std::unique_ptr<psm::crypto::aead_context> enc_ctx;
            std::unique_ptr<psm::crypto::aead_context> dec_ctx;
            ss2022_handshake(sock, enc_ctx, dec_ctx, backend_port);
            ss2022_write(sock, *enc_ctx,
                         reinterpret_cast<const std::uint8_t *>(request.data()), request.size());
            return run_download_impl(sock);
        }

        if (protocol.ends_with("-tls"))
        {
            auto stream = make_tls_stream(ioc, std::move(sock));
            if (protocol == "trojan-tls")
                trojan_handshake(stream, backend_port);
            else
                vless_handshake(stream, backend_port);
            write_all(stream, reinterpret_cast<const std::uint8_t *>(request.data()), request.size());
            return run_download_impl(stream);
        }

        if (protocol == "trojan")
            trojan_handshake(sock, backend_port);
        else if (protocol == "vless")
            vless_handshake(sock, backend_port);
        else if (protocol == "socks5")
            socks5_handshake(sock, backend_port);
        else if (protocol == "http")
            http_handshake(sock, backend_port);
        else
            throw std::runtime_error("unknown protocol: " + std::string(protocol));
        write_all(sock, reinterpret_cast<const std::uint8_t *>(request.data()), request.size());
        return run_download_impl(sock);
    }
} // namespace

auto main(const int argc, char **argv) -> int
{
    if (argc < 4)
    {
        std::cerr << "usage: ProtocolPerf <proto> <up|down> <size_mb> [conns] [file] [proxy_host] [rounds] [backend_port_base] [out_file]"
                  << std::endl;
        return 1;
    }

    const std::string_view protocol = argv[1];
    const std::string_view mode = argv[2];
    const auto size_mb = std::stoull(argv[3]);
    const auto conns = argc > 4 ? std::stoull(argv[4]) : 1;
    const std::string_view file = argc > 5 ? argv[5] : "/bigfile.bin";
    const std::string_view proxy_host = argc > 6 ? argv[6] : "127.0.0.1";
    const auto rounds = argc > 7 ? std::stoull(argv[7]) : 1;
    const auto backend_port_base = static_cast<std::uint16_t>(argc > 8 ? std::stoi(argv[8]) : 18080);
    const auto size_bytes = size_mb * 1024 * 1024;
    const std::string bind_base = argc > 10 ? argv[10] : "";

    std::ofstream out;
    std::mutex out_mtx;
    if (argc > 9)
        out.open(argv[9], std::ios::trunc);

    std::vector<std::thread> threads;
    threads.reserve(conns);
    std::vector<std::uint64_t> bytes(conns, 0);
    std::vector<double> avg_mb_s(conns, 0.0);
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < conns; ++i)
    {
        threads.emplace_back([i, protocol, mode, size_bytes, file, proxy_host, rounds,
                              backend_port_base, bind_base, &bytes, &avg_mb_s, &out, &out_mtx]
        {
            std::uint64_t total = 0;
            double sum_mb_s = 0.0;
            std::size_t ok_rounds = 0;
            // 上行固定连黑洞；下行按 conn 分散到 backend_port_base+i 个后端
            const auto bp = (mode == "up")
                                ? k_blackhole_port
                                : static_cast<std::uint16_t>(backend_port_base + i);
            // 可选：绑定不同本地 IP（127.0.0.(n+i)），使连接分到不同 worker
            std::string bind_addr;
            if (bind_base.size() > 0)
            {
                const auto dot = bind_base.rfind('.');
                if (dot != std::string_view::npos)
                {
                    const auto last = std::stoi(std::string(bind_base.substr(dot + 1)));
                    bind_addr = std::string(bind_base.substr(0, dot + 1))
                                + std::to_string(last + static_cast<int>(i));
                }
            }
            for (std::size_t r = 0; r < rounds; ++r)
            {
                const auto t0 = std::chrono::steady_clock::now();
                std::uint64_t n = 0;
                stage_times st{};
                try
                {
                    n = (mode == "up")
                            ? run_upload(protocol, size_bytes, proxy_host, bp, &st, bind_addr)
                            : run_download(protocol, file, proxy_host, bp, bind_addr);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "conn " << i << " round " << r << " failed: "
                              << e.what() << std::endl;
                }
                const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0)
                                    .count();
                if (n > 0)
                {
                    ++ok_rounds;
                    sum_mb_s += static_cast<double>(n) / 1048576.0
                                / (static_cast<double>(us) / 1e6);
                }
                {
                    std::lock_guard<std::mutex> lk(out_mtx);
                    if (out.is_open())
                        out << i << " " << r << " " << n << " " << us << " "
                            << st.connect_us << " " << st.handshake_us << " "
                            << st.transfer_us << " " << st.max_block_us << " "
                            << st.max_block_idx << "\n";
                }
                total += n;
            }
            bytes[i] = total;
            avg_mb_s[i] = ok_rounds ? sum_mb_s / static_cast<double>(ok_rounds) : 0.0;
        });
    }
    for (auto &t : threads)
        t.join();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - start)
                                .count();

    std::uint64_t total = 0;
    for (const auto b : bytes)
        total += b;
    double avg_all = 0.0;
    for (const auto a : avg_mb_s)
        avg_all += a;
    avg_all /= static_cast<double>(conns);
    const auto gbps = static_cast<double>(total) * 8 / 1000 / 1000 / 1000
                      / (static_cast<double>(elapsed_ms) / 1000);
    std::cout << protocol << " " << mode << " " << size_mb << "MB x" << conns
              << " rounds=" << rounds
              << ": avg=" << avg_all << " MB/s (per-round mean)"
              << " overall=" << (static_cast<double>(total) / 1024 / 1024 / (elapsed_ms / 1000.0))
              << " MB/s (" << gbps << " Gbps)" << std::endl;
    return 0;
}
