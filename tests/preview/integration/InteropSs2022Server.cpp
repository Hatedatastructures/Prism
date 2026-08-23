/**
 * @file InteropSs2022Server.cpp
 * @brief SS2022 互操作测试：C++ common 服务端 ← Go 真实客户端（sing-shadowsocks v0.2.12）
 * @details 用 tests/common/shadowsocks2022 的纯逻辑编解码 + Boost.Asio socket：
 *          1. TCP 监听
 *          2. 解析握手首包（salt + 固定头 + 变长头）
 *          3. 回服务端响应（server salt + 固定头 + 空块）
 *          4. 循环读取 chunk → 解密 → 加密 echo 回包
 * @param argv[1] 监听地址（默认 127.0.0.1:19080）
 */

#include <boost/asio.hpp>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>
#include <vector>

#include <common/protocols/shadowsocks2022/codec.hpp>

namespace ss = preview::shadowsocks2022;

namespace net = boost::asio;

int main(const int argc, char *argv[])
{
    const std::string listen_addr = argc > 1 ? argv[1] : "127.0.0.1:19080";

    // PSK（与 configuration.json 一致）
    std::array<std::uint8_t, 16> psk{0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                                     0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};

    try
    {
        net::io_context ioc;
        std::string host;
        std::uint16_t port = 0;
        const auto colon = listen_addr.find_last_of(':');
        if (colon == std::string::npos)
        {
            std::fprintf(stderr, "bad listen address: %s\n", listen_addr.c_str());
            return 1;
        }
        host = listen_addr.substr(0, colon);
        port = static_cast<std::uint16_t>(std::stoi(listen_addr.substr(colon + 1)));
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::make_address(host), port));
        net::ip::tcp::socket sock(ioc);
        acceptor.accept(sock);

        const auto now = static_cast<std::uint64_t>(std::time(nullptr));

        // 读取握手：salt 16 + 固定头密文 43，再从固定头解析变长头长度动态读取
        std::array<std::uint8_t, 16 + ss::fixed_hdr_size> head{};
        net::read(sock, net::buffer(head), net::transfer_exactly(head.size()));
        const auto probe_key = ss::session_key(psk, std::span<const std::uint8_t>(head).first(16), 16);
        ss::chunk_codec probe_codec(probe_key);
        const auto fixed_plain =
            probe_codec.open_raw(std::span<const std::uint8_t>(head).subspan(16, ss::fixed_hdr_size));
        if (fixed_plain.size() != ss::fixed_hdr_plain || fixed_plain[0] != ss::header_type_client)
        {
            std::fprintf(stderr, "FAIL: fixed header decrypt\n");
            return 1;
        }
        const auto var_len = static_cast<std::size_t>((fixed_plain[9] << 8) | fixed_plain[10]);
        std::vector<std::uint8_t> var_enc(var_len + ss::aead_tag_len);
        net::read(sock, net::buffer(var_enc), net::transfer_exactly(var_enc.size()));
        const auto var_plain = probe_codec.open_raw(var_enc);
        if (var_plain.empty())
        {
            std::fprintf(stderr, "FAIL: var header decrypt\n");
            return 1;
        }
        ss::address dst;
        std::span<const std::uint8_t> payload;
        if (ss::parse_var_header(var_plain, dst, payload) != preview::error::none)
        {
            std::fprintf(stderr, "FAIL: handshake parse\n");
            return 1;
        }
        std::printf("server: handshake ok -> %s:%u\n", dst.host.c_str(), dst.port);

        // 服务端响应按 SS2022 writeResponse 语义：首次发送数据时才构造，
        // 响应固定头（type + ts + requestSalt + payloadLen）后紧跟裸块 payload。
        std::array<std::uint8_t, 16> server_salt{};
        std::random_device rd;
        for (auto &b : server_salt)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto resp_key = ss::session_key(psk, server_salt, 16);
        ss::chunk_codec resp_codec(resp_key);
        std::array<std::uint8_t, ss::resp_fixed_hdr_plain> resp_fixed{};
        resp_fixed[0] = ss::header_type_server;
        for (std::size_t i = 0; i < 8; ++i)
        {
            resp_fixed[1 + i] =
                static_cast<std::uint8_t>((now >> (56 - static_cast<unsigned>(i) * 8)) & 0xFF);
        }
        // requestSalt 回显客户端 salt（head 前 16 字节）
        std::memcpy(resp_fixed.data() + 9, head.data(), 16);
        bool responded{false};

        // 会话密钥（客户端→服务端方向，用客户端 salt）+ chunk 编解码
        auto key = ss::session_key(psk, std::span<const std::uint8_t>(head).first(16), 16);
        // 客户端握手消耗 nonce 0,1，数据从 2 起
        ss::chunk_codec codec(key, 2);
        // 服务端→客户端方向：首次响应消耗 nonce 0/1（固定头 + payload），后续 echo 从 2 起
        ss::chunk_codec echo_codec(resp_key, 2);

        // 循环读取并 echo（最多 16 块）
        for (int i = 0; i < 16; ++i)
        {
            // Go 客户端按块发送：[len 块 18B][载荷块]
            std::array<std::uint8_t, ss::len_block_size> len_enc{};
            boost::system::error_code ec;
            const auto n = net::read(sock, net::buffer(len_enc), net::transfer_exactly(len_enc.size()), ec);
            if (ec || n == 0)
            {
                break;
            }
            const auto len_opt = codec.open_len(len_enc);
            if (!len_opt)
            {
                std::fprintf(stderr, "FAIL: decrypt chunk length\n");
                return 1;
            }
            // 密文 = 明文长度 + 16B 认证标签
            std::vector<std::uint8_t> body_enc(*len_opt + ss::aead_tag_len);
            net::read(sock, net::buffer(body_enc), net::transfer_exactly(body_enc.size()));
            const auto plain = codec.open_payload(body_enc);
            if (plain.empty())
            {
                std::fprintf(stderr, "FAIL: decrypt chunk body\n");
                return 1;
            }
            // echo 回包：首次发送 = writeResponse（响应固定头 + 裸块 payload），
            // 后续 = chunk 流（首次响应已消耗 nonce 0/1，数据面从 2 起）
            if (!responded)
            {
                resp_fixed[25] = static_cast<std::uint8_t>((plain.size() >> 8) & 0xFF);
                resp_fixed[26] = static_cast<std::uint8_t>(plain.size() & 0xFF);
                const auto resp_fixed_enc = resp_codec.seal_raw(resp_fixed);
                const auto payload_enc = resp_codec.seal_raw(plain);
                std::vector<std::uint8_t> resp;
                resp.reserve(server_salt.size() + resp_fixed_enc.size() + payload_enc.size());
                resp.insert(resp.end(), server_salt.begin(), server_salt.end());
                resp.insert(resp.end(), resp_fixed_enc.begin(), resp_fixed_enc.end());
                resp.insert(resp.end(), payload_enc.begin(), payload_enc.end());
                net::write(sock, net::buffer(resp));
                responded = true;
            }
            else
            {
                const auto back = echo_codec.seal(plain);
                net::write(sock, net::buffer(back));
            }
        }
        sock.close();
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
    return 0;
}
