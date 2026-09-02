/**
 * @file InteropSs2022Client.cpp
 * @brief SS2022 互操作测试：C++ common 客户端 → Go 真实服务端（sing-shadowsocks）
 * @details 用 tests/common/shadowsocks2022 的纯逻辑编解码 + Boost.Asio socket：
 *          1. TCP 连接
 *          2. 构造握手首包（salt + 固定头 + 变长头）
 *          3. 加密 echo 载荷（chunk）
 *          4. 校验服务端响应（Server salt + 固定头 + 空块）
 *          5. 读取并解密 echo 回包
 * @param argv[1] 服务端地址（默认 127.0.0.1:19080）
 * @param argv[2] echo 服务器端口（默认 19090，客户端直连 echo 验证转发）
 */

#include <boost/asio.hpp>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include <preview/Protocols/Shadowsocks2022/Codec.hpp>

namespace ss = Preview::Shadowsocks2022;

namespace net = boost::asio;

int main(const int argc, char *argv[])
{
    const std::string server_addr = argc > 1 ? argv[1] : "127.0.0.1:19080";
    const std::string echo_addr = argc > 2 ? argv[2] : "127.0.0.1:19090";

    // PSK（与 configuration.json 一致）
    std::array<std::uint8_t, 16> psk{0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                                     0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};

    try
    {
        net::io_context ioc;

        // 解析服务端地址
        std::string host;
        std::uint16_t port = 0;
        const auto colon = server_addr.find_last_of(':');
        if (colon == std::string::npos)
        {
            std::fprintf(stderr, "bad Server Address: %s\n", server_addr.c_str());
            return 1;
        }
        host = server_addr.substr(0, colon);
        port = static_cast<std::uint16_t>(std::stoi(server_addr.substr(colon + 1)));
        net::ip::tcp::resolver Resolver(ioc);
        auto endpoints = Resolver.resolve(host, std::to_string(port));
        net::ip::tcp::socket sock(ioc);
        net::connect(sock, endpoints);

        // 构造握手（目标 = echo 服务器）
        std::random_device rd;
        std::array<std::uint8_t, 16> salt{};
        for (auto &b : salt)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto key = ss::SessionKey(psk, salt, 16);

        ss::Address dst;
        dst.Type = ss::AddressType::Ipv4;
        dst.Host = "127.0.0.1";
        dst.Port = static_cast<std::uint16_t>(std::stoi(echo_addr.substr(echo_addr.find_last_of(':') + 1)));
        const auto now = static_cast<std::uint64_t>(std::time(nullptr));
        const auto var = ss::BuildVarHeader(dst, 1);
        const auto fixed =
            ss::ParseFixedHeader(ss::HeaderTypeClient, now, static_cast<std::uint16_t>(var.size()));

        ss::ChunkCodec Codec(key);
        const auto fixed_enc = Codec.SealRaw(fixed);
        const auto var_enc = Codec.SealRaw(var);

        std::vector<std::uint8_t> wire;
        wire.reserve(salt.size() + fixed_enc.size() + var_enc.size());
        wire.insert(wire.end(), salt.begin(), salt.end());
        wire.insert(wire.end(), fixed_enc.begin(), fixed_enc.end());
        wire.insert(wire.end(), var_enc.begin(), var_enc.end());
        net::write(sock, net::buffer(wire));

        // 加密 echo 载荷并发送（chunk，Nonce 从 2 起）
        const std::string payload = "hello interop ss2022";
        ss::ChunkCodec data_codec(key, 2);
        const auto enc = data_codec.Seal(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
        net::write(sock, net::buffer(enc));

        // 读取服务端响应：Server salt 16 + 固定头密文 43
        // v0.2.12 服务端 writeResponse = [salt][固定头][payloadLen>0: payload 块]
        std::array<std::uint8_t, 16 + 43> resp_head{};
        net::read(sock, net::buffer(resp_head), net::transfer_exactly(resp_head.size()));
        const auto resp_key = ss::SessionKey(psk, std::span<const std::uint8_t>(resp_head).first(16), 16);
        ss::ChunkCodec RespCodec(resp_key);
        const auto fixed_plain =
            RespCodec.OpenRaw(std::span<const std::uint8_t>(resp_head).subspan(16, 43));
        if (fixed_plain.size() != ss::RespFixedHdrPlain || fixed_plain[0] != ss::HeaderTypeServer)
        {
            std::fprintf(stderr, "FAIL: Server response fixed Header\n");
            return 1;
        }
        // 固定头 paddingLen 字段 = 响应携带的 echo 数据长度
        const auto PayloadLen = static_cast<std::size_t>((fixed_plain[25] << 8) | fixed_plain[26]);
        if (PayloadLen == 0)
        {
            std::fprintf(stderr, "FAIL: Empty Server response payload\n");
            return 1;
        }
        std::vector<std::uint8_t> payload_enc(PayloadLen + 16);
        net::read(sock, net::buffer(payload_enc), net::transfer_exactly(payload_enc.size()));
        const auto plain = RespCodec.OpenRaw(payload_enc);
        if (plain.empty())
        {
            std::fprintf(stderr, "FAIL: Decrypt Server response payload\n");
            return 1;
        }
        if (std::string(reinterpret_cast<const char *>(plain.data()), plain.size()) != payload)
        {
            std::fprintf(stderr, "FAIL: echo mismatch: got %.*s\n", static_cast<int>(plain.size()),
                         reinterpret_cast<const char *>(plain.data()));
            return 1;
        }
        std::printf("PASS: interop ss2022 echo Ok (%zu Bytes)\n", plain.size());
        sock.close();
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
    return 0;
}
