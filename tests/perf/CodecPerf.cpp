/**
 * @file CodecPerf.cpp
 * @brief 协议编解码性能基准（纯热路径，无服务器）
 * @details 测量 7 个代理协议的核心编解码/加密路径：
 * - socks5:   地址编码 + CONNECT 请求构建
 * - trojan:   握手头构建
 * - vless:    握手头构建
 * - vmess:    AEAD chunk 加密（16KB）
 * - ss2022:   AEAD chunk 加密（16KB）
 * - hysteria2:UDP 帧构建
 * - tuic:     消息帧构建
 * @note 验收标准：各指标不得低于 Go 对照（tests/go/perfcmp）。
 * Release 编译（-O3）下运行，避免 Debug 失真。
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <common/proxy/hysteria2/codec.hpp>
#include <common/proxy/shadowsocks2022/codec.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/trojan/codec.hpp>
#include <common/proxy/tuic/codec.hpp>
#include <common/proxy/vless/codec.hpp>
#include <common/proxy/vmess/codec.hpp>

using clk = std::chrono::steady_clock;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    template <typename Fn>
    auto bench(const char *name, const int iters, Fn &&fn) -> void
    {
        volatile std::size_t sink = 0;
        const auto t0 = now_ns();
        for (int i = 0; i < iters; ++i)
        {
            sink += fn();
        }
        const auto t1 = now_ns();
        std::printf("%-28s %8d iters %10.2f ns/op (sink=%zu)\n", name, iters,
                    static_cast<double>(t1 - t0) / iters, static_cast<std::size_t>(sink));
    }

    auto make_domain_addr(psmtest::socks5::address &a) -> void
    {
        a.type = psmtest::socks5::address_type::domain;
        a.host = "example.com";
        a.port = 443;
    }
} // namespace

int main()
{
    // ── socks5 ──
    {
        using namespace psmtest::socks5;
        address addr;
        make_domain_addr(addr);
        request req;
        req.ver = version;
        req.cmd = command::connect;
        req.rsv = 0;
        req.target = addr;
        std::vector<std::uint8_t> buf;

        bench("socks5 encode_address", 200000, [&]()
              {
                  buf.clear();
                  encode_address(addr, buf);
                  return buf.size();
              });
        bench("socks5 build_request", 200000, [&]()
              {
                  buf.clear();
                  build_request(req, buf);
                  return buf.size();
              });
    }

    // ── trojan ──
    {
        using namespace psmtest::trojan;
        address addr;
        addr.type = address_type::domain;
        addr.host = "example.com";
        addr.port = 443;
        const std::string pass = "prism";
        std::vector<std::uint8_t> buf;

        bench("trojan build_request", 200000, [&]()
              {
                  buf.clear();
                  build_request(pass, command::connect, addr, buf);
                  return buf.size();
              });
    }

    // ── vless ──
    {
        using namespace psmtest::vless;
        request_header hdr;
        hdr.version = protocol_version;
        hdr.uuid.fill(0xAB);
        hdr.cmd = command::tcp;
        hdr.target.type = address_type::domain;
        hdr.target.host = "example.com";
        hdr.target.port = 443;
        std::vector<std::uint8_t> buf;

        bench("vless build_request", 200000, [&]()
              {
                  buf.clear();
                  build_request(hdr, buf);
                  return buf.size();
              });
    }

    // ── vmess AEAD chunk ──
    {
        using namespace psmtest::vmess;
        const auto key = std::array<std::uint8_t, 16>{};
        const auto nonce = std::array<std::uint8_t, 12>{};
        chunk_encryptor enc(key, nonce);
        std::vector<std::uint8_t> plain(16384);
        for (std::size_t i = 0; i < plain.size(); ++i)
        {
            plain[i] = static_cast<std::uint8_t>(i);
        }
        std::vector<std::uint8_t> wire;
        wire.resize(plain.size() + chunk_encryptor::overhead);

        bench("vmess chunk seal 16KB", 10000, [&]()
              {
                  const auto n = enc.seal(plain, wire);
                  return n;
              });
    }

    // ── ss2022 AEAD chunk ──
    {
        using namespace psmtest::ss2022;
        const auto key = std::array<std::uint8_t, 16>{};
        chunk_codec codec(key);
        std::vector<std::uint8_t> plain(16384);
        for (std::size_t i = 0; i < plain.size(); ++i)
        {
            plain[i] = static_cast<std::uint8_t>(i);
        }

        bench("ss2022 chunk seal 16KB", 10000, [&]()
              {
                  const auto wire = codec.seal(plain);
                  return wire.size();
              });
    }

    // ── hysteria2 UDP 帧 ──
    {
        using namespace psmtest::hysteria2;
        address addr;
        addr.type = address_type::domain;
        addr.host = "example.com";
        addr.port = 443;
        std::vector<std::uint8_t> payload(128, 0xAB);
        udp_frame_input in;
        in.session_id = 1;
        in.packet_id = 2;
        in.dst = &addr;
        in.payload = payload;
        std::vector<std::uint8_t> buf;

        bench("hysteria2 build_udp", 100000, [&]()
              {
                  buf.clear();
                  build_udp(in, buf);
                  return buf.size();
              });
    }

    // ── tuic 帧 ──
    {
        using namespace psmtest::tuic;
        message msg;
        msg.cmd = cmd_packet;
        msg.assoc_id = 1;
        msg.pkt_id = 2;
        msg.dst.type = address_type::domain;
        msg.dst.host = "example.com";
        msg.dst.port = 443;
        msg.payload.assign(128, static_cast<char>(0xCD));
        std::vector<std::uint8_t> buf;

        bench("tuic build packet", 100000, [&]()
              {
                  buf.clear();
                  build(msg, buf);
                  return buf.size();
              });
    }

    return 0;
}
