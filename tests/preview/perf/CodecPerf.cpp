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

#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>

using clk = std::chrono::steady_clock;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    template <typename Fn>
    auto bench(const char *Name, const int iters, Fn &&fn) -> void
    {
        volatile std::size_t sink = 0;
        const auto t0 = now_ns();
        for (int i = 0; i < iters; ++i)
        {
            sink += fn();
        }
        const auto t1 = now_ns();
        std::printf("%-28s %8d iters %10.2f ns/op (sink=%zu)\n", Name, iters,
                    static_cast<double>(t1 - t0) / iters, static_cast<std::size_t>(sink));
    }

    auto make_domain_addr(Preview::Socks5::Address &a) -> void
    {
        a.Type = Preview::Socks5::AddressType::Domain;
        a.Host = "example.com";
        a.Port = 443;
    }
} // namespace

int main()
{
    // ── socks5 ──
    {
        using namespace Preview::Socks5;
        Address addr;
        make_domain_addr(addr);
        Request req;
        req.Ver = Version;
        req.Cmd = Command::Connect;
        req.Rsv = 0;
        req.Target = addr;
        std::vector<std::uint8_t> buf;

        bench("socks5 EncodeAddress", 200000, [&]()
              {
                  buf.clear();
                  EncodeAddress(addr, buf);
                  return buf.size();
              });
        bench("socks5 BuildRequest", 200000, [&]()
              {
                  buf.clear();
                  BuildRequest(req, buf);
                  return buf.size();
              });
    }

    // ── trojan ──
    {
        using namespace Preview::Trojan;
        Address addr;
        addr.Type = AddressType::Domain;
        addr.Host = "example.com";
        addr.Port = 443;
        const std::string pass = "prism";
        std::vector<std::uint8_t> buf;

        bench("trojan BuildRequest", 200000, [&]()
              {
                  buf.clear();
                  BuildRequest({pass, Command::Connect, addr}, buf);
                  return buf.size();
              });
    }

    // ── vless ──
    {
        using namespace Preview::Vless;
        RequestHeader hdr;
        hdr.Version = ProtocolVersion;
        hdr.Uuid.fill(0xAB);
        hdr.Cmd = Command::Tcp;
        hdr.Target.Type = AddressType::Domain;
        hdr.Target.Host = "example.com";
        hdr.Target.Port = 443;
        std::vector<std::uint8_t> buf;

        bench("vless BuildRequest", 200000, [&]()
              {
                  buf.clear();
                  BuildRequest(hdr, buf);
                  return buf.size();
              });
    }

    // ── vmess AEAD chunk ──
    {
        using namespace Preview::Vmess;
        const auto key = std::array<std::uint8_t, 16>{};
        const auto Nonce = std::array<std::uint8_t, 12>{};
        ChunkEncryptor enc(key, Nonce);
        std::vector<std::uint8_t> plain(16384);
        for (std::size_t i = 0; i < plain.size(); ++i)
        {
            plain[i] = static_cast<std::uint8_t>(i);
        }
        std::vector<std::uint8_t> wire;
        wire.resize(plain.size() + ChunkEncryptor::Overhead);

        bench("vmess chunk Seal 16KB", 10000, [&]()
              {
                  const auto n = enc.Seal(plain, wire);
                  return n;
              });
    }

    // ── ss2022 AEAD chunk ──
    {
        using namespace Preview::Shadowsocks2022;
        const auto key = std::array<std::uint8_t, 16>{};
        ChunkCodec Codec(key);
        std::vector<std::uint8_t> plain(16384);
        for (std::size_t i = 0; i < plain.size(); ++i)
        {
            plain[i] = static_cast<std::uint8_t>(i);
        }

        bench("ss2022 chunk Seal 16KB", 10000, [&]()
              {
                  const auto wire = Codec.Seal(plain);
                  return wire.size();
              });
    }

    // ── hysteria2 UDP 帧 ──
    {
        using namespace Preview::Hysteria2;
        Address addr;
        addr.Type = AddressType::Domain;
        addr.Host = "example.com";
        addr.Port = 443;
        std::vector<std::uint8_t> payload(128, 0xAB);
        UdpFrameInput in;
        in.SessionId = 1;
        in.PacketId = 2;
        in.dst = &addr;
        in.payload = payload;
        std::vector<std::uint8_t> buf;

        bench("hysteria2 BuildUdp", 100000, [&]()
              {
                  buf.clear();
                  BuildUdp(in, buf);
                  return buf.size();
              });
    }

    // ── tuic 帧 ──
    {
        using namespace Preview::Tuic;
        Message msg;
        msg.Cmd = CmdPacket;
        msg.AssocId = 1;
        msg.PktId = 2;
        msg.dst.Type = AddressType::Domain;
        msg.dst.Host = "example.com";
        msg.dst.Port = 443;
        msg.payload.assign(128, static_cast<char>(0xCD));
        std::vector<std::uint8_t> buf;

        bench("tuic Build packet", 100000, [&]()
              {
                  buf.clear();
                  Build(msg, buf);
                  return buf.size();
              });
    }

    return 0;
}
