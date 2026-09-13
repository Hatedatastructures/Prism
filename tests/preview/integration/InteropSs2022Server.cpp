/**
 * @file InteropSs2022Server.cpp
 * @brief SS2022 互操作测试：C++ common 服务端 ← Go 真实客户端（sing-shadowsocks v0.2.12）
 * @details 用 tests/common/shadowsocks2022 的纯逻辑编解码 + Boost.Asio socket：
 *          1. TCP 监听
 *          2. 解析握手首包（salt + 固定头 + 变长头）
 *          3. 回服务端响应（Server salt + 固定头 + 空块）
 *          4. 循环读取 chunk → 解密 → 加密 echo 回包
 * @param argv[1] 监听地址（默认 127.0.0.1:19080）
 */

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <preview/Protocols/Shadowsocks2022/Codec.hpp>

namespace Ss2022 = Preview::Shadowsocks2022;

namespace Net = boost::asio;

auto main(const int Argc, char *Argv[]) -> int
{
    std::string ListenAddress{"127.0.0.1:19080"};
    if (Argc > 1)
    {
        ListenAddress = Argv[1];
    }

    // PSK（与 configuration.json 一致）
    std::array<std::uint8_t, 16> Psk{0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                                     0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};

    try
    {
        Net::io_context Io;
        std::string Host;
        std::uint16_t Port = 0;
        const auto Colon = ListenAddress.find_last_of(':');
        if (Colon == std::string::npos)
        {
            std::fprintf(stderr, "bad listen Address: %s\n", ListenAddress.c_str());
            return 1;
        }
        Host = ListenAddress.substr(0, Colon);
        Port = static_cast<std::uint16_t>(std::stoi(ListenAddress.substr(Colon + 1)));
        const auto ListenEndpoint = Net::ip::tcp::endpoint(Net::ip::make_address(Host), Port);
        Net::ip::tcp::acceptor Acceptor(Io, ListenEndpoint);
        Net::ip::tcp::socket Socket(Io);
        Acceptor.accept(Socket);

        const auto Now = static_cast<std::uint64_t>(std::time(nullptr));

        // 读取握手：salt 16 + 固定头密文 43，再从固定头解析变长头长度动态读取
        std::array<std::uint8_t, 16 + Ss2022::FixedHdrSize> Head{};
        Net::read(Socket, Net::buffer(Head), Net::transfer_exactly(Head.size()));
        const auto ClientSalt = std::span<const std::uint8_t>(Head).first(16);
        const auto ProbeKey = Ss2022::SessionKey(Psk, ClientSalt, 16);
        Ss2022::ChunkCodec ProbeCodec(ProbeKey);
        const auto FixedCiphertext = std::span<const std::uint8_t>(Head).subspan(
            16, Ss2022::FixedHdrSize);
        const auto FixedPlain = ProbeCodec.OpenRaw(FixedCiphertext);
        if (FixedPlain.size() != Ss2022::FixedHdrPlain || FixedPlain[0] != Ss2022::HeaderTypeClient)
        {
            std::fprintf(stderr, "FAIL: fixed Header Decrypt\n");
            return 1;
        }
        const auto VariableLength = static_cast<std::size_t>((FixedPlain[9] << 8) | FixedPlain[10]);
        std::vector<std::uint8_t> VariableEncrypted(VariableLength + Ss2022::AeadTagLen);
        Net::read(Socket, Net::buffer(VariableEncrypted), Net::transfer_exactly(VariableEncrypted.size()));
        const auto VariablePlain = ProbeCodec.OpenRaw(VariableEncrypted);
        if (VariablePlain.empty())
        {
            std::fprintf(stderr, "FAIL: var Header Decrypt\n");
            return 1;
        }
        Ss2022::Address Destination;
        std::span<const std::uint8_t> Payload;
        if (Ss2022::ParseVarHeader(VariablePlain, Destination, Payload) != Preview::Error::None)
        {
            std::fprintf(stderr, "FAIL: handshake Parse\n");
            return 1;
        }
        std::printf("Server: handshake Ok -> %s:%u\n", Destination.Host.c_str(), Destination.Port);

        // 服务端响应按 SS2022 writeResponse 语义：首次发送数据时才构造，
        // 响应固定头（Type + ts + requestSalt + payloadLen）后紧跟裸块 payload。
        std::array<std::uint8_t, 16> ServerSalt{};
        std::random_device RandomDevice;
        for (auto &Byte : ServerSalt)
        {
            Byte = static_cast<std::uint8_t>(RandomDevice() & 0xFF);
        }
        const auto ResponseKey = Ss2022::SessionKey(Psk, ServerSalt, 16);
        Ss2022::ChunkCodec ResponseCodec(ResponseKey);
        std::array<std::uint8_t, Ss2022::RespFixedHdrPlain> ResponseFixed{};
        ResponseFixed[0] = Ss2022::HeaderTypeServer;
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            ResponseFixed[1 + Index] = static_cast<std::uint8_t>(
                (Now >> (56 - static_cast<unsigned>(Index) * 8)) & 0xFF);
        }
        // requestSalt 回显客户端 salt（head 前 16 字节）
        std::memcpy(ResponseFixed.data() + 9, Head.data(), 16);
        bool Responded{false};

        // 会话密钥（客户端→服务端方向，用客户端 salt）+ chunk 编解码
        auto Key = Ss2022::SessionKey(Psk, ClientSalt, 16);
        // 客户端握手消耗 Nonce 0,1，数据从 2 起
        Ss2022::ChunkCodec Codec(Key, 2);
        // 服务端→客户端方向：首次响应消耗 Nonce 0/1（固定头 + payload），后续 echo 从 2 起
        Ss2022::ChunkCodec EchoCodec(ResponseKey, 2);

        // 循环读取并 echo（最多 16 块）
        for (int Index = 0; Index < 16; ++Index)
        {
            // Go 客户端按块发送：[len 块 18B][载荷块]
            std::array<std::uint8_t, Ss2022::LenBlockSize> LengthEncrypted{};
            boost::system::error_code Error;
            const auto Count = Net::read(
                Socket,
                Net::buffer(LengthEncrypted),
                Net::transfer_exactly(LengthEncrypted.size()),
                Error);
            if (Error || Count == 0)
            {
                break;
            }
            const auto Length = Codec.OpenLen(LengthEncrypted);
            if (!Length)
            {
                std::fprintf(stderr, "FAIL: Decrypt chunk length\n");
                return 1;
            }
            // 密文 = 明文长度 + 16B 认证标签
            std::vector<std::uint8_t> BodyEncrypted(*Length + Ss2022::AeadTagLen);
            Net::read(Socket, Net::buffer(BodyEncrypted), Net::transfer_exactly(BodyEncrypted.size()));
            const auto Plain = Codec.OpenPayload(BodyEncrypted);
            if (Plain.empty())
            {
                std::fprintf(stderr, "FAIL: Decrypt chunk body\n");
                return 1;
            }
            // echo 回包：首次发送 = writeResponse（响应固定头 + 裸块 payload），
            // 后续 = chunk 流（首次响应已消耗 Nonce 0/1，数据面从 2 起）
            if (!Responded)
            {
                ResponseFixed[25] = static_cast<std::uint8_t>((Plain.size() >> 8) & 0xFF);
                ResponseFixed[26] = static_cast<std::uint8_t>(Plain.size() & 0xFF);
                const auto ResponseFixedEncrypted = ResponseCodec.SealRaw(ResponseFixed);
                const auto PayloadEncrypted = ResponseCodec.SealRaw(Plain);
                std::vector<std::uint8_t> Response;
                Response.reserve(ServerSalt.size() + ResponseFixedEncrypted.size() + PayloadEncrypted.size());
                Response.insert(Response.end(), ServerSalt.begin(), ServerSalt.end());
                Response.insert(Response.end(), ResponseFixedEncrypted.begin(), ResponseFixedEncrypted.end());
                Response.insert(Response.end(), PayloadEncrypted.begin(), PayloadEncrypted.end());
                Net::write(Socket, Net::buffer(Response));
                Responded = true;
            }
            else
            {
                const auto Echo = EchoCodec.Seal(Plain);
                Net::write(Socket, Net::buffer(Echo));
            }
        }
        Socket.close();
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
    return 0;
}
