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

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Protocols/Shadowsocks2022/Codec.hpp>

namespace Ss2022 = Preview::Shadowsocks2022;

namespace Net = boost::asio;

auto main(const int Argc, char *Argv[]) -> int
{
    std::string ServerAddress{"127.0.0.1:19080"};
    if (Argc > 1)
    {
        ServerAddress = Argv[1];
    }
    std::string EchoAddress{"127.0.0.1:19090"};
    if (Argc > 2)
    {
        EchoAddress = Argv[2];
    }

    // PSK（与 configuration.json 一致）
    std::array<std::uint8_t, 16> Psk{0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                                     0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};

    try
    {
        Net::io_context Io;

        // 解析服务端地址
        std::string Host;
        std::uint16_t Port = 0;
        const auto Colon = ServerAddress.find_last_of(':');
        if (Colon == std::string::npos)
        {
            std::fprintf(stderr, "bad Server Address: %s\n", ServerAddress.c_str());
            return 1;
        }
        Host = ServerAddress.substr(0, Colon);
        Port = static_cast<std::uint16_t>(std::stoi(ServerAddress.substr(Colon + 1)));
        Net::ip::tcp::resolver Resolver(Io);
        auto Endpoints = Resolver.resolve(Host, std::to_string(Port));
        Net::ip::tcp::socket Socket(Io);
        Net::connect(Socket, Endpoints);

        // 构造握手（目标 = echo 服务器）
        std::random_device RandomDevice;
        std::array<std::uint8_t, 16> Salt{};
        for (auto &Byte : Salt)
        {
            Byte = static_cast<std::uint8_t>(RandomDevice() & 0xFF);
        }
        const auto Key = Ss2022::SessionKey(Psk, Salt, 16);

        Ss2022::Address Destination;
        Destination.Type = Ss2022::AddressType::Ipv4;
        Destination.Host = "127.0.0.1";
        Destination.Port = static_cast<std::uint16_t>(
            std::stoi(EchoAddress.substr(EchoAddress.find_last_of(':') + 1)));
        const auto Now = static_cast<std::uint64_t>(std::time(nullptr));
        const auto Variable = Ss2022::BuildVarHeader(Destination, 1);
        const auto Fixed = Ss2022::ParseFixedHeader(
            Ss2022::HeaderTypeClient,
            Now,
            static_cast<std::uint16_t>(Variable.size()));

        Ss2022::ChunkCodec Codec(Key);
        const auto FixedEncrypted = Codec.SealRaw(Fixed);
        const auto VariableEncrypted = Codec.SealRaw(Variable);

        std::vector<std::uint8_t> Wire;
        Wire.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
        Wire.insert(Wire.end(), Salt.begin(), Salt.end());
        Wire.insert(Wire.end(), FixedEncrypted.begin(), FixedEncrypted.end());
        Wire.insert(Wire.end(), VariableEncrypted.begin(), VariableEncrypted.end());
        Net::write(Socket, Net::buffer(Wire));

        // 加密 echo 载荷并发送（chunk，Nonce 从 2 起）
        const std::string PayloadText = "hello interop ss2022";
        Ss2022::ChunkCodec DataCodec(Key, 2);
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
        const auto Encoded = DataCodec.Seal(Payload);
        Net::write(Socket, Net::buffer(Encoded));

        // 读取服务端响应：Server salt 16 + 固定头密文 43
        // v0.2.12 服务端 writeResponse = [salt][固定头][payloadLen>0: payload 块]
        std::array<std::uint8_t, 16 + 43> ResponseHead{};
        Net::read(Socket, Net::buffer(ResponseHead), Net::transfer_exactly(ResponseHead.size()));
        const auto ResponseSalt = std::span<const std::uint8_t>(ResponseHead).first(16);
        const auto ResponseKey = Ss2022::SessionKey(Psk, ResponseSalt, 16);
        Ss2022::ChunkCodec ResponseCodec(ResponseKey);
        const auto ResponseCiphertext = std::span<const std::uint8_t>(ResponseHead).subspan(16, 43);
        const auto FixedPlain = ResponseCodec.OpenRaw(ResponseCiphertext);
        if (FixedPlain.size() != Ss2022::RespFixedHdrPlain || FixedPlain[0] != Ss2022::HeaderTypeServer)
        {
            std::fprintf(stderr, "FAIL: Server response fixed Header\n");
            return 1;
        }
        // 固定头 paddingLen 字段 = 响应携带的 echo 数据长度
        const auto PayloadLength = static_cast<std::size_t>((FixedPlain[25] << 8) | FixedPlain[26]);
        if (PayloadLength == 0)
        {
            std::fprintf(stderr, "FAIL: Empty Server response payload\n");
            return 1;
        }
        std::vector<std::uint8_t> PayloadEncrypted(PayloadLength + 16);
        Net::read(Socket, Net::buffer(PayloadEncrypted), Net::transfer_exactly(PayloadEncrypted.size()));
        const auto Plain = ResponseCodec.OpenRaw(PayloadEncrypted);
        if (Plain.empty())
        {
            std::fprintf(stderr, "FAIL: Decrypt Server response payload\n");
            return 1;
        }
        if (std::string(reinterpret_cast<const char *>(Plain.data()), Plain.size()) != PayloadText)
        {
            std::fprintf(stderr, "FAIL: echo mismatch: got %.*s\n", static_cast<int>(Plain.size()),
                         reinterpret_cast<const char *>(Plain.data()));
            return 1;
        }
        std::printf("PASS: interop ss2022 echo Ok (%zu Bytes)\n", Plain.size());
        Socket.close();
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
    return 0;
}
