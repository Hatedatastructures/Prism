/**
 * @file RestlsServerHandshakeTest.cpp
 * @brief Restls 服务端握手编排契约测试
 * @details 权威实现见 metacubex/restls-client-go v0.1.9 `restls_server.go`：
 *          服务端是真实 TLS 中继——
 *            1) 读客户端首个 TLS 记录（ClientHello）并转发到后端 TLS 服务；
 *            2) 读后端首个响应记录（ServerHello），取出 32B ServerRandom；
 *            3) 将 ServerHello 原样回给客户端；
 *            4) 派生 RestlsSecret，用 ServerRandom 计算 ServerMask；
 *            5) 接管首个客户端加密记录（ClientFinished）作为 Handover 输入。
 *          本文件锁定第 2、4、5 步：ServerRandom 提取、Secret/Mask 派生，
 *          以及 Handover 的完整装配。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Preview/Protocols/Restls/Codec.hpp>
#include <Preview/Protocols/Restls/Types.hpp>

namespace
{

    namespace Restls = Preview::Restls;

    /// 构造最小合法 ServerHello TLS 记录（含 32B random）
    auto BuildServerHelloRecord(const std::array<std::uint8_t, 32> &Random)
        -> std::vector<std::uint8_t>
    {
        // handshake body: version(2) + random(32) + sessionIdLen(1) + cipher(2)
        //                 + compression(1) + extensionsLen(2)
        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), Random.begin(), Random.end());
        Body.push_back(0x00);      // session id length
        Body.push_back(0x13);      // TLS_AES_128_GCM_SHA256
        Body.push_back(0x01);
        Body.push_back(0x00);      // compression
        Body.push_back(0x00);
        Body.push_back(0x00);      // extensions length = 0

        std::vector<std::uint8_t> Message{0x02};
        Message.push_back(static_cast<std::uint8_t>((Body.size() >> 16) & 0xFF));
        Message.push_back(static_cast<std::uint8_t>((Body.size() >> 8) & 0xFF));
        Message.push_back(static_cast<std::uint8_t>(Body.size() & 0xFF));
        Message.insert(Message.end(), Body.begin(), Body.end());

        std::vector<std::uint8_t> Record{0x16, 0x03, 0x03};
        Record.push_back(static_cast<std::uint8_t>(Message.size() >> 8));
        Record.push_back(static_cast<std::uint8_t>(Message.size() & 0xFF));
        Record.insert(Record.end(), Message.begin(), Message.end());
        return Record;
    }

    TEST(RestlsServerHandshake, ExtractsServerRandomFromServerHelloRecord)
    {
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(0x40U + Index);
        }
        const auto Record = BuildServerHelloRecord(Random);

        const auto Parsed = Restls::ParseServerHelloRandom(Record);

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(*Parsed, Random);
    }

    TEST(RestlsServerHandshake, RejectsNonServerHelloRecord)
    {
        // 非 0x16 (handshake) 记录类型
        const std::vector<std::uint8_t> ApplicationData{0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4};
        EXPECT_FALSE(Restls::ParseServerHelloRandom(ApplicationData).has_value());

        // 空记录
        EXPECT_FALSE(Restls::ParseServerHelloRandom({}).has_value());

        // handshake 类型但消息类型不是 ServerHello(0x02)
        std::vector<std::uint8_t> ClientHello{0x16, 0x03, 0x01, 0x00, 0x05,
                                              0x01, 0x00, 0x00, 0x01, 0x00};
        EXPECT_FALSE(Restls::ParseServerHelloRandom(ClientHello).has_value());
    }

    TEST(RestlsServerHandshake, HandoverCarriesServerRandomAndFirstEncrypted)
    {
        const auto Secret = Restls::DeriveSecret("restls_password");
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(Index);
        }

        // 首个后端加密记录（TLS ApplicationData），需经 ServerMask 保护
        std::vector<std::uint8_t> FirstEncrypted{0x17, 0x03, 0x03, 0x00, 0x08};
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            FirstEncrypted.push_back(static_cast<std::uint8_t>(0xA0U + Index));
        }
        const auto [ProtectError, Protected] =
            Restls::ProtectFirstEncrypted(FirstEncrypted, Secret, Random);

        ASSERT_EQ(ProtectError, Preview::Error::None);
        ASSERT_EQ(Protected.size(), FirstEncrypted.size());

        Restls::Handover HandoverValue;
        HandoverValue.ServerRandom = Random;
        HandoverValue.FirstEncrypted = Protected;
        HandoverValue.ClientFinished = {0x17, 0x03, 0x03, 0x00, 0x10};

        EXPECT_EQ(HandoverValue.ServerRandom, Random);
        EXPECT_EQ(HandoverValue.FirstEncrypted, Protected);
        EXPECT_FALSE(HandoverValue.ClientFinished.empty());
    }

    TEST(RestlsServerHandshake, VerifiesTls13ClientAuthFromKeyShares)
    {
        // 对齐 restls_server.go checkTLS13ClientAuth：
        //   expect = BLAKE3_keyed(secret, [group 2B][keyShareData]... +
        //                          [pskLabel]...)[:16]
        //   与 ClientHello sessionId[:16] 比对。
        const auto Secret = Restls::DeriveSecret("restls_password");

        Restls::Tls13ClientAuthInput Input;
        Input.KeyShareGroup = 0x001D; // x25519
        Input.KeyShareData = std::vector<std::uint8_t>(32, 0x5A);

        const auto Expected = Restls::ComputeTls13ClientAuth(Secret, Input);
        ASSERT_EQ(Expected.size(), Restls::HsMaclen);

        std::vector<std::uint8_t> SessionId(32, 0);
        std::copy(Expected.begin(), Expected.end(), SessionId.begin());
        EXPECT_TRUE(Restls::VerifyTls13ClientAuth(Secret, Input, SessionId));

        // sessionId 前 16 字节不匹配 → 认证失败
        SessionId[0] ^= 0xFF;
        EXPECT_FALSE(Restls::VerifyTls13ClientAuth(Secret, Input, SessionId));

        // sessionId 长度不是 32 → 认证失败
        const std::vector<std::uint8_t> ShortSession(16, 0);
        EXPECT_FALSE(Restls::VerifyTls13ClientAuth(Secret, Input, ShortSession));
    }

    TEST(RestlsServerHandshake, ClientAuthCoversKeyShareAndPskIdentities)
    {
        const auto Secret = Restls::DeriveSecret("restls_password");

        Restls::Tls13ClientAuthInput Base;
        Base.KeyShareGroup = 0x001D;
        Base.KeyShareData = std::vector<std::uint8_t>(32, 0x11);
        const auto BaseMac = Restls::ComputeTls13ClientAuth(Secret, Base);

        // 改变 keyShare 数据 → MAC 必须改变
        Restls::Tls13ClientAuthInput Changed = Base;
        Changed.KeyShareData[0] ^= 0x01;
        EXPECT_NE(Restls::ComputeTls13ClientAuth(Secret, Changed), BaseMac);

        // 追加 psk identity → MAC 必须改变
        Restls::Tls13ClientAuthInput WithPsk = Base;
        WithPsk.PskIdentities.push_back(std::vector<std::uint8_t>{0xDE, 0xAD});
        EXPECT_NE(Restls::ComputeTls13ClientAuth(Secret, WithPsk), BaseMac);

        // 不同密码 → MAC 必须不同
        const auto OtherSecret = Restls::DeriveSecret("other_password");
        EXPECT_NE(Restls::ComputeTls13ClientAuth(OtherSecret, Base), BaseMac);
    }

} // namespace
