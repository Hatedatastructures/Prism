/**
 * @file EchKeygenTest.cpp
 * @brief ECH 密钥生成与检测测试（T2-3）
 * @details 覆盖：
 *          - GenerateKeypair：随机密钥 + ECHConfig 序列化
 *          - KeypairFromPrivate：私钥恢复 ECHConfig（确定性）
 *          - MakeEchKeys：SSL_ECH_KEYS 构造
 *          - ContainsEchExtension：ClientHello 扫描（含/不含）
 */

#include <common/Protocols/Ech/Ech.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstring>

#include <gtest/gtest.h>


namespace
{
    namespace Ech = Preview::Ech;
    namespace ech = Preview::Ech;

    /// 构造最小 ClientHello（无扩展）
    auto make_client_hello() -> std::vector<std::byte>
    {
        std::vector<std::byte> ch;
        // 记录头
        ch.push_back(std::byte{0x16});
        ch.push_back(std::byte{0x03});
        ch.push_back(std::byte{0x01});
        // 长度占位
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x00});
        // ClientHello 体
        ch.push_back(std::byte{0x01});
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x00});
        // LegacyVersion
        ch.push_back(std::byte{0x03});
        ch.push_back(std::byte{0x03});
        // random 32
        for (int i = 0; i < 32; ++i)
        {
            ch.push_back(std::byte{0xAA});
        }
        // SessionId
        ch.push_back(std::byte{0x00});
        // cipher_suites
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x02});
        ch.push_back(std::byte{0x13});
        ch.push_back(std::byte{0x01});
        // compression
        ch.push_back(std::byte{0x01});
        ch.push_back(std::byte{0x00});
        return ch;
    }

    /// 追加扩展项
    void add_extension(std::vector<std::byte> &ch, std::uint16_t Type, std::span<const std::byte> Data)
    {
        // 定位 extensions 长度位置：固定在末尾（无扩展时）
        // 先加 extensions 头（2 字节长度），再追加项
        const auto ext_start = ch.size();
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x00});
        // 追加项
        ch.push_back(static_cast<std::byte>((Type >> 8) & 0xFF));
        ch.push_back(static_cast<std::byte>(Type & 0xFF));
        ch.push_back(static_cast<std::byte>((Data.size() >> 8) & 0xFF));
        ch.push_back(static_cast<std::byte>(Data.size() & 0xFF));
        ch.insert(ch.end(), Data.begin(), Data.end());
        // 更新长度
        const auto Total = ch.size() - (ext_start + 2);
        ch[ext_start] = static_cast<std::byte>((Total >> 8) & 0xFF);
        ch[ext_start + 1] = static_cast<std::byte>(Total & 0xFF);
        // 更新记录长度
        const auto rec_len = ch.size() - 5;
        ch[3] = static_cast<std::byte>((rec_len >> 8) & 0xFF);
        ch[4] = static_cast<std::byte>(rec_len & 0xFF);
    }
} // namespace

TEST(EchKeygen, GenerateKeypair)
{
    Ech::EchKeypair kp;
    const auto Code = Ech::GenerateKeypair("example.com", 32, kp);
    EXPECT_EQ(Code, Preview::Fault::Code::Success);
    EXPECT_FALSE(kp.EchConfig.empty());
    EXPECT_FALSE(kp.EchConfigList.empty());
    // ECHConfigList = 2 字节长度前缀 + Config
    EXPECT_EQ(kp.EchConfigList.size(), kp.EchConfig.size() + 2);
    EXPECT_EQ(kp.EchConfigList[0], static_cast<std::uint8_t>(kp.EchConfig.size() >> 8));
    EXPECT_EQ(kp.EchConfigList[1], static_cast<std::uint8_t>(kp.EchConfig.size() & 0xFF));
}

TEST(EchKeygen, KeypairFromPrivateDeterministic)
{
    std::array<std::uint8_t, Ech::PrivateKeyLen> key{};
    for (std::size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<std::uint8_t>(i + 1);
    }

    Ech::EchKeypair kp1;
    Ech::EchKeypair kp2;
    EXPECT_EQ(Ech::KeypairFromPrivate(key, "example.com", 32, kp1), Preview::Fault::Code::Success);
    EXPECT_EQ(Ech::KeypairFromPrivate(key, "example.com", 32, kp2), Preview::Fault::Code::Success);

    // 确定性：相同私钥 → 相同 ECHConfig
    ASSERT_EQ(kp1.EchConfig.size(), kp2.EchConfig.size());
    EXPECT_EQ(std::memcmp(kp1.EchConfig.data(), kp2.EchConfig.data(), kp1.EchConfig.size()), 0);
}

TEST(EchKeygen, MakeEchKeys)
{
    Ech::EchKeypair kp;
    ASSERT_EQ(Ech::GenerateKeypair("example.com", 32, kp), Preview::Fault::Code::Success);

    auto *keys = Ech::MakeEchKeys(kp.private_key, kp.EchConfig);
    ASSERT_NE(keys, nullptr);
    SSL_ECH_KEYS_free(keys);
}

TEST(EchKeygen, ClientHelloNoEch)
{
    auto ch = make_client_hello();
    EXPECT_FALSE(Ech::ContainsEchExtension(ch));
}

TEST(EchKeygen, ClientHelloWithEch)
{
    auto ch = make_client_hello();
    std::array<std::byte, 4> ech_ext{std::byte{0x00}, std::byte{0x20}, std::byte{0x01}, std::byte{0x02}};
    add_extension(ch, Ech::EchExtensionType, ech_ext);
    EXPECT_TRUE(Ech::ContainsEchExtension(ch));
}

TEST(EchKeygen, ClientHelloOtherExtension)
{
    auto ch = make_client_hello();
    std::array<std::byte, 2> sni_ext{std::byte{0x00}, std::byte{0x00}};
    add_extension(ch, 0x0000, sni_ext); // server_name
    EXPECT_FALSE(Ech::ContainsEchExtension(ch));
}