/**
 * @file EchKeygenTest.cpp
 * @brief ECH 密钥生成与检测测试（T2-3）
 * @details 覆盖：
 *          - generate_keypair：随机密钥 + ECHConfig 序列化
 *          - keypair_from_private：私钥恢复 ECHConfig（确定性）
 *          - make_ech_keys：SSL_ECH_KEYS 构造
 *          - contains_ech_extension：ClientHello 扫描（含/不含）
 */

#include <common/stealth/ech/ech.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstring>

#include <gtest/gtest.h>

namespace
{
    namespace ech = psmtest::ech;

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
        // legacy_version
        ch.push_back(std::byte{0x03});
        ch.push_back(std::byte{0x03});
        // random 32
        for (int i = 0; i < 32; ++i)
        {
            ch.push_back(std::byte{0xAA});
        }
        // session_id
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
    void add_extension(std::vector<std::byte> &ch, std::uint16_t type, std::span<const std::byte> data)
    {
        // 定位 extensions 长度位置：固定在末尾（无扩展时）
        // 先加 extensions 头（2 字节长度），再追加项
        const auto ext_start = ch.size();
        ch.push_back(std::byte{0x00});
        ch.push_back(std::byte{0x00});
        // 追加项
        ch.push_back(static_cast<std::byte>((type >> 8) & 0xFF));
        ch.push_back(static_cast<std::byte>(type & 0xFF));
        ch.push_back(static_cast<std::byte>((data.size() >> 8) & 0xFF));
        ch.push_back(static_cast<std::byte>(data.size() & 0xFF));
        ch.insert(ch.end(), data.begin(), data.end());
        // 更新长度
        const auto total = ch.size() - (ext_start + 2);
        ch[ext_start] = static_cast<std::byte>((total >> 8) & 0xFF);
        ch[ext_start + 1] = static_cast<std::byte>(total & 0xFF);
        // 更新记录长度
        const auto rec_len = ch.size() - 5;
        ch[3] = static_cast<std::byte>((rec_len >> 8) & 0xFF);
        ch[4] = static_cast<std::byte>(rec_len & 0xFF);
    }
} // namespace

TEST(EchKeygen, GenerateKeypair)
{
    ech::ech_keypair kp;
    const auto code = ech::generate_keypair("example.com", 32, kp);
    EXPECT_EQ(code, psmtest::fault::code::success);
    EXPECT_FALSE(kp.ech_config.empty());
    EXPECT_FALSE(kp.ech_config_list.empty());
    // ECHConfigList = 2 字节长度前缀 + config
    EXPECT_EQ(kp.ech_config_list.size(), kp.ech_config.size() + 2);
    EXPECT_EQ(kp.ech_config_list[0], static_cast<std::uint8_t>(kp.ech_config.size() >> 8));
    EXPECT_EQ(kp.ech_config_list[1], static_cast<std::uint8_t>(kp.ech_config.size() & 0xFF));
}

TEST(EchKeygen, KeypairFromPrivateDeterministic)
{
    std::array<std::uint8_t, ech::private_key_len> key{};
    for (std::size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<std::uint8_t>(i + 1);
    }

    ech::ech_keypair kp1;
    ech::ech_keypair kp2;
    EXPECT_EQ(ech::keypair_from_private(key, "example.com", 32, kp1), psmtest::fault::code::success);
    EXPECT_EQ(ech::keypair_from_private(key, "example.com", 32, kp2), psmtest::fault::code::success);

    // 确定性：相同私钥 → 相同 ECHConfig
    ASSERT_EQ(kp1.ech_config.size(), kp2.ech_config.size());
    EXPECT_EQ(std::memcmp(kp1.ech_config.data(), kp2.ech_config.data(), kp1.ech_config.size()), 0);
}

TEST(EchKeygen, MakeEchKeys)
{
    ech::ech_keypair kp;
    ASSERT_EQ(ech::generate_keypair("example.com", 32, kp), psmtest::fault::code::success);

    auto *keys = ech::make_ech_keys(kp.private_key, kp.ech_config);
    ASSERT_NE(keys, nullptr);
    SSL_ECH_KEYS_free(keys);
}

TEST(EchKeygen, ClientHelloNoEch)
{
    auto ch = make_client_hello();
    EXPECT_FALSE(ech::contains_ech_extension(ch));
}

TEST(EchKeygen, ClientHelloWithEch)
{
    auto ch = make_client_hello();
    std::array<std::byte, 4> ech_ext{std::byte{0x00}, std::byte{0x20}, std::byte{0x01}, std::byte{0x02}};
    add_extension(ch, ech::ech_extension_type, ech_ext);
    EXPECT_TRUE(ech::contains_ech_extension(ch));
}

TEST(EchKeygen, ClientHelloOtherExtension)
{
    auto ch = make_client_hello();
    std::array<std::byte, 2> sni_ext{std::byte{0x00}, std::byte{0x00}};
    add_extension(ch, 0x0000, sni_ext); // server_name
    EXPECT_FALSE(ech::contains_ech_extension(ch));
}
