/**
 * @file EchKeygen.cpp
 * @brief ECH 密钥生成与序列化测试
 * @details 验证 X25519 密钥生成、ECHConfig 构造、base64 往返。
 */

#include <prism/handshake/ech/util/keygen.hpp>

#include <cstring>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::ech::base64_decode;
    using psm::handshake::ech::base64_encode;
    using psm::handshake::ech::ech_keypair;
    using psm::handshake::ech::generate_keypair;
    using psm::handshake::ech::keypair_from_private;
    using psm::handshake::ech::make_ech_keys;
} // namespace

TEST(EchKeygen, GenerateKeypair)
{
    ech_keypair kp;
    const auto ec = generate_keypair("example.com", 64, kp);
    ASSERT_EQ(ec, psm::fault::code::success);

    // 私钥 32 字节
    bool non_zero = false;
    for (const auto b : kp.private_key)
    {
        non_zero = non_zero || b != 0;
    }
    EXPECT_TRUE(non_zero) << "private key non-zero";

    // ECHConfig 非空
    EXPECT_FALSE(kp.ech_config.empty());
    // ECHConfigList = 2 字节长度 + config
    EXPECT_EQ(kp.ech_config_list.size(), kp.ech_config.size() + 2);
}

TEST(EchKeygen, KeypairFromPrivateRoundtrip)
{
    ech_keypair generated;
    ASSERT_EQ(generate_keypair("example.com", 64, generated), psm::fault::code::success);

    // 从私钥恢复配置
    ech_keypair restored;
    const auto ec = keypair_from_private(std::span<const std::uint8_t, 32>(generated.private_key.data(), 32),
                                         "example.com", 64, restored);
    ASSERT_EQ(ec, psm::fault::code::success);
    EXPECT_EQ(restored.private_key, generated.private_key);
    // config_id 不同（restored 固定 0）但结构应一致
    EXPECT_FALSE(restored.ech_config.empty());
}

TEST(EchKeygen, MakeEchKeys)
{
    ech_keypair kp;
    ASSERT_EQ(generate_keypair("example.com", 64, kp), psm::fault::code::success);

    auto *keys = make_ech_keys(std::span<const std::uint8_t, 32>(kp.private_key.data(), 32), kp.ech_config);
    ASSERT_NE(keys, nullptr);
    SSL_ECH_KEYS_free(keys);
}

TEST(EchKeygen, Base64Roundtrip)
{
    const std::string data = "hello ech keys";
    const auto encoded = base64_encode(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
    EXPECT_FALSE(encoded.empty());

    psm::memory::vector<std::uint8_t> decoded;
    ASSERT_TRUE(base64_decode(encoded, decoded));
    EXPECT_EQ(decoded.size(), data.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(decoded.data()), decoded.size()), data);
}

TEST(EchKeygen, Base64PrivateKeyRoundtrip)
{
    ech_keypair kp;
    ASSERT_EQ(generate_keypair("example.com", 64, kp), psm::fault::code::success);

    const auto encoded = base64_encode(kp.private_key);
    psm::memory::vector<std::uint8_t> decoded;
    ASSERT_TRUE(base64_decode(encoded, decoded));
    ASSERT_EQ(decoded.size(), 32);
    EXPECT_EQ(std::memcmp(decoded.data(), kp.private_key.data(), 32), 0);
}
