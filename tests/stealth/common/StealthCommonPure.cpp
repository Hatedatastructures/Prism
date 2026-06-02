/**
 * @file StealthCommonPure.cpp
 * @brief 伪装层共享纯函数单元测试
 * @details 覆盖 stealth::common 中的 aead_nonce、record_ad、xor_key 三个内联函数。
 */

#include <gtest/gtest.h>

#include <prism/stealth/common.hpp>

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    TEST(StealthCommonPure, AeadNonceZeroSequence)
    {
        const std::uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        auto nonce = psm::stealth::common::aead_nonce(iv, 0);
        EXPECT_TRUE(std::memcmp(nonce.data(), iv, 12) == 0)
            << "aead_nonce: sequence=0 返回原始 IV";
    }

    TEST(StealthCommonPure, AeadNonceNonZeroSequence)
    {
        const std::uint8_t iv[12] = {};
        auto nonce = psm::stealth::common::aead_nonce(iv, 1);
        EXPECT_TRUE(nonce[11] == 0x01) << "aead_nonce: sequence=1 仅影响最后字节";
        for (int i = 0; i < 11; ++i)
        {
            EXPECT_TRUE(nonce[i] == 0x00) << "aead_nonce: sequence=1 高位不变";
        }
    }

    TEST(StealthCommonPure, AeadNonceLargeSequence)
    {
        const std::uint8_t iv[12] = {};
        auto nonce = psm::stealth::common::aead_nonce(iv, 0x0102030405060708ULL);
        EXPECT_TRUE(nonce[4] == 0x01) << "aead_nonce: 大序列号 byte 4";
        EXPECT_TRUE(nonce[11] == 0x08) << "aead_nonce: 大序列号 byte 11";
    }

    TEST(StealthCommonPure, AeadNonceXorOverlap)
    {
        const std::uint8_t iv[12] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        auto nonce = psm::stealth::common::aead_nonce(iv, 0xFF);
        EXPECT_TRUE(nonce[11] == 0x00) << "aead_nonce: XOR 0xFF^0xFF=0";
        EXPECT_TRUE(nonce[10] == 0xFF) << "aead_nonce: 未影响位保持 0xFF";
    }

    TEST(StealthCommonPure, RecordAdZeroLength)
    {
        auto ad = psm::stealth::common::record_ad(0);
        EXPECT_TRUE(ad[0] == 0x17) << "record_ad: content type=0x17";
        EXPECT_TRUE(ad[1] == 0x03 && ad[2] == 0x03) << "record_ad: version=0x0303";
        EXPECT_TRUE(ad[3] == 0x00 && ad[4] == 0x00) << "record_ad: len=0";
    }

    TEST(StealthCommonPure, RecordAdMaxLength)
    {
        auto ad = psm::stealth::common::record_ad(0xFFFF);
        EXPECT_TRUE(ad[3] == 0xFF && ad[4] == 0xFF) << "record_ad: len=0xFFFF";
    }

    TEST(StealthCommonPure, RecordAdTypicalLength)
    {
        auto ad = psm::stealth::common::record_ad(0x0102);
        EXPECT_TRUE(ad[3] == 0x01 && ad[4] == 0x02) << "record_ad: len=258";
    }

    TEST(StealthCommonPure, XorKeyBasic)
    {
        std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        const std::uint8_t key[] = {0x01, 0x02, 0x03};
        psm::stealth::common::xor_key(data, key);
        EXPECT_TRUE(data[0] == std::byte{0xAB}) << "xor_key: byte 0 = 0xAA^0x01";
        EXPECT_TRUE(data[1] == std::byte{0xB9}) << "xor_key: byte 1 = 0xBB^0x02";
        EXPECT_TRUE(data[2] == std::byte{0xCF}) << "xor_key: byte 2 = 0xCC^0x03";
    }

    TEST(StealthCommonPure, XorKeyShortKeyCycles)
    {
        std::byte data[] = {std::byte{0x0F}, std::byte{0xF0}, std::byte{0x0F}, std::byte{0xF0}};
        const std::uint8_t key[] = {0xFF};
        psm::stealth::common::xor_key(data, key);
        EXPECT_TRUE(data[0] == std::byte{0xF0}) << "xor_key: 单字节密钥循环 byte 0";
        EXPECT_TRUE(data[1] == std::byte{0x0F}) << "xor_key: 单字节密钥循环 byte 1";
        EXPECT_TRUE(data[2] == std::byte{0xF0}) << "xor_key: 单字节密钥循环 byte 2";
        EXPECT_TRUE(data[3] == std::byte{0x0F}) << "xor_key: 单字节密钥循环 byte 3";
    }

    TEST(StealthCommonPure, XorKeySelfInverse)
    {
        const std::byte original[] = {std::byte{0x12}, std::byte{0x34}, std::byte{0x56}};
        std::byte data[3];
        std::memcpy(data, original, 3);
        const std::uint8_t key[] = {0xAB, 0xCD};
        psm::stealth::common::xor_key(data, key);
        psm::stealth::common::xor_key(data, key);
        EXPECT_TRUE(std::memcmp(data, original, 3) == 0)
            << "xor_key: 两次异或恢复原始数据";
    }

    TEST(StealthCommonPure, XorKeyEmptyData)
    {
        std::byte data[1] = {std::byte{0x42}};
        const std::uint8_t key[] = {0xFF};
        psm::stealth::common::xor_key(std::span<std::byte>{}, key);
        EXPECT_TRUE(data[0] == std::byte{0x42}) << "xor_key: 空数据不修改任何内容";
    }

} // namespace
