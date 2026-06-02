/**
 * @file EchDecrypt.cpp
 * @brief ECH 解密单元测试
 * @details 覆盖 ech/util/decrypt.cpp 的三个分支：
 *          payload 太短、version 错误、正确 version 但未实现。
 */

#include <prism/stealth/ech/util/decrypt.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <cstddef>

namespace
{
    namespace ech = psm::stealth::ech;

    TEST(EchDecrypt, PayloadTooShort)
    {
        // 6 字节 < 7 → badpayload
        const std::byte data[6]{};
        auto result = ech::decrypt_ech_payload(data, "dummy-key");
        EXPECT_TRUE(result.error == psm::fault::code::badpayload)
            << "ech: payload too short -> badpayload";
    }

    TEST(EchDecrypt, PayloadEmpty)
    {
        std::span<const std::byte> empty;
        auto result = ech::decrypt_ech_payload(empty, "key");
        EXPECT_TRUE(result.error == psm::fault::code::badpayload)
            << "ech: empty payload -> badpayload";
    }

    TEST(EchDecrypt, WrongVersion)
    {
        // 8 字节但 version = 0x0303 (TLS 1.2)
        const std::byte data[] = {
            std::byte{0x03}, std::byte{0x03}, // version = 0x0303
            std::byte{0x00}, std::byte{0x01}, // config_id + enc_len
            std::byte{0x00}, std::byte{0x02}, // payload_len
            std::byte{0xAA}, std::byte{0xBB}};
        auto result = ech::decrypt_ech_payload(data, "key");
        EXPECT_TRUE(result.error == psm::fault::code::badver)
            << "ech: wrong version -> badver";
    }

    TEST(EchDecrypt, CorrectVersionNotSupported)
    {
        // 8 字节且 version = 0xfe0d
        const std::byte data[] = {
            std::byte{0xfe}, std::byte{0x0d}, // version = 0xfe0d
            std::byte{0x01},                   // config_id
            std::byte{0x00}, std::byte{0x01}, // enc_len
            std::byte{0x00}, std::byte{0x02}, // payload_len
            std::byte{0xCC}};
        auto result = ech::decrypt_ech_payload(data, "key");
        EXPECT_TRUE(result.error == psm::fault::code::not_supported)
            << "ech: correct version -> not_supported";
        EXPECT_TRUE(!result.valid) << "ech: not_supported -> valid=false";
    }

    TEST(EchDecrypt, Exactly7BytesBadVersion)
    {
        const std::byte data[] = {
            std::byte{0x00}, std::byte{0x00}, // version = 0x0000
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};
        auto result = ech::decrypt_ech_payload(data, {});
        EXPECT_TRUE(result.error == psm::fault::code::badver)
            << "ech: exactly 7 bytes bad version -> badver";
    }

    TEST(EchDecrypt, Exactly7BytesCorrectVersion)
    {
        const std::byte data[] = {
            std::byte{0xfe}, std::byte{0x0d},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};
        auto result = ech::decrypt_ech_payload(data, {});
        EXPECT_TRUE(result.error == psm::fault::code::not_supported)
            << "ech: exactly 7 bytes correct version -> not_supported";
    }
} // namespace
