/**
 * @file EchDecrypt.cpp
 * @brief ECH 解密单元测试
 * @details 覆盖 ech/util/decrypt.cpp 的三个分支：
 *          payload 太短、version 错误、正确 version 但未实现。
 */

#include <prism/stealth/ech/util/decrypt.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstddef>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace ech = psm::stealth::ech;

    void TestPayloadTooShort(TestRunner &runner)
    {
        // 6 字节 < 7 → badpayload
        const std::byte data[6]{};
        auto result = ech::decrypt_ech_payload(data, "dummy-key");
        runner.Check(result.error == psm::fault::code::badpayload,
                     "ech: payload too short → badpayload");
    }

    void TestPayloadEmpty(TestRunner &runner)
    {
        std::span<const std::byte> empty;
        auto result = ech::decrypt_ech_payload(empty, "key");
        runner.Check(result.error == psm::fault::code::badpayload,
                     "ech: empty payload → badpayload");
    }

    void TestWrongVersion(TestRunner &runner)
    {
        // 8 字节但 version = 0x0303 (TLS 1.2)
        const std::byte data[] = {
            std::byte{0x03}, std::byte{0x03}, // version = 0x0303
            std::byte{0x00}, std::byte{0x01}, // config_id + enc_len
            std::byte{0x00}, std::byte{0x02}, // payload_len
            std::byte{0xAA}, std::byte{0xBB}};
        auto result = ech::decrypt_ech_payload(data, "key");
        runner.Check(result.error == psm::fault::code::badver,
                     "ech: wrong version → badver");
    }

    void TestCorrectVersionNotSupported(TestRunner &runner)
    {
        // 8 字节且 version = 0xfe0d
        const std::byte data[] = {
            std::byte{0xfe}, std::byte{0x0d}, // version = 0xfe0d
            std::byte{0x01},                   // config_id
            std::byte{0x00}, std::byte{0x01}, // enc_len
            std::byte{0x00}, std::byte{0x02}, // payload_len
            std::byte{0xCC}};
        auto result = ech::decrypt_ech_payload(data, "key");
        runner.Check(result.error == psm::fault::code::not_supported,
                     "ech: correct version → not_supported");
        runner.Check(!result.valid, "ech: not_supported → valid=false");
    }

    void TestExactly7BytesBadVersion(TestRunner &runner)
    {
        const std::byte data[] = {
            std::byte{0x00}, std::byte{0x00}, // version = 0x0000
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};
        auto result = ech::decrypt_ech_payload(data, {});
        runner.Check(result.error == psm::fault::code::badver,
                     "ech: exactly 7 bytes bad version → badver");
    }

    void TestExactly7BytesCorrectVersion(TestRunner &runner)
    {
        const std::byte data[] = {
            std::byte{0xfe}, std::byte{0x0d},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};
        auto result = ech::decrypt_ech_payload(data, {});
        runner.Check(result.error == psm::fault::code::not_supported,
                     "ech: exactly 7 bytes correct version → not_supported");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::trace::init({});

    TestRunner runner("EchDecrypt");

    TestPayloadTooShort(runner);
    TestPayloadEmpty(runner);
    TestWrongVersion(runner);
    TestCorrectVersionNotSupported(runner);
    TestExactly7BytesBadVersion(runner);
    TestExactly7BytesCorrectVersion(runner);

    return runner.Summary();
}
