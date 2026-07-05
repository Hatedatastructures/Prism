/**
 * @file RestlsTransportPure.cpp
 * @brief Restls transport 纯函数测试
 * @details 测试 transport.cpp 中匿名命名空间的纯函数：
 *          decode_restls_payload。
 *          通过 #include 源文件覆盖编译行。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>

// #include 源文件增加覆盖率计数
#include "../../src/prism/stealth/facade/restls/transport.cpp"

namespace
{
    using namespace psm::stealth::restls;

    // 辅助：构造有效 restls payload 并返回
    // decode 内部流程：读 MAC → 取 plaintext_sample[12+] → 算 mask → XOR[8..11] →
    //                 取 payload_after_mac[8+]（此时已是明文）→ 算 auth_mac → 比对
    // 所以 wire 格式 = [MAC 8B][masked_len 2B][masked_cmd 2B][data/padding]
    // 构造顺序：先设明文 → 算 mask → 算 auth_mac（从明文 [8+]）→ 写 MAC → XOR 掩码

    auto build_valid_payload(
        std::span<const std::uint8_t, 32> secret,
        std::span<const std::uint8_t, 32> server_random,
        std::uint64_t counter,
        const std::array<std::uint8_t, tls_hdrsize> &tls_hdr,
        std::uint16_t data_len_val,
        std::uint16_t cmd_val,
        const std::uint8_t *extra_data,
        std::size_t extra_size)
        -> psm::memory::vector<std::byte>
    {
        const std::size_t total = auth_hdrlen + extra_size;
        psm::memory::vector<std::byte> payload(total, std::byte{0x00});
        auto *raw = reinterpret_cast<std::uint8_t *>(payload.data());

        // 填充 extra data at [auth_hdrlen+]
        if (extra_size > 0 && extra_data != nullptr)
        {
            std::memcpy(raw + auth_hdrlen, extra_data, extra_size);
        }

        // 设明文 len/cmd at [8..11]
        raw[appdata_lenoff] = static_cast<std::uint8_t>((data_len_val >> 8) & 0xFF);
        raw[appdata_lenoff + 1] = static_cast<std::uint8_t>(data_len_val & 0xFF);
        raw[appdata_lenoff + 2] = static_cast<std::uint8_t>((cmd_val >> 8) & 0xFF);
        raw[appdata_lenoff + 3] = static_cast<std::uint8_t>(cmd_val & 0xFF);

        // plaintext_sample = [12+], decode 读的是 XOR 之前的数据
        const std::size_t sample_len = std::min(total - appdata_offset, std::size_t{32});
        auto plaintext_sample = std::span<const std::uint8_t>(raw + appdata_offset, sample_len);

        auto mask = compute_mask(mask_input{secret, server_random,
            flow_direction::to_client, counter, plaintext_sample});

        // auth_mac 从明文 [8+] 计算（decode XOR 后 payload_after_mac 就是明文）
        auto payload_after_mac = std::span<const std::uint8_t>(raw + appdata_lenoff, total - appdata_lenoff);
        auto expected_mac = compute_auth_mac(auth_mac_input{
            secret, server_random, flow_direction::to_client,
            counter, {}, tls_hdr, payload_after_mac});
        std::memcpy(raw, expected_mac.data(), appdata_maclen);

        // 最后 XOR 掩码 [8..11]（wire 格式 = masked）
        xor_with_mask(std::span<std::uint8_t>(raw + appdata_lenoff, mask_len), mask);

        return payload;
    }

    // ─── decode_restls_payload ─────────────────────

    TEST(RestlsTransportPure, DecodePayloadTooShort)
    {
        psm::memory::vector<std::byte> payload(5, std::byte{0x00});
        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x0C};
        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec;

        auto result = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(!result.has_value()) << "decode: too short -> nullopt";
        EXPECT_TRUE(ec == std::errc::protocol_error) << "decode: too short -> protocol_error";
    }

    TEST(RestlsTransportPure, DecodePayloadExactAuthHeaderLen)
    {
        std::array<std::uint8_t, 32> secret{};
        for (std::size_t i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::uint8_t>(i + 0x80);

        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x0C};

        auto payload = build_valid_payload(
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr, 0, 0, nullptr, 0);

        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec;

        auto result = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(result.has_value()) << "decode: exact auth_header len -> success";
        EXPECT_TRUE(!ec) << "decode: exact auth_header len -> no error";
        EXPECT_TRUE(result->data_len == 0) << "decode: exact auth_header len -> data_len=0";
        EXPECT_TRUE(result->cmd == 0) << "decode: exact auth_header len -> cmd=0";
    }

    TEST(RestlsTransportPure, DecodePayloadWithData)
    {
        std::array<std::uint8_t, 32> secret{};
        for (std::size_t i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i + 0x10);

        std::array<std::uint8_t, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::uint8_t>(i + 0x20);

        const std::size_t data_size = 8;
        std::array<std::uint8_t, data_size> data{};
        for (std::size_t i = 0; i < data_size; ++i)
            data[i] = static_cast<std::uint8_t>(i + 0xAA);

        const std::size_t total = auth_hdrlen + data_size;
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
        tls_hdr[0] = 0x17;
        tls_hdr[1] = 0x03;
        tls_hdr[2] = 0x03;
        tls_hdr[3] = static_cast<std::uint8_t>((total >> 8) & 0xFF);
        tls_hdr[4] = static_cast<std::uint8_t>(total & 0xFF);

        auto payload = build_valid_payload(
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            1, tls_hdr, static_cast<std::uint16_t>(data_size), 0,
            data.data(), data_size);

        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            1, tls_hdr};
        std::error_code ec;

        auto result = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(result.has_value()) << "decode: with data -> success";
        EXPECT_TRUE(!ec) << "decode: with data -> no error";
        EXPECT_TRUE(result->data_len == data_size) << "decode: with data -> data_len=8";
        EXPECT_TRUE(result->cmd == 0) << "decode: with data -> cmd=0";
    }

    TEST(RestlsTransportPure, DecodePayloadMacMismatch)
    {
        psm::memory::vector<std::byte> payload(auth_hdrlen + 4, std::byte{0x00});

        std::array<std::uint8_t, 32> secret{};
        for (std::size_t i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i);

        std::array<std::uint8_t, 32> server_random{};
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x10};

        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec;

        auto result = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(!result.has_value()) << "decode: bad MAC -> nullopt";
        EXPECT_TRUE(ec == std::errc::permission_denied) << "decode: bad MAC -> permission_denied";
    }

    TEST(RestlsTransportPure, DecodePayloadDifferentCounter)
    {
        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x0C};

        // counter=0 的 payload
        auto payload0 = build_valid_payload(
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr, 0, 0, nullptr, 0);

        decode_options opts0{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec0;
        auto r0 = decode_restls_payload(payload0, opts0, ec0);
        EXPECT_TRUE(r0.has_value()) << "decode: counter=0 -> success";

        // counter=0 的 payload 不能用 counter=1 解码
        decode_options opts1{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            1, tls_hdr};
        std::error_code ec1;
        psm::memory::vector<std::byte> payload1_copy(payload0.begin(), payload0.end());
        auto r1 = decode_restls_payload(payload1_copy, opts1, ec1);
        EXPECT_TRUE(!r1.has_value()) << "decode: wrong counter -> fail";
    }

    TEST(RestlsTransportPure, DecodePayloadWithCloseCmd)
    {
        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x0C};

        auto payload = build_valid_payload(
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr, 0, cmd_close, nullptr, 0);

        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec;
        auto r = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(r.has_value()) << "decode: close cmd -> success";
        EXPECT_TRUE(r->cmd == cmd_close) << "decode: close cmd -> cmd=0x0001";
        EXPECT_TRUE(r->data_len == 0) << "decode: close cmd -> data_len=0";
    }

    TEST(RestlsTransportPure, DecodePayloadWithRandrespCmd)
    {
        std::array<std::uint8_t, 32> secret{};
        for (std::size_t i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i + 0x55);
        std::array<std::uint8_t, 32> server_random{};
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x0C};

        auto payload = build_valid_payload(
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr, 0, cmd_randresp, nullptr, 0);

        decode_options opts{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            0, tls_hdr};
        std::error_code ec;
        auto r = decode_restls_payload(payload, opts, ec);
        EXPECT_TRUE(r.has_value()) << "decode: randresp cmd -> success";
        EXPECT_TRUE(r->cmd == cmd_randresp) << "decode: randresp cmd -> cmd=0x0002";
    }

} // namespace
