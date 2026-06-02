/**
 * @file RealityResponse.cpp
 * @brief Reality response 生成器单元测试
 * @details 测试 make_record（纯序列化）和 encrypt_record（确定性 AEAD 加密），
 *          以及 generate_shello 的结构化输出验证。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/util/response.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/fault.hpp>

#include <cstdint>
#include <cstring>

namespace
{
    namespace tls = psm::protocol::tls;
    namespace reality = psm::stealth::reality;

    TEST(RealityResponse, MakeRecordEmpty)
    {
        std::span<const std::uint8_t> payload;
        auto rec = reality::make_record(tls::CT_HANDSHAKE, payload);

        // [ContentType=0x16][Version=0x0303][Length=0x0000] = 5 bytes
        EXPECT_TRUE(rec.size() == 5) << "make_record empty: size=5";
        EXPECT_TRUE(rec[0] == tls::CT_HANDSHAKE) << "make_record empty: content_type";
        EXPECT_TRUE(rec[1] == 0x03 && rec[2] == 0x03) << "make_record empty: version=0x0303";
        EXPECT_TRUE(rec[3] == 0x00 && rec[4] == 0x00) << "make_record empty: length=0";
    }

    TEST(RealityResponse, MakeRecordWithPayload)
    {
        const std::uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
        auto rec = reality::make_record(tls::CT_APPLICATION_DATA,
            std::span<const std::uint8_t>{payload, 4});

        EXPECT_TRUE(rec.size() == 5 + 4) << "make_record payload: size=9";
        EXPECT_TRUE(rec[0] == tls::CT_APPLICATION_DATA) << "make_record payload: content_type=0x17";
        EXPECT_TRUE(rec[3] == 0x00 && rec[4] == 0x04) << "make_record payload: length=4";
        EXPECT_TRUE(rec[5] == 0x01 && rec[6] == 0x02) << "make_record payload: data[0..1]";
    }

    TEST(RealityResponse, MakeRecordChangeCipherSpec)
    {
        const std::uint8_t payload[] = {0x01};
        auto rec = reality::make_record(tls::CT_CHANGE_CIPHER_SPEC,
            std::span<const std::uint8_t>{payload, 1});

        EXPECT_TRUE(rec.size() == 6) << "make_record ccs: size=6";
        EXPECT_TRUE(rec[0] == tls::CT_CHANGE_CIPHER_SPEC) << "make_record ccs: content_type=0x14";
        EXPECT_TRUE(rec[3] == 0x00 && rec[4] == 0x01) << "make_record ccs: length=1";
        EXPECT_TRUE(rec[5] == 0x01) << "make_record ccs: payload=0x01";
    }

    TEST(RealityResponse, EncryptRecordDeterministic)
    {
        // 固定 key 和 IV
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, 12> iv{};
        for (std::size_t i = 0; i < 12; ++i)
            iv[i] = static_cast<std::uint8_t>(i + 1);

        const std::uint8_t plaintext[] = {0xAA, 0xBB, 0xCC};

        reality::encrypt_params params{
            key, iv, 0, tls::CT_HANDSHAKE, plaintext};

        auto [ec1, rec1] = reality::encrypt_record(params);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "encrypt_record: success";

        // 密文记录应 > 5 + plaintext + 1(content_type) + 16(tag) = 5 + 3 + 1 + 16 = 25
        EXPECT_TRUE(rec1.size() > 20) << "encrypt_record: output size > 20";
        EXPECT_TRUE(rec1[0] == tls::CT_APPLICATION_DATA) << "encrypt_record: content_type=0x17";

        // 相同输入应产生相同密文（确定性）
        auto [ec2, rec2] = reality::encrypt_record(params);
        EXPECT_TRUE(ec2 == psm::fault::code::success) << "encrypt_record 2: success";
        EXPECT_TRUE(rec1.size() == rec2.size()) << "encrypt_record: deterministic size";
        EXPECT_TRUE(std::memcmp(rec1.data(), rec2.data(), rec1.size()) == 0)
                     << "encrypt_record: deterministic bytes";
    }

    TEST(RealityResponse, EncryptRecordDifferentSequence)
    {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, 12> iv{};
        for (std::size_t i = 0; i < 12; ++i)
            iv[i] = static_cast<std::uint8_t>(i + 1);

        const std::uint8_t plaintext[] = {0xDE, 0xAD};

        reality::encrypt_params p1{key, iv, 0, tls::CT_HANDSHAKE, plaintext};
        reality::encrypt_params p2{key, iv, 1, tls::CT_HANDSHAKE, plaintext};

        auto [ec1, r1] = reality::encrypt_record(p1);
        auto [ec2, r2] = reality::encrypt_record(p2);

        EXPECT_TRUE(ec1 == psm::fault::code::success) << "encrypt seq 0: success";
        EXPECT_TRUE(ec2 == psm::fault::code::success) << "encrypt seq 1: success";
        EXPECT_TRUE(std::memcmp(r1.data(), r2.data(), r1.size()) != 0)
                     << "encrypt_record: different sequence → different ciphertext";
    }

    TEST(RealityResponse, EncryptRecordEmptyPlaintext)
    {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, 12> iv{};
        for (std::size_t i = 0; i < 12; ++i)
            iv[i] = static_cast<std::uint8_t>(i + 1);

        std::span<const std::uint8_t> empty;
        reality::encrypt_params params{
            key, iv, 0, tls::CT_APPLICATION_DATA, empty};

        auto [ec, rec] = reality::encrypt_record(params);
        EXPECT_TRUE(ec == psm::fault::code::success) << "encrypt empty: success";
        // inner = content_type(1) + tag(16) = 17 bytes encrypted, plus 5-byte record header
        EXPECT_TRUE(rec.size() == 5 + 1 + 16) << "encrypt empty: size=22";
    }

    TEST(RealityResponse, EncryptRecordRecordHeader)
    {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, 12> iv{};
        for (std::size_t i = 0; i < 12; ++i)
            iv[i] = static_cast<std::uint8_t>(i + 1);

        const std::uint8_t payload[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        reality::encrypt_params params{
            key, iv, 42, tls::CT_HANDSHAKE, payload};

        auto [ec, rec] = reality::encrypt_record(params);
        EXPECT_TRUE(ec == psm::fault::code::success) << "encrypt header: success";

        // 验证 record header: CT=0x17, version=0x0303
        EXPECT_TRUE(rec[0] == 0x17) << "encrypt header: ct=0x17";
        EXPECT_TRUE(rec[1] == 0x03) << "encrypt header: version hi=0x03";
        EXPECT_TRUE(rec[2] == 0x03) << "encrypt header: version lo=0x03";

        // length field should match remaining bytes
        const auto len = (static_cast<std::uint16_t>(rec[3]) << 8) | rec[4];
        EXPECT_TRUE(len == rec.size() - 5) << "encrypt header: length matches";
    }

    TEST(RealityResponse, GenerateShelloBasic)
    {
        // 构造最小的 ClientHello features
        tls::hello_features features;
        features.session_id_len = 0;
        features.session_id = {};
        features.has_x25519 = true;
        features.x25519_key.fill(0x42);

        // 服务端临时公钥 (X25519, 32 bytes)
        std::array<std::uint8_t, 32> eph_pub{};
        for (std::size_t i = 0; i < 32; ++i)
            eph_pub[i] = static_cast<std::uint8_t>(i + 1);

        // 构造 shared_secret → derive_hs_keys
        std::array<std::uint8_t, 32> shared_secret{};
        for (std::size_t i = 0; i < 32; ++i)
            shared_secret[i] = static_cast<std::uint8_t>(i + 0xAA);

        // 构造一个最小的 ClientHello 消息字节（至少 4 字节）
        psm::memory::vector<std::uint8_t> fake_chello;
        fake_chello.insert(fake_chello.end(), {0x01, 0x00, 0x00, 0x10}); // minimal handshake header
        fake_chello.insert(fake_chello.end(), 16, 0x00);

        // 先派生握手密钥（需要 shello_msg 但可先用空串占位）
        // 实际 generate_shello 需要有效的 key_material，这里构造一个
        reality::key_material keys{};
        for (std::size_t i = 0; i < 16; ++i)
        {
            keys.server_hskey[i] = static_cast<std::uint8_t>(i + 1);
            keys.server_hsiv[i % 12] = static_cast<std::uint8_t>(i + 1);
            keys.server_finkey[i] = static_cast<std::uint8_t>(i + 0x80);
            keys.master_secret[i] = static_cast<std::uint8_t>(i + 0x40);
        }

        // 目标证书 (fake DER, 不需要有效)
        const std::uint8_t fake_cert[] = {0x30, 0x82, 0x01, 0x00};

        // auth_key (32 bytes)
        std::array<std::uint8_t, 32> auth_key{};
        for (std::size_t i = 0; i < 32; ++i)
            auth_key[i] = static_cast<std::uint8_t>(i + 0x55);

        reality::hello_request req{
            features,
            eph_pub,
            keys,
            fake_cert,
            fake_chello,
            auth_key};

        auto [ec, result] = reality::generate_shello(req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "generate_shello: success";

        // shello_msg 不应为空
        EXPECT_TRUE(!result.shello_msg.empty()) << "generate_shello: shello_msg not empty";
        // shello_record 不应为空，且以 CT_HANDSHAKE 开头
        EXPECT_TRUE(!result.shello_record.empty()) << "generate_shello: shello_record not empty";
        EXPECT_TRUE(result.shello_record[0] == tls::CT_HANDSHAKE) << "generate_shello: record ct=0x16";

        // ccs_record 应为 6 字节: [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        EXPECT_TRUE(result.ccs_record.size() == 6) << "generate_shello: ccs_record size=6";
        EXPECT_TRUE(result.ccs_record[0] == tls::CT_CHANGE_CIPHER_SPEC) << "generate_shello: ccs ct=0x14";

        // enc_hs_record 不应为空
        EXPECT_TRUE(!result.enc_hs_record.empty()) << "generate_shello: enc_hs_record not empty";
        EXPECT_TRUE(result.enc_hs_record[0] == tls::CT_APPLICATION_DATA) << "generate_shello: enc_hs ct=0x17";

        // enc_hs_plain 不应为空（包含 EncryptedExtensions + Certificate + CertVerify + Finished）
        EXPECT_TRUE(!result.enc_hs_plain.empty()) << "generate_shello: enc_hs_plain not empty";
    }

    TEST(RealityResponse, GenerateShelloNoAuthKey)
    {
        tls::hello_features features;
        features.session_id_len = 4;
        features.session_id = {0x01, 0x02, 0x03, 0x04};
        features.has_x25519 = true;

        std::array<std::uint8_t, 32> eph_pub{};
        eph_pub[0] = 0xFF;

        reality::key_material keys{};
        for (std::size_t i = 0; i < 16; ++i)
        {
            keys.server_hskey[i] = static_cast<std::uint8_t>(i + 1);
            keys.server_hsiv[i % 12] = static_cast<std::uint8_t>(i + 1);
            keys.server_finkey[i] = static_cast<std::uint8_t>(i + 0x80);
            keys.master_secret[i] = static_cast<std::uint8_t>(i + 0x40);
        }

        psm::memory::vector<std::uint8_t> fake_chello;
        fake_chello.insert(fake_chello.end(), 20, 0xAA);

        const std::uint8_t fake_cert[] = {0x30, 0x01, 0x02};

        reality::hello_request req{
            features,
            eph_pub,
            keys,
            fake_cert,
            fake_chello,
            {}}; // 空 auth_key → 使用 dest_certificate

        auto [ec, result] = reality::generate_shello(req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "generate_shello no auth: success";
        EXPECT_TRUE(!result.shello_msg.empty()) << "generate_shello no auth: shello_msg not empty";
        EXPECT_TRUE(!result.enc_hs_record.empty()) << "generate_shello no auth: enc_hs_record not empty";
    }

} // namespace
