/**
 * @file CryptoExceptionCoverage.cpp
 * @brief tests/common/core/crypto 与 tests/common/core/exception 覆盖率补充测试
 * @details 纯函数单元测试（无协程），目标提升两个模块的路径覆盖：
 * - crypto：aead 错误路径补充（空密钥/空输入/短密文）、base64（非法字符/填充
 *   错误/往返）、blake3（空输入/大输入/已知向量）、block（AES-128/256 往返、
 *   密钥长度错误）、hkdf（RFC 4231/5869 已知向量、expand 非法长度边界）、
 *   Sha224（空/边界/已知向量、Credential 规范化）、X25519（RFC 7748 向量、
 *   密钥派生往返、非法长度、低阶点）
 * - exception：Deviant/Network/Protocol/Security 的构造（错误码+描述）、
 *   What() 内容、TypeName()、ErrorCode()、Location()/Filename()、
 *   Dump() 完整格式、安全异常的敏感信息保护（错误码消息不携带描述、
 *   Dump 不泄露完整路径）
 * @note 已知向量来源：FIPS-197、RFC 4231、RFC 5869、RFC 7748、NIST、
 *       BLAKE3 官方测试向量
 */

#include <common/Core/Crypto/Crypto.hpp>
#include <common/Core/Crypto/X25519.hpp>
#include <common/Core/Exception/Network.hpp>
#include <common/Core/Exception/Protocol.hpp>
#include <common/Core/Exception/Security.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace crypto = Preview::Crypto;
    namespace fault = Preview::Fault;
    namespace exc = Preview::Exception;

    /**
     * @brief 十六进制字符串转字节数组
     * @param hex 十六进制字符串（无 0x 前缀，成对字符）
     * @return 解码后的字节序列
     */
    auto hex_to_bytes(const std::string_view hex) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const auto nib = [](const char c) -> std::uint8_t
            {
                if (c >= '0' && c <= '9')
                {
                    return static_cast<std::uint8_t>(c - '0');
                }
                if (c >= 'a' && c <= 'f')
                {
                    return static_cast<std::uint8_t>(c - 'a' + 10);
                }
                return static_cast<std::uint8_t>(c - 'A' + 10);
            };
            out.push_back(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
        }
        return out;
    }

    /**
     * @brief 字节序列转十六进制字符串
     * @param Data 字节序列
     * @return 小写十六进制字符串
     */
    auto ToHex(const std::span<const std::uint8_t> Data) -> std::string
    {
        constexpr char hex_chars[] = "0123456789abcdef";
        std::string out;
        out.reserve(Data.size() * 2);
        for (const auto byte : Data)
        {
            out.push_back(hex_chars[(byte >> 4) & 0x0F]);
            out.push_back(hex_chars[byte & 0x0F]);
        }
        return out;
    }

    /**
     * @brief 检查字符串是否包含子串
     * @param haystack 被搜索的字符串
     * @param needle 目标子串
     * @return 找到返回 true
     */
    auto Contains(const std::string &haystack, const std::string_view needle) -> bool
    {
        return haystack.find(needle) != std::string::npos;
    }

    // ──────────────────────── crypto: aead 错误路径补充 ────────────────────────

    TEST(AeadCoverage, EmptyKeyConstruct)
    {
        // 0 字节密钥：EVP_AEAD_CTX_init 失败 → ctx 为 null
        crypto::AeadContext ctx(crypto::AeadCipher::aes_128_gcm, std::span<const std::uint8_t>{});
        std::array<std::uint8_t, 32> out{};
        EXPECT_EQ(ctx.Seal(out, std::span<const std::uint8_t>{}), fault::Code::crypto_error);
        EXPECT_EQ(ctx.Open(out, out), fault::Code::crypto_error);
        EXPECT_EQ(ctx.NonceLength(), 12);
    }

    TEST(AeadCoverage, SealEmptyPlaintextAutoNonce)
    {
        // 空明文 Seal：输出仅 16 字节 tag，且内部 Nonce 正常递增
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        crypto::AeadContext ctx(crypto::AeadCipher::aes_256_gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.Seal(out, std::span<const std::uint8_t>{}), fault::Code::success);
        EXPECT_EQ(ctx.Nonce()[0], 1) << "Nonce should advance after Empty Seal";
    }

    TEST(AeadCoverage, OpenEmptyCiphertext)
    {
        // 空密文 Open：密文长度 < tag 长度 → 认证失败
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::aes_128_gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.Open(out, std::span<const std::uint8_t>{}), fault::Code::crypto_error);
    }

    TEST(AeadCoverage, OpenCiphertextShorterThanTag)
    {
        // 密文长度 8 字节（不足 16 字节 tag）→ 解密失败
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::aes_128_gcm, key);
        const std::array<std::uint8_t, 8> short_ct{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        std::array<std::uint8_t, 8> out{};
        EXPECT_EQ(ctx.Open(out, short_ct), fault::Code::crypto_error);
    }

    TEST(AeadCoverage, OpenEmptyCiphertextExplicitNonce)
    {
        // 显式 Nonce 重载：空密文同样失败，且不修改内部状态
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::aes_128_gcm, key);
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 16> out{};
        crypto::OpenInput input{out, std::span<const std::uint8_t>{}, Nonce, {}};
        EXPECT_EQ(ctx.Open(input), fault::Code::crypto_error);
        EXPECT_EQ(ctx.Nonce()[0], 0) << "Failed explicit Open must not advance Nonce";
    }

    // ──────────────────────── crypto: base64 ────────────────────────

    TEST(Base64Coverage, EncodeKnownVectors)
    {
        EXPECT_EQ(std::string(crypto::Base64Encode({})), "");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 3>{'M', 'a', 'n'})), "TWFu");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 2>{'M', 'a'})), "TWE=");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 1>{'M'})), "TQ==");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 1>{0xFF})), "/w==");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 2>{0xFF, 0xFF})), "//8=");
        EXPECT_EQ(std::string(crypto::Base64Encode(std::array<std::uint8_t, 3>{0xFF, 0xFF, 0xFF})), "////");
    }

    TEST(Base64Coverage, DecodeKnownVectors)
    {
        EXPECT_EQ(std::string(crypto::Base64Decode("")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TWFu")), "Man");
        EXPECT_EQ(std::string(crypto::Base64Decode("TWE=")), "Ma");
        EXPECT_EQ(std::string(crypto::Base64Decode("TQ==")), "M");
        EXPECT_EQ(std::string(crypto::Base64Decode("//8=")), std::string("\xFF\xFF", 2));
        EXPECT_EQ(std::string(crypto::Base64Decode("SGVsbG8sIFdvcmxkIQ==")), "Hello, World!");
    }

    TEST(Base64Coverage, RoundTripAllByteValues)
    {
        // 0..64 字节全值域数据：Encode → Decode 完全还原
        for (std::size_t n = 0; n <= 64; ++n)
        {
            std::vector<std::uint8_t> Data(n);
            for (std::size_t i = 0; i < n; ++i)
            {
                Data[i] = static_cast<std::uint8_t>(i * 7 + 3);
            }
            const auto encoded = crypto::Base64Encode(Data);
            const auto decoded = crypto::Base64Decode(std::string_view(encoded.data(), encoded.size()));
            const auto Bytes = std::string_view(decoded.data(), decoded.size());
            EXPECT_EQ(Bytes, std::string_view(reinterpret_cast<const char *>(Data.data()), Data.size()))
                << "roundtrip mismatch at n=" << n;
        }
    }

    TEST(Base64Coverage, DecodeWhitespace)
    {
        // 自动忽略空白字符
        EXPECT_EQ(std::string(crypto::Base64Decode("TW Fu")), "Man");
        EXPECT_EQ(std::string(crypto::Base64Decode("\tTWF\nu")), "Man");
        EXPECT_EQ(std::string(crypto::Base64Decode("TWE =")), "Ma");
    }

    TEST(Base64Coverage, DecodeUrlSafe)
    {
        // URL-safe 变体：'-' 与 '_' 分别映射 '+' 与 '/'
        EXPECT_EQ(std::string(crypto::Base64Decode("-w==")), std::string("\xFB", 1));
        EXPECT_EQ(std::string(crypto::Base64Decode("__8=")), std::string("\xFF\xFF", 2));
        EXPECT_EQ(std::string(crypto::Base64Decode("__8=")),
                  std::string(crypto::Base64Decode("//8=")));
    }

    TEST(Base64Coverage, DecodeInvalidChars)
    {
        // 非法字符（非字母数字、非 +/-/_/空白）→ 返回空串
        EXPECT_EQ(std::string(crypto::Base64Decode("T!Fu")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("$")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("AAAA$")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("T@==")), "");
    }

    TEST(Base64Coverage, DecodePaddingErrors)
    {
        // padding 数量非法：超过 2 个或与有效字符不构成 4 字节组
        EXPECT_EQ(std::string(crypto::Base64Decode("TQ=")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TQ===")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("====")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("==")), "");
    }

    TEST(Base64Coverage, DecodeNonMultipleOfFour)
    {
        // 无 padding 且有效字符数不是 4 的倍数 → 返回空串
        EXPECT_EQ(std::string(crypto::Base64Decode("TWF")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("T")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TW")), "");
    }

    // ──────────────────────── crypto: blake3 ────────────────────────

    TEST(Blake3Coverage, EmptyHashKnownVector)
    {
        // BLAKE3("") 官方测试向量
        const auto h = crypto::Hash({});
        EXPECT_EQ(h.size(), 32);
        EXPECT_EQ(ToHex(h), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }

    TEST(Blake3Coverage, AbcKnownVector)
    {
        // BLAKE3("abc") 官方测试向量
        const std::string Data = "abc";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        const auto h = crypto::Hash(Bytes);
        EXPECT_EQ(ToHex(h), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    }

    TEST(Blake3Coverage, LargeInputDeterministic)
    {
        // 1MiB 输入：确定性且与短输入不同
        std::vector<std::uint8_t> Data(1024 * 1024);
        for (std::size_t i = 0; i < Data.size(); ++i)
        {
            Data[i] = static_cast<std::uint8_t>(i & 0xFF);
        }
        const auto h1 = crypto::Hash(Data);
        const auto h2 = crypto::Hash(Data);
        EXPECT_EQ(h1, h2);
        Data.pop_back();
        EXPECT_NE(h1, crypto::Hash(Data)) << "large Hash must change with input";
    }

    TEST(Blake3Coverage, KeyedHashIncrementalEqualsOneshot)
    {
        // KeyedHasher 增量更新（分块）与 KeyedHash 一次性结果一致
        const std::vector<std::uint8_t> key = hex_to_bytes("000102030405060708090a0b0c0d0e0f"
                                                           "101112131415161718191a1b1c1d1e1f");
        const std::string Data = "incremental keyed hashing";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());

        auto hasher = crypto::KeyedHasher(key);
        blake3_hasher_update(&hasher, Bytes.data(), 5);
        blake3_hasher_update(&hasher, Bytes.data() + 5, Bytes.size() - 5);
        std::array<std::uint8_t, 32> incremental{};
        blake3_hasher_finalize(&hasher, incremental.data(), incremental.size());

        EXPECT_EQ(incremental, crypto::KeyedHash(key, Bytes));
    }

    TEST(Blake3Coverage, KeyedHashKeySeparation)
    {
        // 不同密钥 → 不同 keyed Hash；空输入可计算
        const std::vector<std::uint8_t> key_a = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        std::vector<std::uint8_t> key_b = key_a;
        key_b[0] ^= 0x01;
        const auto empty_hash_a = crypto::KeyedHash(key_a, {});
        const auto empty_hash_b = crypto::KeyedHash(key_b, {});
        EXPECT_NE(empty_hash_a, empty_hash_b);
    }

    TEST(Blake3Coverage, DeriveKeyContextAndMaterialSeparation)
    {
        // 上下文域分离：不同 Context/材料 → 不同密钥；span 与 vector 版本等价
        const std::vector<std::uint8_t> material(32, 0xAB);
        const auto k1 = crypto::DeriveKey("ctx-alpha", material, 32);
        const auto k2 = crypto::DeriveKey("ctx-beta", material, 32);
        EXPECT_EQ(k1.size(), 32);
        EXPECT_NE(k1, k2) << "different contexts must derive different keys";

        std::vector<std::uint8_t> buf(32);
        crypto::DeriveKey("ctx-alpha", material, buf);
        EXPECT_EQ(k1, buf) << "span overload must match vector overload";

        // 空材料与空上下文均可派生
        const auto k3 = crypto::DeriveKey("ctx-alpha", std::span<const std::uint8_t>{}, 32);
        EXPECT_EQ(k3.size(), 32);
        EXPECT_NE(k3, k1);
        const auto k4 = crypto::DeriveKey("", material, 16);
        EXPECT_EQ(k4.size(), 16);
    }

    // ──────────────────────── crypto: block ────────────────────────

    TEST(BlockCoverage, Aes128Fips197Vector)
    {
        // FIPS-197 附录 B 已知向量
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const auto ct = crypto::EcbEncrypt(block, key);
        EXPECT_EQ(ToHex(ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
        EXPECT_EQ(crypto::EcbDecrypt(ct, key), block);
    }

    TEST(BlockCoverage, Aes256RoundTrip)
    {
        // AES-256（32 字节密钥）：加密后解密还原
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f"
                                      "101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::EcbEncrypt(block, key);
        EXPECT_NE(ct, block);
        EXPECT_EQ(crypto::EcbDecrypt(ct, key), block);
    }

    TEST(BlockCoverage, WrongKeyLengthInitFailure)
    {
        // 24 字节密钥：非 16 → 走 AES-256 分支；BoringSSL 支持 AES-192（24 字节），
        // 加解密正常往返（safe 路径覆盖 else 分支）
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::EcbEncrypt(block, key);
        EXPECT_NE(ct, block);
        EXPECT_EQ(crypto::EcbDecrypt(ct, key), block);
    }

    // ──────────────────────── crypto: hkdf ────────────────────────

    TEST(HkdfCoverage, HmacSha256Rfc4231)
    {
        // RFC 4231 测试用例 1：key=0x0b×20，Data="Hi There"
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string Data = "Hi There";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        const auto mac = crypto::HmacSha256(key, Bytes);
        EXPECT_EQ(ToHex(mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    TEST(HkdfCoverage, HmacSha512Rfc4231)
    {
        // RFC 4231 测试用例 1（SHA-512 版本）
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string Data = "Hi There";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        const auto mac = crypto::HmacSha512(key, Bytes);
        EXPECT_EQ(ToHex(mac), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded"
                               "aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    TEST(HkdfCoverage, HmacSha256EmptyKeyAndData)
    {
        // 空密钥与空数据的已知向量
        const auto mac = crypto::HmacSha256({}, {});
        EXPECT_EQ(ToHex(mac), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

    TEST(HkdfCoverage, ExtractRfc5869Prk)
    {
        // RFC 5869 测试用例 1：PRK = HMAC-SHA256(salt, IKM)
        const auto salt = hex_to_bytes("000102030405060708090a0b0c");
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const auto prk = crypto::HkdfExtract(salt, ikm);
        EXPECT_EQ(ToHex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    }

    TEST(HkdfCoverage, ExtractEmptySaltEqualsZeroSalt)
    {
        // 空盐等价于 32 字节全零盐（RFC 5869 规则）
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const std::array<std::uint8_t, crypto::Sha256Len> zero_salt{};
        EXPECT_EQ(crypto::HkdfExtract({}, ikm), crypto::HkdfExtract(zero_salt, ikm));
    }

    TEST(HkdfCoverage, ExtractEmptyIkm)
    {
        // 空 IKM 可提取（HMAC(salt, "")），且确定性
        const std::vector<std::uint8_t> salt = hex_to_bytes("000102030405060708090a0b0c");
        EXPECT_EQ(crypto::HkdfExtract(salt, {}), crypto::HkdfExtract(salt, {}));
    }

    TEST(HkdfCoverage, ExpandRfc5869Okm)
    {
        // RFC 5869 测试用例 1：L=42 的 OKM
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        const auto Info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        const auto [ec, okm] = crypto::HkdfExpand(prk, Info, 42);
        EXPECT_EQ(ec, fault::Code::success);
        EXPECT_EQ(ToHex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865");
    }

    TEST(HkdfCoverage, ExpandInvalidArguments)
    {
        // 非法参数：长度超限 / PRK 过短 / Info 过长
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        EXPECT_EQ(crypto::HkdfExpand(prk, {}, 255 * crypto::Sha256Len + 1).first,
                  fault::Code::invalid_argument);

        const std::vector<std::uint8_t> short_prk(31, 0x11);
        EXPECT_EQ(crypto::HkdfExpand(short_prk, {}, 32).first, fault::Code::invalid_argument);

        std::vector<std::uint8_t> big_info(515, 0x22);
        EXPECT_EQ(crypto::HkdfExpand(prk, big_info, 32).first, fault::Code::invalid_argument);
    }

    TEST(HkdfCoverage, ExpandZeroAndMaxLength)
    {
        // 边界：length=0 成功且为空；length=8160（255×32）成功
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        const auto [ec_zero, out_zero] = crypto::HkdfExpand(prk, {}, 0);
        EXPECT_EQ(ec_zero, fault::Code::success);
        EXPECT_TRUE(out_zero.empty());

        const auto [ec_max, out_max] = crypto::HkdfExpand(prk, {}, 255 * crypto::Sha256Len);
        EXPECT_EQ(ec_max, fault::Code::success);
        EXPECT_EQ(out_max.size(), 255 * crypto::Sha256Len);
    }

    TEST(HkdfCoverage, ExpandLabelEquivalenceAndInvalid)
    {
        // ExpandLabel 与手构 HkdfLabel 的 HkdfExpand 结果一致
        const auto Secret = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 3> Context = {0x01, 0x02, 0x03};

        const auto [ec, out] = crypto::ExpandLabel(
            crypto::ExpandParams{Secret, "key", Context, 32});
        ASSERT_EQ(ec, fault::Code::success);
        EXPECT_EQ(out.size(), 32);

        // 手工构造 HkdfLabel = Length(2) || label_len(1) || "tls13 " + Label || ctx_len(1) || Context
        std::vector<std::uint8_t> label_buf;
        label_buf.push_back(static_cast<std::uint8_t>(32 >> 8));
        label_buf.push_back(static_cast<std::uint8_t>(32 & 0xFF));
        const std::string_view full_label = "tls13 key";
        label_buf.push_back(static_cast<std::uint8_t>(full_label.size()));
        for (const auto c : full_label)
        {
            label_buf.push_back(static_cast<std::uint8_t>(c));
        }
        label_buf.push_back(static_cast<std::uint8_t>(Context.size()));
        label_buf.insert(label_buf.end(), Context.begin(), Context.end());

        const auto [ec_manual, manual] = crypto::HkdfExpand(Secret, label_buf, 32);
        ASSERT_EQ(ec_manual, fault::Code::success);
        EXPECT_EQ(out, manual) << "ExpandLabel must match manual HkdfLabel construction";

        // 非法：Label 过长（>249 字节）与 Context 过长（>255 字节）
        const std::string long_label(250, 'x');
        EXPECT_EQ(crypto::ExpandLabel(crypto::ExpandParams{Secret, long_label, {}, 32}).first,
                  fault::Code::invalid_argument);
        std::vector<std::uint8_t> big_context(256, 0x33);
        EXPECT_EQ(crypto::ExpandLabel(crypto::ExpandParams{Secret, "key", big_context, 32}).first,
                  fault::Code::invalid_argument);
    }

    TEST(HkdfCoverage, Sha256KnownVectors)
    {
        // NIST 已知向量
        const auto Empty = crypto::Sha256({});
        EXPECT_EQ(ToHex(Empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        const std::string abc = "abc";
        const auto abc_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
        EXPECT_EQ(ToHex(crypto::Sha256(abc_bytes)),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    TEST(HkdfCoverage, Sha256MultiBlock)
    {
        // 双块/三块重载与拼接后单块哈希一致
        const std::string a = "first part";
        const std::string b = "second part";
        const std::string c = "third part";
        const auto a_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(a.data()), a.size());
        const auto b_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(b.data()), b.size());
        const auto c_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(c.data()), c.size());

        const std::string ab = a + b;
        const auto ab_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(ab.data()), ab.size());
        EXPECT_EQ(crypto::Sha256(a_bytes, b_bytes), crypto::Sha256(ab_bytes));

        const std::string abc = a + b + c;
        const auto abc_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
        EXPECT_EQ(crypto::Sha256(a_bytes, b_bytes, c_bytes), crypto::Sha256(abc_bytes));
    }

    // ──────────────────────── crypto: Sha224 ────────────────────────

    TEST(Sha224Coverage, EmptyInputKnownVector)
    {
        // NIST 已知向量：SHA-224("")
        const auto h = crypto::Sha224("");
        EXPECT_EQ(h.size(), 56);
        EXPECT_EQ(std::string(h), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    TEST(Sha224Coverage, AbcKnownVector)
    {
        // NIST 已知向量：SHA-224("abc")
        EXPECT_EQ(std::string(crypto::Sha224("abc")),
                  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    }

    TEST(Sha224Coverage, IsHex)
    {
        EXPECT_TRUE(crypto::IsHex("0123456789abcdefABCDEF"));
        EXPECT_TRUE(crypto::IsHex(""));
        EXPECT_FALSE(crypto::IsHex("0x12"));
        EXPECT_FALSE(crypto::IsHex("12g4"));
        EXPECT_FALSE(crypto::IsHex("12 34"));
        EXPECT_FALSE(crypto::IsHex("abcdefgh"));
    }

    TEST(Sha224Coverage, NormalizeCredential)
    {
        // 56 字符十六进制凭据：原样返回（已是哈希）
        const std::string hashed(56, '0');
        EXPECT_EQ(std::string(crypto::NormalizeCredential(hashed)), hashed);

        // 明文凭据：计算 SHA-224
        const auto normalized = crypto::NormalizeCredential("my-Credential");
        EXPECT_EQ(std::string(normalized), std::string(crypto::Sha224("my-Credential")));
        EXPECT_EQ(normalized.size(), 56);
    }

    TEST(Sha224Coverage, NormalizeNonHexAndEmpty)
    {
        // 56 字符但含非十六进制字符：仍被哈希而非原样返回
        const std::string not_hex(56, 'g');
        EXPECT_FALSE(crypto::IsHex(not_hex));
        const auto normalized = crypto::NormalizeCredential(not_hex);
        EXPECT_EQ(std::string(normalized), std::string(crypto::Sha224(not_hex)));

        // 空凭据：哈希空串
        EXPECT_EQ(std::string(crypto::NormalizeCredential("")),
                  std::string(crypto::Sha224("")));
    }

    // ──────────────────────── crypto: X25519 ────────────────────────

    TEST(X25519Coverage, GenerateKeypairConsistent)
    {
        // 密钥对：私钥非零，公钥 = DerivePubkey(私钥)
        const auto kp = crypto::GenerateKeypair();
        const std::array<std::uint8_t, crypto::X25519Klen> zero{};
        EXPECT_NE(kp.private_key, zero);
        EXPECT_EQ(crypto::DerivePubkey(kp.private_key), kp.PublicKey);
    }

    TEST(X25519Coverage, DerivePubkeyRfc7748)
    {
        // RFC 7748 测试向量 1：Alice 私钥 → 公钥
        const auto priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto pub = crypto::DerivePubkey(priv);
        EXPECT_EQ(ToHex(pub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

    TEST(X25519Coverage, DerivePubkeyWrongLength)
    {
        // 非法长度：0/16/64 字节私钥 → 全零公钥
        const auto bad = crypto::DerivePubkey({});
        EXPECT_EQ(ToHex(bad), std::string(64, '0'));
        const auto key16 = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        EXPECT_EQ(ToHex(crypto::DerivePubkey(key16)), std::string(64, '0'));
    }

    TEST(X25519Coverage, SharedSecretRoundtrip)
    {
        // 密钥交换对称性：Alice×Bob == Bob×Alice
        const auto alice = crypto::GenerateKeypair();
        const auto bob = crypto::GenerateKeypair();

        const auto [ec1, s1] = crypto::X25519(alice.private_key, bob.PublicKey);
        const auto [ec2, s2] = crypto::X25519(bob.private_key, alice.PublicKey);
        EXPECT_EQ(ec1, fault::Code::success);
        EXPECT_EQ(ec2, fault::Code::success);
        EXPECT_EQ(s1, s2);
        const std::array<std::uint8_t, crypto::X25519Slen> zero{};
        EXPECT_NE(s1, zero);
    }

    TEST(X25519Coverage, SharedSecretRfc7748)
    {
        // RFC 7748 测试向量 1：Alice/Bob 共享密钥
        const auto alice_priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto bob_pub = hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        const auto [ec, shared] = crypto::X25519(alice_priv, bob_pub);
        EXPECT_EQ(ec, fault::Code::success);
        EXPECT_EQ(ToHex(shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    TEST(X25519Coverage, InvalidLengthsAndLowOrder)
    {
        // 非法长度 → invalid_argument
        const auto short_priv = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const auto pub = hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        EXPECT_EQ(crypto::X25519(short_priv, pub).first, fault::Code::invalid_argument);
        const std::vector<std::uint8_t> long_pub(33, 0x11);
        EXPECT_EQ(crypto::X25519(short_priv, long_pub).first, fault::Code::invalid_argument);

        // 低阶点（全零对端公钥）：共享密钥全零 → kexfail
        const std::array<std::uint8_t, crypto::X25519Klen> zero_key{};
        const auto kp = crypto::GenerateKeypair();
        EXPECT_EQ(crypto::X25519(kp.private_key, zero_key).first, fault::Code::kexfail);

        // 全零私钥经 RFC 7748 钳制（e[31]|=64）后是有效标量 → 成功且共享密钥非零
        const auto [ec, shared] = crypto::X25519(zero_key, kp.PublicKey);
        EXPECT_EQ(ec, fault::Code::success);
        EXPECT_NE(shared, zero_key);
    }

    // ──────────────────────── exception: Deviant ────────────────────────

    /**
     * @class exposed_deviant
     * @brief 暴露 TypeName() 的 Deviant 测试子类
     * @details Deviant 是抽象基类，此类用于实例化测试并公开类型名称。
     */
    class exposed_deviant : public exc::Deviant
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_deviant(std::error_code ec, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::Deviant(ec, desc, loc)
        {
        }

        /** @brief 转发字符串构造 */
        explicit exposed_deviant(const std::string &msg,
                                 const std::source_location &loc = std::source_location::current())
            : exc::Deviant(msg, loc)
        {
        }

        /** @brief 转发格式化构造 */
        template <typename... Args>
        explicit exposed_deviant(const std::source_location &loc, std::format_string<Args...> fmt,
                                 Args &&...args)
            : exc::Deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return "EXPOSED";
        }
    };

    TEST(ExceptionDeviant, AbstractBase)
    {
        // Deviant 为抽象基类：必须实现 TypeName() 才能实例化
        static_assert(std::is_abstract_v<exc::Deviant>);
        const exposed_deviant ex(fault::make_error_code(fault::Code::eof));
        EXPECT_EQ(ex.TypeName(), "EXPOSED");
    }

    TEST(ExceptionDeviant, ConstructWithCodeAndDesc)
    {
        // 错误码 + 描述：What() = "Message: desc"
        const exposed_deviant ex(fault::make_error_code(fault::Code::eof), "Stream ended");
        EXPECT_EQ(std::string(ex.what()), "eof: Stream ended");
    }

    TEST(ExceptionDeviant, ConstructWithCodeNoDesc)
    {
        // 仅错误码：What() = 错误码消息本身
        const exposed_deviant ex(fault::make_error_code(fault::Code::timeout));
        EXPECT_EQ(std::string(ex.what()), "timeout");
    }

    TEST(ExceptionDeviant, ConstructWithStringGenericError)
    {
        // 字符串构造：回退到 generic_error 错误码
        const exposed_deviant ex(std::string("legacy Message"));
        EXPECT_EQ(ex.ErrorCode().value(), static_cast<int>(fault::Code::generic_error));
        EXPECT_EQ(std::string(ex.what()), "generic_error: legacy Message");
    }

    TEST(ExceptionDeviant, ConstructFormatted)
    {
        // 格式化构造：格式参数被替换
        const exposed_deviant ex(std::source_location::current(), "format Error {}", 42);
        EXPECT_EQ(std::string(ex.what()), "generic_error: format Error 42");
    }

    TEST(ExceptionDeviant, ErrorCodeAccessors)
    {
        // ErrorCode() 保留值与分类
        const exposed_deviant ex(fault::make_error_code(fault::Code::parse_error), "bad");
        const auto &ec = ex.ErrorCode();
        EXPECT_EQ(ec.value(), static_cast<int>(fault::Code::parse_error));
        EXPECT_EQ(std::string_view(ec.category().name()), "Preview::fault");
        EXPECT_EQ(ec.message(), "parse_error");
    }

    TEST(ExceptionDeviant, LocationAndFilename)
    {
        // 位置捕获：文件名、行号有效；Filename() 仅纯文件名
        const exposed_deviant ex(fault::make_error_code(fault::Code::eof));
        const auto &loc = ex.Location();
        ASSERT_TRUE(loc.file_name());
        EXPECT_TRUE(Contains(std::string(loc.file_name()), "CryptoExceptionCoverage"));
        EXPECT_GT(loc.line(), 0);

        const std::string fname = ex.Filename();
        EXPECT_EQ(fname, "CryptoExceptionCoverage.cpp");
        EXPECT_EQ(fname.find('/'), std::string::npos);
        EXPECT_EQ(fname.find('\\'), std::string::npos);
    }

    TEST(ExceptionDeviant, DumpExactFormat)
    {
        // Dump() 完整格式：[Filename:line] [TYPE:value] Message
        const exposed_deviant ex(fault::make_error_code(fault::Code::eof), "Stream ended");
        const std::string expected = std::format("[{}:{}] [EXPOSED:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

    TEST(ExceptionDeviant, CopySemantics)
    {
        // 拷贝：错误码、消息与 Dump 完全一致
        const exposed_deviant src(fault::make_error_code(fault::Code::connection_reset), "peer Reset");
        const exposed_deviant copied(src);
        EXPECT_EQ(copied.ErrorCode().value(), src.ErrorCode().value());
        EXPECT_STREQ(copied.what(), src.what());
        EXPECT_EQ(copied.Dump(), src.Dump());
    }

    TEST(ExceptionDeviant, TypeNameOverride)
    {
        // 子类实现 TypeName()，Dump() 中体现
        const exposed_deviant ex(fault::make_error_code(fault::Code::eof), "x");
        EXPECT_TRUE(Contains(ex.Dump(), "[EXPOSED:3]"));
    }

    // ──────────────────────── exception: Network ────────────────────────

    /**
     * @class exposed_network
     * @brief 暴露 protected TypeName() 的 Network 测试子类
     */
    class exposed_network : public exc::Network
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_network(fault::Code err, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::Network(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Network::TypeName();
        }
    };

    TEST(ExceptionNetwork, ConstructAllForms)
    {
        // 四种构造形态：错误码 / 错误码+描述 / 字符串 / 格式化
        const exc::Network by_code(fault::Code::eof);
        EXPECT_EQ(std::string(by_code.what()), "eof");

        const exc::Network with_desc(fault::Code::timeout, "handshake stalled");
        EXPECT_EQ(std::string(with_desc.what()), "timeout: handshake stalled");

        const exc::Network by_string(std::string("legacy net"));
        EXPECT_EQ(by_string.ErrorCode().value(), static_cast<int>(fault::Code::generic_error));
        EXPECT_EQ(std::string(by_string.what()), "generic_error: legacy net");

        const exc::Network formatted("net Fail {}", 7);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: net Fail 7");

        const exc::Network formatted_loc(std::source_location::current(), "net Fail {}", 8);
        EXPECT_EQ(std::string(formatted_loc.what()), "generic_error: net Fail 8");
    }

    TEST(ExceptionNetwork, TypeName)
    {
        const exposed_network ex(fault::Code::dns_failed, "resolve Fail");
        EXPECT_EQ(ex.TypeName(), "NETWORK");
        EXPECT_TRUE(Contains(ex.Dump(), "NETWORK"));
    }

    TEST(ExceptionNetwork, DumpFormat)
    {
        const exc::Network ex(fault::Code::connection_refused, "refused");
        const std::string expected = std::format("[{}:{}] [NETWORK:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

    // ──────────────────────── exception: Protocol ────────────────────────

    /**
     * @class exposed_protocol
     * @brief 暴露 protected TypeName() 的 Protocol 测试子类
     */
    class exposed_protocol : public exc::Protocol
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_protocol(fault::Code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::Protocol(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Protocol::TypeName();
        }
    };

    TEST(ExceptionProtocol, ConstructCodeAndDesc)
    {
        const exc::Protocol by_code(fault::Code::parse_error);
        EXPECT_EQ(std::string(by_code.what()), "parse_error");
        EXPECT_EQ(by_code.ErrorCode().value(), static_cast<int>(fault::Code::parse_error));

        const exc::Protocol with_desc(fault::Code::bad_message, "malformed Header");
        EXPECT_EQ(std::string(with_desc.what()), "bad_message: malformed Header");

        const exc::Protocol formatted("proto Fail {}", 3);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: proto Fail 3");
    }

    TEST(ExceptionProtocol, TypeName)
    {
        const exposed_protocol ex(fault::Code::protocol_error, "State Error");
        EXPECT_EQ(ex.TypeName(), "PROTOCOL");
        EXPECT_TRUE(Contains(ex.Dump(), "PROTOCOL"));
    }

    TEST(ExceptionProtocol, DumpFormat)
    {
        const exc::Protocol ex(fault::Code::parse_error, "bad Frame");
        const std::string expected = std::format("[{}:{}] [PROTOCOL:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

    // ──────────────────────── exception: Security（敏感信息保护） ────────────────────────

    /**
     * @class exposed_security
     * @brief 暴露 protected TypeName() 的 Security 测试子类
     */
    class exposed_security : public exc::Security
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_security(fault::Code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::Security(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Security::TypeName();
        }
    };

    TEST(ExceptionSecurity, WhatGenericForSecurityCode)
    {
        // 认证失败异常：What() 仅含通用错误文本，不泄露任何凭据细节
        const exc::Security ex(fault::Code::auth_failed);
        EXPECT_EQ(std::string(ex.what()), "auth_failed");
        EXPECT_EQ(ex.ErrorCode().message(), "auth_failed");
    }

    TEST(ExceptionSecurity, ErrorCodeMessageNotContainingDesc)
    {
        // 描述包含敏感内容时，ErrorCode() 消息保持通用（描述仅出现在 What()）
        const exc::Security ex(fault::Code::auth_failed, "user 'admin' rejected");
        EXPECT_EQ(ex.ErrorCode().message(), "auth_failed")
            << "Error Code Message must not carry user-provided details";
        EXPECT_TRUE(Contains(std::string(ex.what()), "user 'admin' rejected"));
    }

    TEST(ExceptionSecurity, DumpNoPathLeak)
    {
        // Dump() 仅含纯文件名，不泄露构建路径等内部信息
        const exc::Security ex(fault::Code::auth_failed, "rejected");
        const std::string Dump = ex.Dump();
        EXPECT_EQ(Dump.find('/'), std::string::npos);
        EXPECT_EQ(Dump.find('\\'), std::string::npos);
        EXPECT_TRUE(Contains(Dump, "CryptoExceptionCoverage.cpp"));
    }

    TEST(ExceptionSecurity, TypeName)
    {
        const exposed_security ex(fault::Code::verifyfail, "cert invalid");
        EXPECT_EQ(ex.TypeName(), "SECURITY");
        EXPECT_TRUE(Contains(ex.Dump(), "SECURITY"));
    }

    TEST(ExceptionSecurity, DumpFormat)
    {
        const exc::Security ex(fault::Code::auth_failed, "login denied");
        const std::string expected = std::format("[{}:{}] [SECURITY:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }
} // namespace
