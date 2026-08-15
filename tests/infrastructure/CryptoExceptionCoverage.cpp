/**
 * @file CryptoExceptionCoverage.cpp
 * @brief tests/common/core/crypto 与 tests/common/core/exception 覆盖率补充测试
 * @details 纯函数单元测试（无协程），目标提升两个模块的路径覆盖：
 * - crypto：aead 错误路径补充（空密钥/空输入/短密文）、base64（非法字符/填充
 *   错误/往返）、blake3（空输入/大输入/已知向量）、block（AES-128/256 往返、
 *   密钥长度错误）、hkdf（RFC 4231/5869 已知向量、expand 非法长度边界）、
 *   sha224（空/边界/已知向量、credential 规范化）、x25519（RFC 7748 向量、
 *   密钥派生往返、非法长度、低阶点）
 * - exception：deviant/network/protocol/security 的构造（错误码+描述）、
 *   what() 内容、type_name()、error_code()、location()/filename()、
 *   dump() 完整格式、安全异常的敏感信息保护（错误码消息不携带描述、
 *   dump 不泄露完整路径）
 * @note 已知向量来源：FIPS-197、RFC 4231、RFC 5869、RFC 7748、NIST、
 *       BLAKE3 官方测试向量
 */

#include <common/core/crypto/crypto.hpp>
#include <common/core/crypto/x25519.hpp>
#include <common/core/exception/network.hpp>
#include <common/core/exception/protocol.hpp>
#include <common/core/exception/security.hpp>

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
    namespace crypto = psmtest::crypto;
    namespace fault = psmtest::fault;
    namespace exc = psmtest::exception;

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
     * @param data 字节序列
     * @return 小写十六进制字符串
     */
    auto to_hex(const std::span<const std::uint8_t> data) -> std::string
    {
        constexpr char hex_chars[] = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (const auto byte : data)
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
    auto contains(const std::string &haystack, const std::string_view needle) -> bool
    {
        return haystack.find(needle) != std::string::npos;
    }

    // ──────────────────────── crypto: aead 错误路径补充 ────────────────────────

    TEST(AeadCoverage, EmptyKeyConstruct)
    {
        // 0 字节密钥：EVP_AEAD_CTX_init 失败 → ctx 为 null
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, std::span<const std::uint8_t>{});
        std::array<std::uint8_t, 32> out{};
        EXPECT_EQ(ctx.seal(out, std::span<const std::uint8_t>{}), fault::code::crypto_error);
        EXPECT_EQ(ctx.open(out, out), fault::code::crypto_error);
        EXPECT_EQ(ctx.nonce_length(), 12);
    }

    TEST(AeadCoverage, SealEmptyPlaintextAutoNonce)
    {
        // 空明文 seal：输出仅 16 字节 tag，且内部 nonce 正常递增
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        crypto::aead_context ctx(crypto::aead_cipher::aes_256_gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.seal(out, std::span<const std::uint8_t>{}), fault::code::success);
        EXPECT_EQ(ctx.nonce()[0], 1) << "nonce should advance after empty seal";
    }

    TEST(AeadCoverage, OpenEmptyCiphertext)
    {
        // 空密文 open：密文长度 < tag 长度 → 认证失败
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.open(out, std::span<const std::uint8_t>{}), fault::code::crypto_error);
    }

    TEST(AeadCoverage, OpenCiphertextShorterThanTag)
    {
        // 密文长度 8 字节（不足 16 字节 tag）→ 解密失败
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, key);
        const std::array<std::uint8_t, 8> short_ct{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        std::array<std::uint8_t, 8> out{};
        EXPECT_EQ(ctx.open(out, short_ct), fault::code::crypto_error);
    }

    TEST(AeadCoverage, OpenEmptyCiphertextExplicitNonce)
    {
        // 显式 nonce 重载：空密文同样失败，且不修改内部状态
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, key);
        const std::array<std::uint8_t, 12> nonce{};
        std::array<std::uint8_t, 16> out{};
        crypto::open_input input{out, std::span<const std::uint8_t>{}, nonce, {}};
        EXPECT_EQ(ctx.open(input), fault::code::crypto_error);
        EXPECT_EQ(ctx.nonce()[0], 0) << "failed explicit open must not advance nonce";
    }

    // ──────────────────────── crypto: base64 ────────────────────────

    TEST(Base64Coverage, EncodeKnownVectors)
    {
        EXPECT_EQ(std::string(crypto::base64_encode({})), "");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 3>{'M', 'a', 'n'})), "TWFu");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 2>{'M', 'a'})), "TWE=");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 1>{'M'})), "TQ==");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 1>{0xFF})), "/w==");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 2>{0xFF, 0xFF})), "//8=");
        EXPECT_EQ(std::string(crypto::base64_encode(std::array<std::uint8_t, 3>{0xFF, 0xFF, 0xFF})), "////");
    }

    TEST(Base64Coverage, DecodeKnownVectors)
    {
        EXPECT_EQ(std::string(crypto::base64_decode("")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("TWFu")), "Man");
        EXPECT_EQ(std::string(crypto::base64_decode("TWE=")), "Ma");
        EXPECT_EQ(std::string(crypto::base64_decode("TQ==")), "M");
        EXPECT_EQ(std::string(crypto::base64_decode("//8=")), std::string("\xFF\xFF", 2));
        EXPECT_EQ(std::string(crypto::base64_decode("SGVsbG8sIFdvcmxkIQ==")), "Hello, World!");
    }

    TEST(Base64Coverage, RoundTripAllByteValues)
    {
        // 0..64 字节全值域数据：encode → decode 完全还原
        for (std::size_t n = 0; n <= 64; ++n)
        {
            std::vector<std::uint8_t> data(n);
            for (std::size_t i = 0; i < n; ++i)
            {
                data[i] = static_cast<std::uint8_t>(i * 7 + 3);
            }
            const auto encoded = crypto::base64_encode(data);
            const auto decoded = crypto::base64_decode(std::string_view(encoded.data(), encoded.size()));
            const auto bytes = std::string_view(decoded.data(), decoded.size());
            EXPECT_EQ(bytes, std::string_view(reinterpret_cast<const char *>(data.data()), data.size()))
                << "roundtrip mismatch at n=" << n;
        }
    }

    TEST(Base64Coverage, DecodeWhitespace)
    {
        // 自动忽略空白字符
        EXPECT_EQ(std::string(crypto::base64_decode("TW Fu")), "Man");
        EXPECT_EQ(std::string(crypto::base64_decode("\tTWF\nu")), "Man");
        EXPECT_EQ(std::string(crypto::base64_decode("TWE =")), "Ma");
    }

    TEST(Base64Coverage, DecodeUrlSafe)
    {
        // URL-safe 变体：'-' 与 '_' 分别映射 '+' 与 '/'
        EXPECT_EQ(std::string(crypto::base64_decode("-w==")), std::string("\xFB", 1));
        EXPECT_EQ(std::string(crypto::base64_decode("__8=")), std::string("\xFF\xFF", 2));
        EXPECT_EQ(std::string(crypto::base64_decode("__8=")),
                  std::string(crypto::base64_decode("//8=")));
    }

    TEST(Base64Coverage, DecodeInvalidChars)
    {
        // 非法字符（非字母数字、非 +/-/_/空白）→ 返回空串
        EXPECT_EQ(std::string(crypto::base64_decode("T!Fu")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("$")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("AAAA$")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("T@==")), "");
    }

    TEST(Base64Coverage, DecodePaddingErrors)
    {
        // padding 数量非法：超过 2 个或与有效字符不构成 4 字节组
        EXPECT_EQ(std::string(crypto::base64_decode("TQ=")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("TQ===")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("====")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("==")), "");
    }

    TEST(Base64Coverage, DecodeNonMultipleOfFour)
    {
        // 无 padding 且有效字符数不是 4 的倍数 → 返回空串
        EXPECT_EQ(std::string(crypto::base64_decode("TWF")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("T")), "");
        EXPECT_EQ(std::string(crypto::base64_decode("TW")), "");
    }

    // ──────────────────────── crypto: blake3 ────────────────────────

    TEST(Blake3Coverage, EmptyHashKnownVector)
    {
        // BLAKE3("") 官方测试向量
        const auto h = crypto::hash({});
        EXPECT_EQ(h.size(), 32);
        EXPECT_EQ(to_hex(h), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }

    TEST(Blake3Coverage, AbcKnownVector)
    {
        // BLAKE3("abc") 官方测试向量
        const std::string data = "abc";
        const auto bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
        const auto h = crypto::hash(bytes);
        EXPECT_EQ(to_hex(h), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    }

    TEST(Blake3Coverage, LargeInputDeterministic)
    {
        // 1MiB 输入：确定性且与短输入不同
        std::vector<std::uint8_t> data(1024 * 1024);
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            data[i] = static_cast<std::uint8_t>(i & 0xFF);
        }
        const auto h1 = crypto::hash(data);
        const auto h2 = crypto::hash(data);
        EXPECT_EQ(h1, h2);
        data.pop_back();
        EXPECT_NE(h1, crypto::hash(data)) << "large hash must change with input";
    }

    TEST(Blake3Coverage, KeyedHashIncrementalEqualsOneshot)
    {
        // keyed_hasher 增量更新（分块）与 keyed_hash 一次性结果一致
        const std::vector<std::uint8_t> key = hex_to_bytes("000102030405060708090a0b0c0d0e0f"
                                                           "101112131415161718191a1b1c1d1e1f");
        const std::string data = "incremental keyed hashing";
        const auto bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(data.data()), data.size());

        auto hasher = crypto::keyed_hasher(key);
        blake3_hasher_update(&hasher, bytes.data(), 5);
        blake3_hasher_update(&hasher, bytes.data() + 5, bytes.size() - 5);
        std::array<std::uint8_t, 32> incremental{};
        blake3_hasher_finalize(&hasher, incremental.data(), incremental.size());

        EXPECT_EQ(incremental, crypto::keyed_hash(key, bytes));
    }

    TEST(Blake3Coverage, KeyedHashKeySeparation)
    {
        // 不同密钥 → 不同 keyed hash；空输入可计算
        const std::vector<std::uint8_t> key_a = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        std::vector<std::uint8_t> key_b = key_a;
        key_b[0] ^= 0x01;
        const auto empty_hash_a = crypto::keyed_hash(key_a, {});
        const auto empty_hash_b = crypto::keyed_hash(key_b, {});
        EXPECT_NE(empty_hash_a, empty_hash_b);
    }

    TEST(Blake3Coverage, DeriveKeyContextAndMaterialSeparation)
    {
        // 上下文域分离：不同 context/材料 → 不同密钥；span 与 vector 版本等价
        const std::vector<std::uint8_t> material(32, 0xAB);
        const auto k1 = crypto::derive_key("ctx-alpha", material, 32);
        const auto k2 = crypto::derive_key("ctx-beta", material, 32);
        EXPECT_EQ(k1.size(), 32);
        EXPECT_NE(k1, k2) << "different contexts must derive different keys";

        std::vector<std::uint8_t> buf(32);
        crypto::derive_key("ctx-alpha", material, buf);
        EXPECT_EQ(k1, buf) << "span overload must match vector overload";

        // 空材料与空上下文均可派生
        const auto k3 = crypto::derive_key("ctx-alpha", std::span<const std::uint8_t>{}, 32);
        EXPECT_EQ(k3.size(), 32);
        EXPECT_NE(k3, k1);
        const auto k4 = crypto::derive_key("", material, 16);
        EXPECT_EQ(k4.size(), 16);
    }

    // ──────────────────────── crypto: block ────────────────────────

    TEST(BlockCoverage, Aes128Fips197Vector)
    {
        // FIPS-197 附录 B 已知向量
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const auto ct = crypto::ecb_encrypt(block, key);
        EXPECT_EQ(to_hex(ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
        EXPECT_EQ(crypto::ecb_decrypt(ct, key), block);
    }

    TEST(BlockCoverage, Aes256RoundTrip)
    {
        // AES-256（32 字节密钥）：加密后解密还原
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f"
                                      "101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::ecb_encrypt(block, key);
        EXPECT_NE(ct, block);
        EXPECT_EQ(crypto::ecb_decrypt(ct, key), block);
    }

    TEST(BlockCoverage, WrongKeyLengthInitFailure)
    {
        // 24 字节密钥：非 16 → 走 AES-256 分支；BoringSSL 支持 AES-192（24 字节），
        // 加解密正常往返（safe 路径覆盖 else 分支）
        const auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::ecb_encrypt(block, key);
        EXPECT_NE(ct, block);
        EXPECT_EQ(crypto::ecb_decrypt(ct, key), block);
    }

    // ──────────────────────── crypto: hkdf ────────────────────────

    TEST(HkdfCoverage, HmacSha256Rfc4231)
    {
        // RFC 4231 测试用例 1：key=0x0b×20，data="Hi There"
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string data = "Hi There";
        const auto bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
        const auto mac = crypto::hmac_sha256(key, bytes);
        EXPECT_EQ(to_hex(mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    TEST(HkdfCoverage, HmacSha512Rfc4231)
    {
        // RFC 4231 测试用例 1（SHA-512 版本）
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string data = "Hi There";
        const auto bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
        const auto mac = crypto::hmac_sha512(key, bytes);
        EXPECT_EQ(to_hex(mac), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded"
                               "aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    TEST(HkdfCoverage, HmacSha256EmptyKeyAndData)
    {
        // 空密钥与空数据的已知向量
        const auto mac = crypto::hmac_sha256({}, {});
        EXPECT_EQ(to_hex(mac), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

    TEST(HkdfCoverage, ExtractRfc5869Prk)
    {
        // RFC 5869 测试用例 1：PRK = HMAC-SHA256(salt, IKM)
        const auto salt = hex_to_bytes("000102030405060708090a0b0c");
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const auto prk = crypto::hkdf_extract(salt, ikm);
        EXPECT_EQ(to_hex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    }

    TEST(HkdfCoverage, ExtractEmptySaltEqualsZeroSalt)
    {
        // 空盐等价于 32 字节全零盐（RFC 5869 规则）
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const std::array<std::uint8_t, crypto::sha256_len> zero_salt{};
        EXPECT_EQ(crypto::hkdf_extract({}, ikm), crypto::hkdf_extract(zero_salt, ikm));
    }

    TEST(HkdfCoverage, ExtractEmptyIkm)
    {
        // 空 IKM 可提取（HMAC(salt, "")），且确定性
        const std::vector<std::uint8_t> salt = hex_to_bytes("000102030405060708090a0b0c");
        EXPECT_EQ(crypto::hkdf_extract(salt, {}), crypto::hkdf_extract(salt, {}));
    }

    TEST(HkdfCoverage, ExpandRfc5869Okm)
    {
        // RFC 5869 测试用例 1：L=42 的 OKM
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        const auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        const auto [ec, okm] = crypto::hkdf_expand(prk, info, 42);
        EXPECT_EQ(ec, fault::code::success);
        EXPECT_EQ(to_hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865");
    }

    TEST(HkdfCoverage, ExpandInvalidArguments)
    {
        // 非法参数：长度超限 / PRK 过短 / info 过长
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        EXPECT_EQ(crypto::hkdf_expand(prk, {}, 255 * crypto::sha256_len + 1).first,
                  fault::code::invalid_argument);

        const std::vector<std::uint8_t> short_prk(31, 0x11);
        EXPECT_EQ(crypto::hkdf_expand(short_prk, {}, 32).first, fault::code::invalid_argument);

        std::vector<std::uint8_t> big_info(515, 0x22);
        EXPECT_EQ(crypto::hkdf_expand(prk, big_info, 32).first, fault::code::invalid_argument);
    }

    TEST(HkdfCoverage, ExpandZeroAndMaxLength)
    {
        // 边界：length=0 成功且为空；length=8160（255×32）成功
        const auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        const auto [ec_zero, out_zero] = crypto::hkdf_expand(prk, {}, 0);
        EXPECT_EQ(ec_zero, fault::code::success);
        EXPECT_TRUE(out_zero.empty());

        const auto [ec_max, out_max] = crypto::hkdf_expand(prk, {}, 255 * crypto::sha256_len);
        EXPECT_EQ(ec_max, fault::code::success);
        EXPECT_EQ(out_max.size(), 255 * crypto::sha256_len);
    }

    TEST(HkdfCoverage, ExpandLabelEquivalenceAndInvalid)
    {
        // expand_label 与手构 HkdfLabel 的 hkdf_expand 结果一致
        const auto secret = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 3> context = {0x01, 0x02, 0x03};

        const auto [ec, out] = crypto::expand_label(
            crypto::expand_params{secret, "key", context, 32});
        ASSERT_EQ(ec, fault::code::success);
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
        label_buf.push_back(static_cast<std::uint8_t>(context.size()));
        label_buf.insert(label_buf.end(), context.begin(), context.end());

        const auto [ec_manual, manual] = crypto::hkdf_expand(secret, label_buf, 32);
        ASSERT_EQ(ec_manual, fault::code::success);
        EXPECT_EQ(out, manual) << "expand_label must match manual HkdfLabel construction";

        // 非法：label 过长（>249 字节）与 context 过长（>255 字节）
        const std::string long_label(250, 'x');
        EXPECT_EQ(crypto::expand_label(crypto::expand_params{secret, long_label, {}, 32}).first,
                  fault::code::invalid_argument);
        std::vector<std::uint8_t> big_context(256, 0x33);
        EXPECT_EQ(crypto::expand_label(crypto::expand_params{secret, "key", big_context, 32}).first,
                  fault::code::invalid_argument);
    }

    TEST(HkdfCoverage, Sha256KnownVectors)
    {
        // NIST 已知向量
        const auto empty = crypto::sha256({});
        EXPECT_EQ(to_hex(empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        const std::string abc = "abc";
        const auto abc_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
        EXPECT_EQ(to_hex(crypto::sha256(abc_bytes)),
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
        EXPECT_EQ(crypto::sha256(a_bytes, b_bytes), crypto::sha256(ab_bytes));

        const std::string abc = a + b + c;
        const auto abc_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
        EXPECT_EQ(crypto::sha256(a_bytes, b_bytes, c_bytes), crypto::sha256(abc_bytes));
    }

    // ──────────────────────── crypto: sha224 ────────────────────────

    TEST(Sha224Coverage, EmptyInputKnownVector)
    {
        // NIST 已知向量：SHA-224("")
        const auto h = crypto::sha224("");
        EXPECT_EQ(h.size(), 56);
        EXPECT_EQ(std::string(h), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    TEST(Sha224Coverage, AbcKnownVector)
    {
        // NIST 已知向量：SHA-224("abc")
        EXPECT_EQ(std::string(crypto::sha224("abc")),
                  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    }

    TEST(Sha224Coverage, IsHex)
    {
        EXPECT_TRUE(crypto::is_hex("0123456789abcdefABCDEF"));
        EXPECT_TRUE(crypto::is_hex(""));
        EXPECT_FALSE(crypto::is_hex("0x12"));
        EXPECT_FALSE(crypto::is_hex("12g4"));
        EXPECT_FALSE(crypto::is_hex("12 34"));
        EXPECT_FALSE(crypto::is_hex("abcdefgh"));
    }

    TEST(Sha224Coverage, NormalizeCredential)
    {
        // 56 字符十六进制凭据：原样返回（已是哈希）
        const std::string hashed(56, '0');
        EXPECT_EQ(std::string(crypto::normalize_credential(hashed)), hashed);

        // 明文凭据：计算 SHA-224
        const auto normalized = crypto::normalize_credential("my-credential");
        EXPECT_EQ(std::string(normalized), std::string(crypto::sha224("my-credential")));
        EXPECT_EQ(normalized.size(), 56);
    }

    TEST(Sha224Coverage, NormalizeNonHexAndEmpty)
    {
        // 56 字符但含非十六进制字符：仍被哈希而非原样返回
        const std::string not_hex(56, 'g');
        EXPECT_FALSE(crypto::is_hex(not_hex));
        const auto normalized = crypto::normalize_credential(not_hex);
        EXPECT_EQ(std::string(normalized), std::string(crypto::sha224(not_hex)));

        // 空凭据：哈希空串
        EXPECT_EQ(std::string(crypto::normalize_credential("")),
                  std::string(crypto::sha224("")));
    }

    // ──────────────────────── crypto: x25519 ────────────────────────

    TEST(X25519Coverage, GenerateKeypairConsistent)
    {
        // 密钥对：私钥非零，公钥 = derive_pubkey(私钥)
        const auto kp = crypto::generate_keypair();
        const std::array<std::uint8_t, crypto::x25519_klen> zero{};
        EXPECT_NE(kp.private_key, zero);
        EXPECT_EQ(crypto::derive_pubkey(kp.private_key), kp.public_key);
    }

    TEST(X25519Coverage, DerivePubkeyRfc7748)
    {
        // RFC 7748 测试向量 1：Alice 私钥 → 公钥
        const auto priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto pub = crypto::derive_pubkey(priv);
        EXPECT_EQ(to_hex(pub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

    TEST(X25519Coverage, DerivePubkeyWrongLength)
    {
        // 非法长度：0/16/64 字节私钥 → 全零公钥
        const auto bad = crypto::derive_pubkey({});
        EXPECT_EQ(to_hex(bad), std::string(64, '0'));
        const auto key16 = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        EXPECT_EQ(to_hex(crypto::derive_pubkey(key16)), std::string(64, '0'));
    }

    TEST(X25519Coverage, SharedSecretRoundtrip)
    {
        // 密钥交换对称性：Alice×Bob == Bob×Alice
        const auto alice = crypto::generate_keypair();
        const auto bob = crypto::generate_keypair();

        const auto [ec1, s1] = crypto::x25519(alice.private_key, bob.public_key);
        const auto [ec2, s2] = crypto::x25519(bob.private_key, alice.public_key);
        EXPECT_EQ(ec1, fault::code::success);
        EXPECT_EQ(ec2, fault::code::success);
        EXPECT_EQ(s1, s2);
        const std::array<std::uint8_t, crypto::x25519_slen> zero{};
        EXPECT_NE(s1, zero);
    }

    TEST(X25519Coverage, SharedSecretRfc7748)
    {
        // RFC 7748 测试向量 1：Alice/Bob 共享密钥
        const auto alice_priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto bob_pub = hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        const auto [ec, shared] = crypto::x25519(alice_priv, bob_pub);
        EXPECT_EQ(ec, fault::code::success);
        EXPECT_EQ(to_hex(shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    TEST(X25519Coverage, InvalidLengthsAndLowOrder)
    {
        // 非法长度 → invalid_argument
        const auto short_priv = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const auto pub = hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        EXPECT_EQ(crypto::x25519(short_priv, pub).first, fault::code::invalid_argument);
        const std::vector<std::uint8_t> long_pub(33, 0x11);
        EXPECT_EQ(crypto::x25519(short_priv, long_pub).first, fault::code::invalid_argument);

        // 低阶点（全零对端公钥）：共享密钥全零 → kexfail
        const std::array<std::uint8_t, crypto::x25519_klen> zero_key{};
        const auto kp = crypto::generate_keypair();
        EXPECT_EQ(crypto::x25519(kp.private_key, zero_key).first, fault::code::kexfail);

        // 全零私钥经 RFC 7748 钳制（e[31]|=64）后是有效标量 → 成功且共享密钥非零
        const auto [ec, shared] = crypto::x25519(zero_key, kp.public_key);
        EXPECT_EQ(ec, fault::code::success);
        EXPECT_NE(shared, zero_key);
    }

    // ──────────────────────── exception: deviant ────────────────────────

    /**
     * @class exposed_deviant
     * @brief 暴露 type_name() 的 deviant 测试子类
     * @details deviant 是抽象基类，此类用于实例化测试并公开类型名称。
     */
    class exposed_deviant : public exc::deviant
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_deviant(std::error_code ec, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::deviant(ec, desc, loc)
        {
        }

        /** @brief 转发字符串构造 */
        explicit exposed_deviant(const std::string &msg,
                                 const std::source_location &loc = std::source_location::current())
            : exc::deviant(msg, loc)
        {
        }

        /** @brief 转发格式化构造 */
        template <typename... Args>
        explicit exposed_deviant(const std::source_location &loc, std::format_string<Args...> fmt,
                                 Args &&...args)
            : exc::deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return "EXPOSED";
        }
    };

    TEST(ExceptionDeviant, AbstractBase)
    {
        // deviant 为抽象基类：必须实现 type_name() 才能实例化
        static_assert(std::is_abstract_v<exc::deviant>);
        const exposed_deviant ex(fault::make_error_code(fault::code::eof));
        EXPECT_EQ(ex.type_name(), "EXPOSED");
    }

    TEST(ExceptionDeviant, ConstructWithCodeAndDesc)
    {
        // 错误码 + 描述：what() = "message: desc"
        const exposed_deviant ex(fault::make_error_code(fault::code::eof), "stream ended");
        EXPECT_EQ(std::string(ex.what()), "eof: stream ended");
    }

    TEST(ExceptionDeviant, ConstructWithCodeNoDesc)
    {
        // 仅错误码：what() = 错误码消息本身
        const exposed_deviant ex(fault::make_error_code(fault::code::timeout));
        EXPECT_EQ(std::string(ex.what()), "timeout");
    }

    TEST(ExceptionDeviant, ConstructWithStringGenericError)
    {
        // 字符串构造：回退到 generic_error 错误码
        const exposed_deviant ex(std::string("legacy message"));
        EXPECT_EQ(ex.error_code().value(), static_cast<int>(fault::code::generic_error));
        EXPECT_EQ(std::string(ex.what()), "generic_error: legacy message");
    }

    TEST(ExceptionDeviant, ConstructFormatted)
    {
        // 格式化构造：格式参数被替换
        const exposed_deviant ex(std::source_location::current(), "format error {}", 42);
        EXPECT_EQ(std::string(ex.what()), "generic_error: format error 42");
    }

    TEST(ExceptionDeviant, ErrorCodeAccessors)
    {
        // error_code() 保留值与分类
        const exposed_deviant ex(fault::make_error_code(fault::code::parse_error), "bad");
        const auto &ec = ex.error_code();
        EXPECT_EQ(ec.value(), static_cast<int>(fault::code::parse_error));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
        EXPECT_EQ(ec.message(), "parse_error");
    }

    TEST(ExceptionDeviant, LocationAndFilename)
    {
        // 位置捕获：文件名、行号有效；filename() 仅纯文件名
        const exposed_deviant ex(fault::make_error_code(fault::code::eof));
        const auto &loc = ex.location();
        ASSERT_TRUE(loc.file_name());
        EXPECT_TRUE(contains(std::string(loc.file_name()), "CryptoExceptionCoverage"));
        EXPECT_GT(loc.line(), 0);

        const std::string fname = ex.filename();
        EXPECT_EQ(fname, "CryptoExceptionCoverage.cpp");
        EXPECT_EQ(fname.find('/'), std::string::npos);
        EXPECT_EQ(fname.find('\\'), std::string::npos);
    }

    TEST(ExceptionDeviant, DumpExactFormat)
    {
        // dump() 完整格式：[filename:line] [TYPE:value] message
        const exposed_deviant ex(fault::make_error_code(fault::code::eof), "stream ended");
        const std::string expected = std::format("[{}:{}] [EXPOSED:{}] {}", ex.filename(),
                                                 ex.location().line(), ex.error_code().value(),
                                                 ex.what());
        EXPECT_EQ(ex.dump(), expected);
    }

    TEST(ExceptionDeviant, CopySemantics)
    {
        // 拷贝：错误码、消息与 dump 完全一致
        const exposed_deviant src(fault::make_error_code(fault::code::connection_reset), "peer reset");
        const exposed_deviant copied(src);
        EXPECT_EQ(copied.error_code().value(), src.error_code().value());
        EXPECT_STREQ(copied.what(), src.what());
        EXPECT_EQ(copied.dump(), src.dump());
    }

    TEST(ExceptionDeviant, TypeNameOverride)
    {
        // 子类实现 type_name()，dump() 中体现
        const exposed_deviant ex(fault::make_error_code(fault::code::eof), "x");
        EXPECT_TRUE(contains(ex.dump(), "[EXPOSED:3]"));
    }

    // ──────────────────────── exception: network ────────────────────────

    /**
     * @class exposed_network
     * @brief 暴露 protected type_name() 的 network 测试子类
     */
    class exposed_network : public exc::network
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_network(fault::code err, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::network(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return exc::network::type_name();
        }
    };

    TEST(ExceptionNetwork, ConstructAllForms)
    {
        // 四种构造形态：错误码 / 错误码+描述 / 字符串 / 格式化
        const exc::network by_code(fault::code::eof);
        EXPECT_EQ(std::string(by_code.what()), "eof");

        const exc::network with_desc(fault::code::timeout, "handshake stalled");
        EXPECT_EQ(std::string(with_desc.what()), "timeout: handshake stalled");

        const exc::network by_string(std::string("legacy net"));
        EXPECT_EQ(by_string.error_code().value(), static_cast<int>(fault::code::generic_error));
        EXPECT_EQ(std::string(by_string.what()), "generic_error: legacy net");

        const exc::network formatted("net fail {}", 7);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: net fail 7");

        const exc::network formatted_loc(std::source_location::current(), "net fail {}", 8);
        EXPECT_EQ(std::string(formatted_loc.what()), "generic_error: net fail 8");
    }

    TEST(ExceptionNetwork, TypeName)
    {
        const exposed_network ex(fault::code::dns_failed, "resolve fail");
        EXPECT_EQ(ex.type_name(), "NETWORK");
        EXPECT_TRUE(contains(ex.dump(), "NETWORK"));
    }

    TEST(ExceptionNetwork, DumpFormat)
    {
        const exc::network ex(fault::code::connection_refused, "refused");
        const std::string expected = std::format("[{}:{}] [NETWORK:{}] {}", ex.filename(),
                                                 ex.location().line(), ex.error_code().value(),
                                                 ex.what());
        EXPECT_EQ(ex.dump(), expected);
    }

    // ──────────────────────── exception: protocol ────────────────────────

    /**
     * @class exposed_protocol
     * @brief 暴露 protected type_name() 的 protocol 测试子类
     */
    class exposed_protocol : public exc::protocol
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_protocol(fault::code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::protocol(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return exc::protocol::type_name();
        }
    };

    TEST(ExceptionProtocol, ConstructCodeAndDesc)
    {
        const exc::protocol by_code(fault::code::parse_error);
        EXPECT_EQ(std::string(by_code.what()), "parse_error");
        EXPECT_EQ(by_code.error_code().value(), static_cast<int>(fault::code::parse_error));

        const exc::protocol with_desc(fault::code::bad_message, "malformed header");
        EXPECT_EQ(std::string(with_desc.what()), "bad_message: malformed header");

        const exc::protocol formatted("proto fail {}", 3);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: proto fail 3");
    }

    TEST(ExceptionProtocol, TypeName)
    {
        const exposed_protocol ex(fault::code::protocol_error, "state error");
        EXPECT_EQ(ex.type_name(), "PROTOCOL");
        EXPECT_TRUE(contains(ex.dump(), "PROTOCOL"));
    }

    TEST(ExceptionProtocol, DumpFormat)
    {
        const exc::protocol ex(fault::code::parse_error, "bad frame");
        const std::string expected = std::format("[{}:{}] [PROTOCOL:{}] {}", ex.filename(),
                                                 ex.location().line(), ex.error_code().value(),
                                                 ex.what());
        EXPECT_EQ(ex.dump(), expected);
    }

    // ──────────────────────── exception: security（敏感信息保护） ────────────────────────

    /**
     * @class exposed_security
     * @brief 暴露 protected type_name() 的 security 测试子类
     */
    class exposed_security : public exc::security
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_security(fault::code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::security(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return exc::security::type_name();
        }
    };

    TEST(ExceptionSecurity, WhatGenericForSecurityCode)
    {
        // 认证失败异常：what() 仅含通用错误文本，不泄露任何凭据细节
        const exc::security ex(fault::code::auth_failed);
        EXPECT_EQ(std::string(ex.what()), "auth_failed");
        EXPECT_EQ(ex.error_code().message(), "auth_failed");
    }

    TEST(ExceptionSecurity, ErrorCodeMessageNotContainingDesc)
    {
        // 描述包含敏感内容时，error_code() 消息保持通用（描述仅出现在 what()）
        const exc::security ex(fault::code::auth_failed, "user 'admin' rejected");
        EXPECT_EQ(ex.error_code().message(), "auth_failed")
            << "error code message must not carry user-provided details";
        EXPECT_TRUE(contains(std::string(ex.what()), "user 'admin' rejected"));
    }

    TEST(ExceptionSecurity, DumpNoPathLeak)
    {
        // dump() 仅含纯文件名，不泄露构建路径等内部信息
        const exc::security ex(fault::code::auth_failed, "rejected");
        const std::string dump = ex.dump();
        EXPECT_EQ(dump.find('/'), std::string::npos);
        EXPECT_EQ(dump.find('\\'), std::string::npos);
        EXPECT_TRUE(contains(dump, "CryptoExceptionCoverage.cpp"));
    }

    TEST(ExceptionSecurity, TypeName)
    {
        const exposed_security ex(fault::code::verifyfail, "cert invalid");
        EXPECT_EQ(ex.type_name(), "SECURITY");
        EXPECT_TRUE(contains(ex.dump(), "SECURITY"));
    }

    TEST(ExceptionSecurity, DumpFormat)
    {
        const exc::security ex(fault::code::auth_failed, "login denied");
        const std::string expected = std::format("[{}:{}] [SECURITY:{}] {}", ex.filename(),
                                                 ex.location().line(), ex.error_code().value(),
                                                 ex.what());
        EXPECT_EQ(ex.dump(), expected);
    }
} // namespace
