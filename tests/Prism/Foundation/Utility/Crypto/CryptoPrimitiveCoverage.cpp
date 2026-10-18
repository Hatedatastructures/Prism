/**
 * @file CryptoPrimitiveCoverage.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "CryptoExceptionTestSupport.hpp"

TEST(AeadCoverage, EmptyKeyConstruct)
    {
        // 0 字节密钥：EVP_AEAD_CTX_init 失败 → ctx 为 null
        crypto::AeadContext ctx(crypto::AeadCipher::Aes128Gcm, std::span<const std::uint8_t>{});
        std::array<std::uint8_t, 32> out{};
        EXPECT_EQ(ctx.Seal(out, std::span<const std::uint8_t>{}), fault::Code::CryptoError);
        EXPECT_EQ(ctx.Open(out, out), fault::Code::CryptoError);
        EXPECT_EQ(ctx.NonceLength(), 12);
    }

TEST(AeadCoverage, SealEmptyPlaintextAutoNonce)
    {
        // 空明文 Seal：输出仅 16 字节 tag，且内部 Nonce 正常递增
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        crypto::AeadContext ctx(crypto::AeadCipher::Aes256Gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.Seal(out, std::span<const std::uint8_t>{}), fault::Code::Success);
        EXPECT_EQ(ctx.Nonce()[0], 1) << "Nonce should advance after Empty Seal";
    }

TEST(AeadCoverage, OpenEmptyCiphertext)
    {
        // 空密文 Open：密文长度 < tag 长度 → 认证失败
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::Aes128Gcm, key);
        std::array<std::uint8_t, 16> out{};
        EXPECT_EQ(ctx.Open(out, std::span<const std::uint8_t>{}), fault::Code::CryptoError);
    }

TEST(AeadCoverage, OpenCiphertextShorterThanTag)
    {
        // 密文长度 8 字节（不足 16 字节 tag）→ 解密失败
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::Aes128Gcm, key);
        const std::array<std::uint8_t, 8> short_ct{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        std::array<std::uint8_t, 8> out{};
        EXPECT_EQ(ctx.Open(out, short_ct), fault::Code::CryptoError);
    }

TEST(AeadCoverage, OpenEmptyCiphertextExplicitNonce)
    {
        // 显式 Nonce 重载：空密文同样失败，且不修改内部状态
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        crypto::AeadContext ctx(crypto::AeadCipher::Aes128Gcm, key);
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 16> out{};
        crypto::OpenInput input{out, std::span<const std::uint8_t>{}, Nonce, {}};
        EXPECT_EQ(ctx.Open(input), fault::Code::CryptoError);
        EXPECT_EQ(ctx.Nonce()[0], 0) << "Failed explicit Open must not advance Nonce";
    }

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

TEST(Base64Coverage, AsioIncludeOrderCompatibility)
    {
        const std::array<std::uint8_t, 1> Data{0xFF};
        EXPECT_EQ(std::string(crypto::Base64Encode(Data)), "/w==");
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

TEST(Base64Coverage, DecodeRejectsNonCanonicalPadding)
    {
        EXPECT_EQ(std::string(crypto::Base64Decode("T=WE")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TWE=AAAA")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TR==")), "");
    }

TEST(Base64Coverage, DecodeNonMultipleOfFour)
    {
        // 无 padding 且有效字符数不是 4 的倍数 → 返回空串
        EXPECT_EQ(std::string(crypto::Base64Decode("TWF")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("T")), "");
        EXPECT_EQ(std::string(crypto::Base64Decode("TW")), "");
    }

TEST(RandomCoverage, ReportsSourceFailure)
    {
        std::array<std::uint8_t, 4> Bytes{};
        const auto Failed = crypto::FillRandom(
            std::span<std::uint8_t>(Bytes), [](std::uint8_t *, int) { return 0; });
        EXPECT_FALSE(Failed);

        const auto Succeeded = crypto::FillRandom(
            std::span<std::uint8_t>(Bytes), [](std::uint8_t *Data, int Size)
            {
                std::fill(Data, Data + Size, 0x5A);
                return 1;
            });
        EXPECT_TRUE(Succeeded);
        EXPECT_EQ(Bytes, (std::array<std::uint8_t, 4>{0x5A, 0x5A, 0x5A, 0x5A}));
    }

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
        const std::vector<std::uint8_t> key = HexToBytes("000102030405060708090a0b0c0d0e0f"
                                                           "101112131415161718191a1b1c1d1e1f");
        const std::string Data = "incremental keyed hashing";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());

        auto hasher = crypto::KeyedHasher(key);
        ASSERT_TRUE(hasher);
        blake3_hasher_update(&*hasher, Bytes.data(), 5);
        blake3_hasher_update(&*hasher, Bytes.data() + 5, Bytes.size() - 5);
        std::array<std::uint8_t, 32> incremental{};
        blake3_hasher_finalize(&*hasher, incremental.data(), incremental.size());

        const auto Oneshot = crypto::KeyedHash(key, Bytes);
        ASSERT_TRUE(Oneshot);
        EXPECT_EQ(incremental, *Oneshot);
    }

TEST(Blake3Coverage, KeyedHashKeySeparation)
    {
        // 不同密钥 → 不同 keyed Hash；空输入可计算
        const std::vector<std::uint8_t> key_a = HexToBytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        std::vector<std::uint8_t> key_b = key_a;
        key_b[0] ^= 0x01;
        const auto empty_hash_a = crypto::KeyedHash(key_a, {});
        const auto empty_hash_b = crypto::KeyedHash(key_b, {});
        ASSERT_TRUE(empty_hash_a);
        ASSERT_TRUE(empty_hash_b);
        EXPECT_NE(*empty_hash_a, *empty_hash_b);
    }

TEST(Blake3Coverage, RejectsInvalidKeyLengths)
    {
        const std::vector<std::uint8_t> EmptyKey;
        const std::vector<std::uint8_t> ShortKey(31, 0x11);
        const std::vector<std::uint8_t> LongKey(33, 0x22);
        const auto EmptyResult = crypto::KeyedHasher(EmptyKey);
        const auto ShortResult = crypto::KeyedHasher(ShortKey);
        const auto LongResult = crypto::KeyedHash(LongKey, {});
        ASSERT_FALSE(EmptyResult);
        ASSERT_FALSE(ShortResult);
        ASSERT_FALSE(LongResult);
        EXPECT_EQ(EmptyResult.error().Code, fault::Code::InvalidArgument);
        EXPECT_EQ(ShortResult.error().Code, fault::Code::InvalidArgument);
        EXPECT_EQ(LongResult.error().Code, fault::Code::InvalidArgument);
    }

TEST(Blake3Coverage, DeriveKeyContextAndMaterialSeparation)
    {
        // 上下文域分离：不同 Context/材料产生不同密钥，调用者提供输出缓冲区。
        const std::vector<std::uint8_t> material(32, 0xAB);
        std::vector<std::uint8_t> k1(32);
        crypto::DeriveKey("ctx-alpha", material, k1);
        std::vector<std::uint8_t> k2(32);
        crypto::DeriveKey("ctx-beta", material, k2);
        EXPECT_EQ(k1.size(), 32);
        EXPECT_NE(k1, k2) << "different contexts must derive different keys";

        std::vector<std::uint8_t> buf(32);
        crypto::DeriveKey("ctx-alpha", material, buf);
        EXPECT_EQ(k1, buf) << "repeated derivation must match caller-owned output";

        // 空材料与空上下文均可派生
        std::vector<std::uint8_t> k3(32);
        crypto::DeriveKey("ctx-alpha", std::span<const std::uint8_t>{}, k3);
        EXPECT_EQ(k3.size(), 32);
        EXPECT_NE(k3, k1);
        std::vector<std::uint8_t> k4(16);
        crypto::DeriveKey("", material, k4);
        EXPECT_EQ(k4.size(), 16);
    }

TEST(BlockCoverage, Aes128Fips197Vector)
    {
        // FIPS-197 附录 B 已知向量
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const auto ct = crypto::EcbEncrypt(block, key);
        ASSERT_TRUE(ct);
        EXPECT_EQ(ToHex(*ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
        const auto Plain = crypto::EcbDecrypt(*ct, key);
        ASSERT_TRUE(Plain);
        EXPECT_EQ(*Plain, block);
    }

TEST(BlockCoverage, Aes256RoundTrip)
    {
        // AES-256（32 字节密钥）：加密后解密还原
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f"
                                      "101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::EcbEncrypt(block, key);
        ASSERT_TRUE(ct);
        EXPECT_NE(*ct, block);
        const auto Plain = crypto::EcbDecrypt(*ct, key);
        ASSERT_TRUE(Plain);
        EXPECT_EQ(*Plain, block);
    }

TEST(BlockCoverage, WrongKeyLengthInitFailure)
    {
        // 24 字节密钥使用 AES-192；合法长度必须正常往返。
        const auto key = HexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const std::array<std::uint8_t, 16> block = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const auto ct = crypto::EcbEncrypt(block, key);
        ASSERT_TRUE(ct);
        EXPECT_NE(*ct, block);
        const auto Plain = crypto::EcbDecrypt(*ct, key);
        ASSERT_TRUE(Plain);
        EXPECT_EQ(*Plain, block);
    }

TEST(BlockCoverage, RejectsInvalidKeyLengths)
    {
        const std::array<std::uint8_t, 16> block{};
        for (const auto Length : std::array<std::size_t, 5>{0, 15, 17, 31, 33})
        {
            const std::vector<std::uint8_t> Key(Length, 0xA5);
            const auto Encrypted = crypto::EcbEncrypt(block, Key);
            const auto Decrypted = crypto::EcbDecrypt(block, Key);
            ASSERT_FALSE(Encrypted) << "length=" << Length;
            ASSERT_FALSE(Decrypted) << "length=" << Length;
            EXPECT_EQ(Encrypted.error().Code, fault::Code::InvalidArgument) << "length=" << Length;
            EXPECT_EQ(Decrypted.error().Code, fault::Code::InvalidArgument) << "length=" << Length;
        }
    }

TEST(HkdfCoverage, HmacSha256Rfc4231)
    {
        // RFC 4231 测试用例 1：key=0x0b×20，Data="Hi There"
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string Data = "Hi There";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        const auto mac = crypto::HmacSha256(key, Bytes);
        ASSERT_TRUE(mac);
        EXPECT_EQ(ToHex(*mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

TEST(HkdfCoverage, HmacSha512Rfc4231)
    {
        // RFC 4231 测试用例 1（SHA-512 版本）
        const std::vector<std::uint8_t> key(20, 0x0B);
        const std::string Data = "Hi There";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        const auto mac = crypto::HmacSha512(key, Bytes);
        ASSERT_TRUE(mac);
        EXPECT_EQ(ToHex(*mac), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded"
                               "aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

TEST(HkdfCoverage, HmacSha256EmptyKeyAndData)
    {
        // 空密钥与空数据的已知向量
        const auto mac = crypto::HmacSha256({}, {});
        ASSERT_TRUE(mac);
        EXPECT_EQ(ToHex(*mac), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

TEST(HkdfCoverage, ExtractRfc5869Prk)
    {
        // RFC 5869 测试用例 1：PRK = HMAC-SHA256(salt, IKM)
        const auto salt = HexToBytes("000102030405060708090a0b0c");
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const auto prk = crypto::HkdfExtract(salt, ikm);
        ASSERT_TRUE(prk);
        EXPECT_EQ(ToHex(*prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    }

TEST(HkdfCoverage, ExtractEmptySaltEqualsZeroSalt)
    {
        // 空盐等价于 32 字节全零盐（RFC 5869 规则）
        const std::vector<std::uint8_t> ikm(22, 0x0B);
        const std::array<std::uint8_t, crypto::Sha256Len> ZeroSalt{};
        const auto EmptySalt = crypto::HkdfExtract({}, ikm);
        const auto ExplicitSalt = crypto::HkdfExtract(ZeroSalt, ikm);
        ASSERT_TRUE(EmptySalt);
        ASSERT_TRUE(ExplicitSalt);
        EXPECT_EQ(*EmptySalt, *ExplicitSalt);
    }

TEST(HkdfCoverage, ExtractEmptyIkm)
    {
        // 空 IKM 可提取（HMAC(salt, "")），且确定性
        const std::vector<std::uint8_t> salt = HexToBytes("000102030405060708090a0b0c");
        const auto First = crypto::HkdfExtract(salt, {});
        const auto Second = crypto::HkdfExtract(salt, {});
        ASSERT_TRUE(First);
        ASSERT_TRUE(Second);
        EXPECT_EQ(*First, *Second);
    }

TEST(HkdfCoverage, ExpandRfc5869Okm)
    {
        // RFC 5869 测试用例 1：L=42 的 OKM
        const auto prk = HexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        const auto Info = HexToBytes("f0f1f2f3f4f5f6f7f8f9");
        std::array<std::uint8_t, 42> okm{};
        const auto ec = crypto::HkdfExpand({prk, Info}, okm);
        EXPECT_EQ(ec.Code, fault::Code::Success);
        EXPECT_EQ(ToHex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865");
    }

TEST(HkdfCoverage, ExpandInvalidArguments)
    {
        // 非法参数：长度超限 / PRK 过短 / Info 过长
        const auto prk = HexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        std::vector<std::uint8_t> Oversized(255 * crypto::Sha256Len + 1);
        std::array<std::uint8_t, 32> Output{};
        EXPECT_EQ(crypto::HkdfExpand({prk, {}}, Oversized).Code,
                  fault::Code::InvalidArgument);

        const std::vector<std::uint8_t> short_prk(31, 0x11);
        EXPECT_EQ(crypto::HkdfExpand({short_prk, {}}, Output).Code, fault::Code::InvalidArgument);

        std::vector<std::uint8_t> big_info(515, 0x22);
        EXPECT_EQ(crypto::HkdfExpand({prk, big_info}, Output).Code, fault::Code::InvalidArgument);
    }

TEST(HkdfCoverage, ExpandZeroAndMaxLength)
    {
        // 边界：length=0 成功且为空；length=8160（255×32）成功
        const auto prk = HexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        std::array<std::uint8_t, 0> out_zero{};
        const auto ec_zero = crypto::HkdfExpand({prk, {}}, out_zero);
        EXPECT_EQ(ec_zero.Code, fault::Code::Success);
        EXPECT_TRUE(out_zero.empty());

        std::vector<std::uint8_t> out_max(255 * crypto::Sha256Len);
        const auto ec_max = crypto::HkdfExpand({prk, {}}, out_max);
        EXPECT_EQ(ec_max.Code, fault::Code::Success);
        EXPECT_EQ(out_max.size(), 255 * crypto::Sha256Len);
    }

TEST(HkdfCoverage, ExpandLabelEquivalenceAndInvalid)
    {
        // ExpandLabel 与手构 HkdfLabel 的 HkdfExpand 结果一致
        const auto Secret = HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const std::array<std::uint8_t, 3> Context = {0x01, 0x02, 0x03};

        std::array<std::uint8_t, 32> out{};
        const auto ec = crypto::ExpandLabel(
            crypto::ExpandParams{Secret, "key", Context}, out);
        ASSERT_EQ(ec.Code, fault::Code::Success);
        EXPECT_EQ(out.size(), 32);

        // 手工构造 HkdfLabel = Length(2) || LabelLen(1) || "tls13 " + Label || ctx_len(1) || Context
        std::vector<std::uint8_t> LabelBuf;
        LabelBuf.push_back(static_cast<std::uint8_t>(32 >> 8));
        LabelBuf.push_back(static_cast<std::uint8_t>(32 & 0xFF));
        const std::string_view full_label = "tls13 key";
        LabelBuf.push_back(static_cast<std::uint8_t>(full_label.size()));
        for (const auto c : full_label)
        {
            LabelBuf.push_back(static_cast<std::uint8_t>(c));
        }
        LabelBuf.push_back(static_cast<std::uint8_t>(Context.size()));
        LabelBuf.insert(LabelBuf.end(), Context.begin(), Context.end());

        std::array<std::uint8_t, 32> manual{};
        const auto ec_manual = crypto::HkdfExpand({Secret, LabelBuf}, manual);
        ASSERT_EQ(ec_manual.Code, fault::Code::Success);
        EXPECT_EQ(out, manual) << "ExpandLabel must match manual HkdfLabel construction";

        // 非法：Label 过长（>249 字节）与 Context 过长（>255 字节）
        const std::string long_label(250, 'x');
        EXPECT_EQ(crypto::ExpandLabel(crypto::ExpandParams{Secret, long_label, {}}, out).Code,
                  fault::Code::InvalidArgument);
        std::vector<std::uint8_t> big_context(256, 0x33);
        EXPECT_EQ(crypto::ExpandLabel(crypto::ExpandParams{Secret, "key", big_context}, out).Code,
                  fault::Code::InvalidArgument);
    }

TEST(HkdfCoverage, Sha256KnownVectors)
    {
        const auto Empty = crypto::Sha256(std::span<const std::uint8_t>{});
        ASSERT_TRUE(Empty);
        EXPECT_EQ(ToHex(*Empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        const std::string Abc = "abc";
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Abc.data()), Abc.size());
        const auto Hash = crypto::Sha256(Bytes);
        ASSERT_TRUE(Hash);
        EXPECT_EQ(ToHex(*Hash), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

TEST(HkdfCoverage, Sha256MultiBlock)
    {
        const std::string A = "first part";
        const std::string B = "second part";
        const std::string C = "third part";
        const auto ABytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(A.data()), A.size());
        const auto BBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(B.data()), B.size());
        const auto CBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(C.data()), C.size());
        const std::string Ab = A + B;
        const auto AbBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Ab.data()), Ab.size());
        const std::array<std::span<const std::uint8_t>, 2> TwoParts{ABytes, BBytes};
        const auto TwoHash = crypto::Sha256(crypto::HashInput{TwoParts});
        const auto AbHash = crypto::Sha256(AbBytes);
        ASSERT_TRUE(TwoHash);
        ASSERT_TRUE(AbHash);
        EXPECT_EQ(*TwoHash, *AbHash);
        const std::string Abc = A + B + C;
        const auto AbcBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Abc.data()), Abc.size());
        const std::array<std::span<const std::uint8_t>, 3> ThreeParts{ABytes, BBytes, CBytes};
        const auto ThreeHash = crypto::Sha256(crypto::HashInput{ThreeParts});
        const auto AbcHash = crypto::Sha256(AbcBytes);
        ASSERT_TRUE(ThreeHash);
        ASSERT_TRUE(AbcHash);
        EXPECT_EQ(*ThreeHash, *AbcHash);
    }

TEST(Sha224Coverage, EmptyInputKnownVector)
    {
        const auto Hash = crypto::Sha224("");
        ASSERT_TRUE(Hash);
        EXPECT_EQ(Hash->size(), 56);
        EXPECT_EQ(std::string(Hash->begin(), Hash->end()),
                  "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

TEST(Sha224Coverage, AbcKnownVector)
    {
        const auto Hash = crypto::Sha224("abc");
        ASSERT_TRUE(Hash);
        EXPECT_EQ(std::string(Hash->begin(), Hash->end()),
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
        const std::string Hashed(56, '0');
        const auto Preserved = crypto::NormalizeCredential(Hashed);
        ASSERT_TRUE(Preserved);
        EXPECT_EQ(std::string(Preserved->begin(), Preserved->end()), Hashed);
        const auto Normalized = crypto::NormalizeCredential("my-Credential");
        const auto Hash = crypto::Sha224("my-Credential");
        ASSERT_TRUE(Normalized);
        ASSERT_TRUE(Hash);
        EXPECT_EQ(*Normalized, *Hash);
        EXPECT_EQ(Normalized->size(), 56);
    }

TEST(Sha224Coverage, NormalizeNonHexAndEmpty)
    {
        const std::string NotHex(56, 'g');
        EXPECT_FALSE(crypto::IsHex(NotHex));
        const auto Normalized = crypto::NormalizeCredential(NotHex);
        const auto Hash = crypto::Sha224(NotHex);
        ASSERT_TRUE(Normalized);
        ASSERT_TRUE(Hash);
        EXPECT_EQ(*Normalized, *Hash);
        const auto Empty = crypto::NormalizeCredential("");
        const auto EmptyHash = crypto::Sha224("");
        ASSERT_TRUE(Empty);
        ASSERT_TRUE(EmptyHash);
        EXPECT_EQ(*Empty, *EmptyHash);
    }

TEST(X25519Coverage, GenerateKeypairConsistent)
    {
        const auto Keypair = crypto::GenerateKeypair();
        ASSERT_TRUE(Keypair);
        const std::array<std::uint8_t, crypto::X25519Klen> Zero{};
        EXPECT_NE(Keypair->PrivateKey, Zero);
        const auto Public = crypto::DerivePubkey(Keypair->PrivateKey);
        ASSERT_TRUE(Public);
        EXPECT_EQ(*Public, Keypair->PublicKey);
    }

TEST(X25519Coverage, DerivePubkeyRfc7748)
    {
        const auto Private = HexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto Public = crypto::DerivePubkey(Private);
        ASSERT_TRUE(Public);
        EXPECT_EQ(ToHex(*Public), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

TEST(X25519Coverage, DerivePubkeyWrongLength)
    {
        // 原非法输入保持不变，错误以正式结果表达。
        const auto Empty = crypto::DerivePubkey({});
        ASSERT_FALSE(Empty);
        EXPECT_EQ(Empty.error().Code, fault::Code::InvalidArgument);
        const auto Key16 = HexToBytes("000102030405060708090a0b0c0d0e0f");
        const auto Short = crypto::DerivePubkey(Key16);
        ASSERT_FALSE(Short);
        EXPECT_EQ(Short.error().Code, fault::Code::InvalidArgument);
    }

TEST(X25519Coverage, SharedSecretRoundtrip)
    {
        const auto Alice = crypto::GenerateKeypair();
        const auto Bob = crypto::GenerateKeypair();
        ASSERT_TRUE(Alice);
        ASSERT_TRUE(Bob);
        const auto First = crypto::X25519(Alice->PrivateKey, Bob->PublicKey);
        const auto Second = crypto::X25519(Bob->PrivateKey, Alice->PublicKey);
        ASSERT_TRUE(First);
        ASSERT_TRUE(Second);
        EXPECT_EQ(*First, *Second);
        const std::array<std::uint8_t, crypto::X25519Slen> Zero{};
        EXPECT_NE(*First, Zero);
    }

TEST(X25519Coverage, SharedSecretRfc7748)
    {
        const auto AlicePrivate = HexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto BobPublic = HexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        const auto Shared = crypto::X25519(AlicePrivate, BobPublic);
        ASSERT_TRUE(Shared);
        EXPECT_EQ(ToHex(*Shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

TEST(X25519Coverage, InvalidLengthsAndLowOrder)
    {
        const auto ShortPrivate = HexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const auto Public = HexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        const auto Short = crypto::X25519(ShortPrivate, Public);
        ASSERT_FALSE(Short);
        EXPECT_EQ(Short.error().Code, fault::Code::InvalidArgument);
        const std::vector<std::uint8_t> LongPublic(33, 0x11);
        const auto Long = crypto::X25519(ShortPrivate, LongPublic);
        ASSERT_FALSE(Long);
        EXPECT_EQ(Long.error().Code, fault::Code::InvalidArgument);
        const std::array<std::uint8_t, crypto::X25519Klen> ZeroKey{};
        const auto Keypair = crypto::GenerateKeypair();
        ASSERT_TRUE(Keypair);
        const auto LowOrder = crypto::X25519(Keypair->PrivateKey, ZeroKey);
        ASSERT_FALSE(LowOrder);
        EXPECT_EQ(LowOrder.error().Code, fault::Code::Kexfail);
        const auto Shared = crypto::X25519(ZeroKey, Keypair->PublicKey);
        ASSERT_TRUE(Shared);
        EXPECT_NE(*Shared, ZeroKey);
    }
