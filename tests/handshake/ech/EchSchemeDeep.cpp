/**
 * @file EchSchemeDeep.cpp
 * @brief ECH scheme 属性测试
 * @details 验证名称、层级、启用条件与 ECH 扩展检测。
 */

#include <prism/handshake/ech/scheme.hpp>
#include <prism/handshake/ech/util/keygen.hpp>
#include <prism/settings/settings.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::ech::scheme;
    namespace ech = psm::handshake::ech;

    auto make_string(const std::string_view s) -> psm::memory::string
    {
        return psm::memory::string(s.data(), s.size());
    }
} // namespace

TEST(EchSchemeDeep, SchemeName)
{
    scheme s;
    EXPECT_EQ(s.name(), "ech");
}

TEST(EchSchemeDeep, SchemeTier)
{
    scheme s;
    EXPECT_EQ(s.tier(), 1) << "scheme: tier 1 (verify)";
}

TEST(EchSchemeDeep, SchemeActive)
{
    scheme s;
    psm::settings cfg;
    EXPECT_FALSE(s.active(cfg)) << "inactive without key";

    cfg.stealth.ech.key = make_string("dGVzdA==");
    cfg.stealth.ech.public_name = make_string("example.com");
    EXPECT_TRUE(s.active(cfg)) << "active with key + public_name";
}

TEST(EchSchemeDeep, VerifyDetectsEchExtension)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.ech.key = make_string("dGVzdA==");
    cfg.stealth.ech.public_name = make_string("example.com");

    // 构造带 ECH 扩展的 ClientHello（简化：仅含扩展列表结构）
    // handshake 头(4) + version(2) + random(32) + sid_len(1) + cipher_len(2)+cipher(2)
    // + comp_len(1)+comp(1) + ext_len(2) + ext(6)
    std::vector<std::byte> raw;
    raw.resize(4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 6);
    const auto ext_offset = 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2;
    // cipher_len = 2（位于 39..40）
    raw[39] = std::byte{0x00};
    raw[40] = std::byte{0x02};
    // comp_len = 1（位于 43）
    raw[43] = std::byte{0x01};
    // ext_len = 6（一个 ECH 扩展，位于 45..46）
    raw[45] = std::byte{0x00};
    raw[46] = std::byte{0x06};
    // ECH 扩展：type=0xfe0d，len=2
    raw[ext_offset] = std::byte{0xfe};
    raw[ext_offset + 1] = std::byte{0x0d};
    raw[ext_offset + 2] = std::byte{0x00};
    raw[ext_offset + 3] = std::byte{0x02};
    raw[ext_offset + 4] = std::byte{0x00};
    raw[ext_offset + 5] = std::byte{0x00};

    auto result = s.verify({}, raw, cfg);
    EXPECT_GT(result.score, 0) << "verify: ECH extension detected";
    EXPECT_GT(result.solo_flag, 0) << "verify: solo hit";
}

TEST(EchSchemeDeep, VerifyNoEchExtension)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.ech.key = make_string("dGVzdA==");
    cfg.stealth.ech.public_name = make_string("example.com");

    // 普通 ClientHello（无扩展）
    std::vector<std::byte> raw;
    raw.resize(4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2);

    auto result = s.verify({}, raw, cfg);
    EXPECT_EQ(result.score, 0) << "verify: no ECH extension";
}
