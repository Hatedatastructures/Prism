/**
 * @file TlsHelloDeep.cpp
 * @brief TLS ClientHello 深度测试
 * @details 测试 hello.cpp 匿名命名空间的解析函数：
 *          read_u16、read_u24、parse_sni、parse_keyshare、parse_versions、parse_exts。
 *          以及 from_bytes 的更多错误分支。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/tls/hello.hpp>
#include <prism/proto/protocol/tls/record.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>

#include <gtest/gtest.h>

// #include 源文件增加覆盖率计数
#include "../../src/prism/proto/protocol/tls/hello.cpp"

namespace
{
    using namespace psm::tls;
    namespace ptls = psm::protocol::tls;

    void write_u16(psm::memory::vector<std::uint8_t> &buf, std::uint16_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    void write_u24(psm::memory::vector<std::uint8_t> &buf, std::size_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    // ─── read_u16 ──────────────────────────────────────

    TEST(TlsHelloDeep, ReadU16Basic)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0x01);
        data.push_back(0x23);
        auto val = read_u16(data, 0);
        EXPECT_TRUE(val == 0x0123) << "read_u16: basic value";
    }

    TEST(TlsHelloDeep, ReadU16Max)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0xFF);
        data.push_back(0xFF);
        auto val = read_u16(data, 0);
        EXPECT_TRUE(val == 0xFFFF) << "read_u16: max value";
    }

    TEST(TlsHelloDeep, ReadU16Zero)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0x00);
        data.push_back(0x00);
        auto val = read_u16(data, 0);
        EXPECT_TRUE(val == 0) << "read_u16: zero";
    }

    TEST(TlsHelloDeep, ReadU16AtOffset)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0xAB);
        data.push_back(0xCD);
        auto val = read_u16(data, 2);
        EXPECT_TRUE(val == 0xABCD) << "read_u16: at offset 2";
    }

    // ─── read_u24 ──────────────────────────────────────

    TEST(TlsHelloDeep, ReadU24Basic)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0x01);
        data.push_back(0x23);
        data.push_back(0x45);
        auto val = read_u24(data, 0);
        EXPECT_TRUE(val == 0x012345) << "read_u24: basic value";
    }

    TEST(TlsHelloDeep, ReadU24Max)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0xFF);
        data.push_back(0xFF);
        data.push_back(0xFF);
        auto val = read_u24(data, 0);
        EXPECT_TRUE(val == 0xFFFFFF) << "read_u24: max value";
    }

    TEST(TlsHelloDeep, ReadU24Zero)
    {
        psm::memory::vector<std::uint8_t> data(psm::memory::current_resource());
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0x00);
        auto val = read_u24(data, 0);
        EXPECT_TRUE(val == 0) << "read_u24: zero";
    }

    // ─── parse_sni ─────────────────────────────────────

    TEST(TlsHelloDeep, ParseSniHostname)
    {
        const char *name = "example.com";
        auto name_len = static_cast<std::uint16_t>(std::string_view(name).size());

        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // list_len = 1(type) + 2(len) + name_len
        write_u16(ext, static_cast<std::uint16_t>(1 + 2 + name_len));
        ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        write_u16(ext, name_len);
        for (auto c : std::string_view(name)) ext.push_back(static_cast<std::uint8_t>(c));

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni == "example.com") << "parse_sni: hostname extracted";
    }

    TEST(TlsHelloDeep, ParseSniEmptyExt)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // 只 1 字节，不足 2 字节 list_len
        ext.push_back(0x00);

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni.empty()) << "parse_sni: too short -> empty sni";
    }

    TEST(TlsHelloDeep, ParseSniNonHostnameType)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // list_len=7: type(1) + len(2) + data(3) + type(1) + len(2)... 不精确
        write_u16(ext, 6);
        // 非 hostname 类型
        ext.push_back(0x01); // 非 SNAME_TYPE_HOSTNAME
        write_u16(ext, 3);
        ext.push_back('a');
        ext.push_back('b');
        ext.push_back('c');

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni.empty()) << "parse_sni: non-hostname type -> empty sni";
    }

    TEST(TlsHelloDeep, ParseSniMixedTypes)
    {
        // 先一个非 hostname，再一个 hostname
        const char *name = "test.io";
        auto name_len = static_cast<std::uint16_t>(std::string_view(name).size());

        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // 非 hostname 条目: type(1) + len(2) + data(2) = 5
        // hostname 条目: type(1) + len(2) + data(name_len) = 3 + name_len
        auto total = static_cast<std::uint16_t>(5 + 3 + name_len);
        write_u16(ext, total);

        // 非 hostname
        ext.push_back(0x01);
        write_u16(ext, 2);
        ext.push_back(0x00);
        ext.push_back(0x00);

        // hostname
        ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        write_u16(ext, name_len);
        for (auto c : std::string_view(name)) ext.push_back(static_cast<std::uint8_t>(c));

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni == "test.io") << "parse_sni: mixed types -> hostname found";
    }

    TEST(TlsHelloDeep, ParseSniTruncatedNameLen)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 5);
        ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        // 只 1 字节，不足 2 字节 name_len
        ext.push_back(0x00);

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni.empty()) << "parse_sni: truncated name_len -> break";
    }

    TEST(TlsHelloDeep, ParseSniTruncatedNameData)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 10);
        ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        write_u16(ext, 100); // 声称 100 字节但实际不足
        ext.push_back('a');

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni.empty()) << "parse_sni: truncated name data -> break";
    }

    TEST(TlsHelloDeep, ParseSniNonHostTruncatedLen)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 3);
        ext.push_back(0x01); // 非 hostname
        // 不足 2 字节 name_len -> break

        psm::memory::string sni(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_sni(span, sni);
        EXPECT_TRUE(sni.empty()) << "parse_sni: non-host truncated len -> break";
    }

    // ─── parse_keyshare ────────────────────────────────

    TEST(TlsHelloDeep, ParseKeyshareX25519)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // list_len = 2(group) + 2(key_len) + 32(key) = 36
        write_u16(ext, 36);
        write_u16(ext, ptls::GROUP_X25519);
        write_u16(ext, 32);
        for (std::size_t i = 0; i < 32; ++i) ext.push_back(static_cast<std::uint8_t>(i + 1));

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(has_key) << "parse_keyshare: X25519 found";
        EXPECT_TRUE(key[0] == 1) << "parse_keyshare: X25519 key[0]=1";
        EXPECT_TRUE(key[31] == 32) << "parse_keyshare: X25519 key[31]=32";
    }

    TEST(TlsHelloDeep, ParseKeyshareMlKem)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // ML-KEM key 可以超过 32 字节，只要 key_len >= 32 就取前 32 字节
        write_u16(ext, 40); // list_len
        write_u16(ext, ptls::GROUP_X25519_MLKEM768);
        write_u16(ext, 36); // key_len > 32
        for (std::size_t i = 0; i < 36; ++i) ext.push_back(static_cast<std::uint8_t>(i));

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(has_key) << "parse_keyshare: ML-KEM found";
        EXPECT_TRUE(key[0] == 0) << "parse_keyshare: ML-KEM key[0]";
        EXPECT_TRUE(key[31] == 31) << "parse_keyshare: ML-KEM key[31]";
    }

    TEST(TlsHelloDeep, ParseKeyshareEmpty)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // 不足 2 字节
        ext.push_back(0x00);

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(!has_key) << "parse_keyshare: too short -> no key";
    }

    TEST(TlsHelloDeep, ParseKeyshareUnknownGroup)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 36);
        write_u16(ext, 0x9999); // 未知 group
        write_u16(ext, 32);
        for (std::size_t i = 0; i < 32; ++i) ext.push_back(0x00);

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(!has_key) << "parse_keyshare: unknown group -> no key";
    }

    TEST(TlsHelloDeep, ParseKeyshareTruncatedKey)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 36);
        write_u16(ext, ptls::GROUP_X25519);
        write_u16(ext, 32);
        for (std::size_t i = 0; i < 16; ++i) ext.push_back(0x00); // 只 16 字节，不够 32

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(!has_key) << "parse_keyshare: truncated key -> break";
    }

    TEST(TlsHelloDeep, ParseKeyshareX25519WrongKeyLen)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 8);
        write_u16(ext, ptls::GROUP_X25519);
        write_u16(ext, 16); // key_len != 32 -> 跳过
        for (std::size_t i = 0; i < 16; ++i) ext.push_back(0x00);

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(!has_key) << "parse_keyshare: X25519 with wrong key_len -> skip";
    }

    TEST(TlsHelloDeep, ParseKeyshareMultipleEntries)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        // 第一个 entry: 未知 group，跳过
        // 第二个 entry: X25519
        auto total = static_cast<std::uint16_t>(4 + 4 + 2 + 4 + 32);
        write_u16(ext, total);
        write_u16(ext, 0x9999);
        write_u16(ext, 2);
        ext.push_back(0x00);
        ext.push_back(0x00);
        write_u16(ext, ptls::GROUP_X25519);
        write_u16(ext, 32);
        for (std::size_t i = 0; i < 32; ++i) ext.push_back(static_cast<std::uint8_t>(i + 10));

        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_keyshare(span, has_key, key);
        EXPECT_TRUE(has_key) << "parse_keyshare: multiple entries -> X25519 found";
        EXPECT_TRUE(key[0] == 10) << "parse_keyshare: second entry key[0]";
    }

    // ─── parse_versions ────────────────────────────────

    TEST(TlsHelloDeep, ParseVersionsBasic)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        ext.push_back(4); // list_len=4
        write_u16(ext, ptls::VERSION_TLS12);
        write_u16(ext, ptls::VERSION_TLS13);

        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_versions(span, versions);
        EXPECT_TRUE(versions.size() == 2) << "parse_versions: 2 versions";
        EXPECT_TRUE(versions[0] == ptls::VERSION_TLS12) << "parse_versions: TLS 1.2";
        EXPECT_TRUE(versions[1] == ptls::VERSION_TLS13) << "parse_versions: TLS 1.3";
    }

    TEST(TlsHelloDeep, ParseVersionsEmpty)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_versions(span, versions);
        EXPECT_TRUE(versions.empty()) << "parse_versions: empty -> no versions";
    }

    TEST(TlsHelloDeep, ParseVersionsOddListLen)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        ext.push_back(3); // 奇数 list_len -> 读 1 个 version + 1 字节剩余
        write_u16(ext, ptls::VERSION_TLS13);
        ext.push_back(0x00); // 多余字节

        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_versions(span, versions);
        EXPECT_TRUE(versions.size() == 1) << "parse_versions: odd list -> 1 version";
    }

    TEST(TlsHelloDeep, ParseVersionsSingleByteList)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        ext.push_back(1); // list_len=1，不足 2 字节
        ext.push_back(0x00);

        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_versions(span, versions);
        EXPECT_TRUE(versions.empty()) << "parse_versions: list_len=1 -> no versions";
    }

    // ─── parse_exts ────────────────────────────────────

    TEST(TlsHelloDeep, ParseExtsAllThree)
    {
        // 构造包含 SNI + KeyShare + Versions 的扩展块
        psm::memory::vector<std::uint8_t> ext_block(psm::memory::current_resource());

        // SNI
        const char *name = "ext.test";
        auto name_len = static_cast<std::uint16_t>(std::string_view(name).size());
        psm::memory::vector<std::uint8_t> sni_ext(psm::memory::current_resource());
        write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name_len));
        sni_ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        write_u16(sni_ext, name_len);
        for (auto c : std::string_view(name)) sni_ext.push_back(static_cast<std::uint8_t>(c));
        write_u16(ext_block, ptls::EXT_SERVER_NAME);
        write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
        ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());

        // KeyShare
        psm::memory::vector<std::uint8_t> ks_ext(psm::memory::current_resource());
        write_u16(ks_ext, 36);
        write_u16(ks_ext, ptls::GROUP_X25519);
        write_u16(ks_ext, 32);
        for (std::size_t i = 0; i < 32; ++i) ks_ext.push_back(0x42);
        write_u16(ext_block, ptls::EXT_KEY_SHARE);
        write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
        ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());

        // Versions
        psm::memory::vector<std::uint8_t> sv_ext(psm::memory::current_resource());
        sv_ext.push_back(2);
        write_u16(sv_ext, ptls::VERSION_TLS13);
        write_u16(ext_block, ptls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
        ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());

        // 包装为 parse_exts 格式（前面加 ext_len）
        psm::memory::vector<std::uint8_t> full_ext(psm::memory::current_resource());
        write_u16(full_ext, static_cast<std::uint16_t>(ext_block.size()));
        full_ext.insert(full_ext.end(), ext_block.begin(), ext_block.end());

        psm::memory::string sni(psm::memory::current_resource());
        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        parse_ctx state{sni, has_key, key, versions};

        auto span = std::span<const std::uint8_t>(full_ext.data(), full_ext.size());
        parse_exts(span, state);

        EXPECT_TRUE(sni == "ext.test") << "parse_exts: SNI parsed";
        EXPECT_TRUE(has_key) << "parse_exts: key found";
        EXPECT_TRUE(versions.size() == 1) << "parse_exts: 1 version";
    }

    TEST(TlsHelloDeep, ParseExtsEmpty)
    {
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        ext.push_back(0x00); // 不足 2 字节

        psm::memory::string sni(psm::memory::current_resource());
        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        parse_ctx state{sni, has_key, key, versions};

        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_exts(span, state);
        EXPECT_TRUE(sni.empty()) << "parse_exts: empty -> no sni";
        EXPECT_TRUE(!has_key) << "parse_exts: empty -> no key";
    }

    TEST(TlsHelloDeep, ParseExtsUnknownExtType)
    {
        psm::memory::vector<std::uint8_t> ext_block(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> unknown_ext(psm::memory::current_resource());
        unknown_ext.push_back(0x01);
        unknown_ext.push_back(0x02);
        write_u16(ext_block, static_cast<std::uint16_t>(0x1234)); // 未知 type
        write_u16(ext_block, static_cast<std::uint16_t>(unknown_ext.size()));
        ext_block.insert(ext_block.end(), unknown_ext.begin(), unknown_ext.end());

        psm::memory::vector<std::uint8_t> full_ext(psm::memory::current_resource());
        write_u16(full_ext, static_cast<std::uint16_t>(ext_block.size()));
        full_ext.insert(full_ext.end(), ext_block.begin(), ext_block.end());

        psm::memory::string sni(psm::memory::current_resource());
        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        parse_ctx state{sni, has_key, key, versions};

        auto span = std::span<const std::uint8_t>(full_ext.data(), full_ext.size());
        parse_exts(span, state);
        EXPECT_TRUE(sni.empty()) << "parse_exts: unknown type -> no sni";
        EXPECT_TRUE(!has_key) << "parse_exts: unknown type -> no key";
    }

    TEST(TlsHelloDeep, ParseExtsTruncatedPayload)
    {
        // 声称 ext_len=100 但实际只有 8 字节
        psm::memory::vector<std::uint8_t> ext(psm::memory::current_resource());
        write_u16(ext, 100); // ext_len 声称 100
        write_u16(ext, ptls::EXT_SERVER_NAME);
        write_u16(ext, 50); // cur_len=50，但 offset+50 > size

        psm::memory::string sni(psm::memory::current_resource());
        bool has_key = false;
        std::array<std::uint8_t, 32> key{};
        psm::memory::vector<std::uint16_t> versions(psm::memory::current_resource());
        parse_ctx state{sni, has_key, key, versions};

        auto span = std::span<const std::uint8_t>(ext.data(), ext.size());
        parse_exts(span, state);
        EXPECT_TRUE(sni.empty()) << "parse_exts: truncated -> break";
    }

    // ─── from_bytes 更多分支 ───────────────────────────

    TEST(TlsHelloDeep, FromBytesBadContentType)
    {
        psm::memory::vector<std::uint8_t> raw(44, static_cast<std::uint8_t>(0x17)); // 非 CT_HANDSHAKE
        raw[0] = 0x17; // Application Data
        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: bad content type -> error";
    }

    TEST(TlsHelloDeep, FromBytesBodyTooLarge)
    {
        psm::memory::vector<std::uint8_t> raw(44, static_cast<std::uint8_t>(0x00));
        raw[0] = ptls::CT_HANDSHAKE;
        // body_len 声称比 raw 大
        raw[3] = 0xFF;
        raw[4] = 0xFF;
        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: body too large -> error";
    }

    TEST(TlsHelloDeep, FromBytesBadHandshakeType)
    {
        psm::memory::vector<std::uint8_t> raw(44, static_cast<std::uint8_t>(0x00));
        raw[0] = ptls::CT_HANDSHAKE;
        // body_len = 39 (44 - 5)
        raw[3] = 0x00;
        raw[4] = 39;
        raw[5] = 0x02; // HS_SERVER_HELLO 而非 HS_CLIENT_HELLO
        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: bad handshake type -> error";
    }

    TEST(TlsHelloDeep, FromBytesHandshakeLenOverflow)
    {
        psm::memory::vector<std::uint8_t> raw(50, static_cast<std::uint8_t>(0x00));
        raw[0] = ptls::CT_HANDSHAKE;
        raw[3] = 0x00;
        raw[4] = 45; // body_len = 45
        raw[5] = ptls::HS_CLIENT_HELLO;
        // handshake_len 声称非常大
        raw[6] = 0x7F;
        raw[7] = 0xFF;
        raw[8] = 0xFF;
        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: handshake len overflow -> error";
    }

    TEST(TlsHelloDeep, FromBytesSessionIdOutOfRange)
    {
        // session_id_len 声称的长度 + offset 超出 raw.size()
        psm::memory::vector<std::uint8_t> hs_body(psm::memory::current_resource());
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        for (std::size_t i = 0; i < 32; ++i) hs_body.push_back(0x00); // random
        hs_body.push_back(20); // session_id_len=20
        for (std::size_t i = 0; i < 5; ++i) hs_body.push_back(0x00); // 只有 5 字节，不够 20

        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        write_u16(raw, ptls::VERSION_TLS12);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: sid out of range -> error";
    }

    TEST(TlsHelloDeep, FromBytesOddCipherLen)
    {
        // cipher_len 为奇数
        psm::memory::vector<std::uint8_t> hs_body(psm::memory::current_resource());
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        for (std::size_t i = 0; i < 32; ++i) hs_body.push_back(0x00); // random
        hs_body.push_back(0x00); // session_id_len=0
        // cipher_len = 3 (奇数)
        write_u16(hs_body, 3);
        hs_body.push_back(0x13);
        hs_body.push_back(0x01);
        hs_body.push_back(0x00);

        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        write_u16(raw, ptls::VERSION_TLS12);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: odd cipher_len -> error";
    }

    TEST(TlsHelloDeep, FromBytesCompLenOverflow)
    {
        psm::memory::vector<std::uint8_t> hs_body(psm::memory::current_resource());
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        for (std::size_t i = 0; i < 32; ++i) hs_body.push_back(0x00); // random
        hs_body.push_back(0x00); // session_id_len=0
        write_u16(hs_body, 2);
        write_u16(hs_body, ptls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(10); // comp_len=10 但后面没数据

        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        write_u16(raw, ptls::VERSION_TLS12);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: comp_len overflow -> error";
    }

    TEST(TlsHelloDeep, FromBytesWithExtensions)
    {
        const char *name = "deep.test";
        auto name_len = static_cast<std::uint16_t>(std::string_view(name).size());

        psm::memory::vector<std::uint8_t> ext_block(psm::memory::current_resource());

        // SNI
        psm::memory::vector<std::uint8_t> sni_ext(psm::memory::current_resource());
        write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name_len));
        sni_ext.push_back(ptls::SNAME_TYPE_HOSTNAME);
        write_u16(sni_ext, name_len);
        for (auto c : std::string_view(name)) sni_ext.push_back(static_cast<std::uint8_t>(c));
        write_u16(ext_block, ptls::EXT_SERVER_NAME);
        write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
        ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());

        // KeyShare X25519
        psm::memory::vector<std::uint8_t> ks_ext(psm::memory::current_resource());
        write_u16(ks_ext, 36);
        write_u16(ks_ext, ptls::GROUP_X25519);
        write_u16(ks_ext, 32);
        for (std::size_t i = 0; i < 32; ++i) ks_ext.push_back(static_cast<std::uint8_t>(i + 100));
        write_u16(ext_block, ptls::EXT_KEY_SHARE);
        write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
        ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());

        // Supported Versions
        psm::memory::vector<std::uint8_t> sv_ext(psm::memory::current_resource());
        sv_ext.push_back(4);
        write_u16(sv_ext, ptls::VERSION_TLS12);
        write_u16(sv_ext, ptls::VERSION_TLS13);
        write_u16(ext_block, ptls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
        ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());

        // Handshake body
        psm::memory::vector<std::uint8_t> hs_body(psm::memory::current_resource());
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        for (std::size_t i = 0; i < 32; ++i) hs_body.push_back(static_cast<std::uint8_t>(i)); // random
        hs_body.push_back(4); // session_id_len=4
        for (std::size_t i = 0; i < 4; ++i) hs_body.push_back(static_cast<std::uint8_t>(i));
        write_u16(hs_body, 2);
        write_u16(hs_body, ptls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1); // comp_methods_len
        hs_body.push_back(0x00);
        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        write_u16(raw, ptls::VERSION_TLS12);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::success) << "from_bytes: full hello -> success";
        EXPECT_TRUE(ch.sni() == "deep.test") << "from_bytes: sni";
        EXPECT_TRUE(ch.has_x25519()) << "from_bytes: has_x25519";
        EXPECT_TRUE(ch.x25519_key()[0] == 100) << "from_bytes: key[0]=100";
        EXPECT_TRUE(ch.versions().size() == 2) << "from_bytes: 2 versions";
        EXPECT_TRUE(ch.session_id().size() == 4) << "from_bytes: session_id len=4";
        EXPECT_TRUE(ch.random()[0] == 0) << "from_bytes: random[0]=0";
        EXPECT_TRUE(ch.random()[31] == 31) << "from_bytes: random[31]=31";

        auto feat = ch.to_features();
        EXPECT_TRUE(feat.server_name == "deep.test") << "to_features: server_name";
        EXPECT_TRUE(feat.session_id_len == 4) << "to_features: session_id_len=4";
        EXPECT_TRUE(feat.has_x25519) << "to_features: has_x25519";
        EXPECT_TRUE(feat.versions.size() == 2) << "to_features: 2 versions";
    }

    TEST(TlsHelloDeep, FromBytesRandomOverflow)
    {
        // 构造一个 handshake_len 小到 random 溢出的消息
        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        // body_len 足够小
        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, 5); // handshake_len=5 -> version(2) 后不够 32 字节 random
        body.push_back(0x03);
        body.push_back(0x03);
        body.push_back(0x00);
        body.push_back(0x00);
        body.push_back(0x00);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        // 需要 raw.size() >= 44 才能通过第一个检查
        while (raw.size() < 44) raw.push_back(0x00);
        // 修正 body_len
        raw[3] = static_cast<std::uint8_t>((body.size() >> 8) & 0xFF);
        raw[4] = static_cast<std::uint8_t>(body.size() & 0xFF);

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: random overflow -> error";
    }

    TEST(TlsHelloDeep, FromBytesSidLenOverflow)
    {
        // session_id_len 声称长度但 offset + sid_len > raw.size()
        psm::memory::vector<std::uint8_t> hs_body(psm::memory::current_resource());
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        for (std::size_t i = 0; i < 32; ++i) hs_body.push_back(0x00); // random
        hs_body.push_back(10); // session_id_len=10 但后续不足

        psm::memory::vector<std::uint8_t> body(psm::memory::current_resource());
        body.push_back(ptls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        psm::memory::vector<std::uint8_t> raw(psm::memory::current_resource());
        raw.push_back(ptls::CT_HANDSHAKE);
        write_u16(raw, ptls::VERSION_TLS12);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = client_hello::from_bytes(raw);
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "from_bytes: sid overflow -> error";
    }

} // namespace
